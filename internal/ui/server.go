package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pedroloch/workbench/internal/vault"
)

//go:embed web/*
var assets embed.FS

type Options struct {
	Out         io.Writer
	OpenBrowser bool
	Timeout     time.Duration
	Copy        func(string) error
}

type Server struct {
	store     *vault.Store
	options   Options
	origin    string
	host      string
	bootstrap string
	session   string
	csrf      string
	mu        sync.Mutex
	used      bool
	onLogin   func()
	last      atomic.Int64
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("cannot generate UI session")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func New(s *vault.Store, origin string, options Options) (*Server, error) {
	bootstrap, err := randomToken()
	if err != nil {
		return nil, err
	}
	session, err := randomToken()
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken()
	if err != nil {
		return nil, err
	}
	server := &Server{store: s, options: options, origin: origin, host: strings.TrimPrefix(origin, "http://"), bootstrap: bootstrap, session: session, csrf: csrf}
	server.last.Store(time.Now().UnixNano())
	return server, nil
}

func equal(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Server) authenticated(r *http.Request) bool {
	cookie, err := r.Cookie(s.cookieName())
	return err == nil && equal(cookie.Value, s.session)
}

func (s *Server) cookieName() string { return "wb_session_" + strings.ReplaceAll(s.host, ":", "_") }

func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.handle) }

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if r.Host != s.host {
		s.failure(w, http.StatusForbidden, "Invalid host")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.origin {
		s.failure(w, http.StatusForbidden, "Invalid origin")
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); strings.HasPrefix(r.URL.Path, "/api/") && site != "" && site != "same-origin" && site != "none" {
		s.failure(w, http.StatusForbidden, "Cross-site request rejected")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		s.static(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Header.Get("Origin") != s.origin {
		s.failure(w, http.StatusForbidden, "Origin required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, vault.MaxBlob)
	if r.URL.Path == "/api/session" {
		s.login(w, r)
		return
	}
	if !s.authenticated(r) || !equal(r.Header.Get("X-Workbench-CSRF"), s.csrf) {
		s.failure(w, http.StatusUnauthorized, "Session expired or unauthorized; restart workbench ui")
		return
	}
	s.last.Store(time.Now().UnixNano())
	if r.URL.Path == "/api/list" {
		if r.Method != http.MethodGet {
			s.failure(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		d, err := s.store.View()
		if err != nil {
			s.failure(w, http.StatusBadRequest, err.Error())
			return
		}
		s.respond(w, map[string]any{"entries": d.List("."), "identity": s.store.Identity()})
		return
	}
	if r.Method != http.MethodPost {
		s.failure(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	switch r.URL.Path {
	case "/api/classify":
		var request struct {
			Path   string `json:"path"`
			Secret *bool  `json:"secret"`
		}
		if !s.body(w, r, &request) {
			return
		}
		if request.Secret == nil {
			s.failure(w, 400, "Choose an explicit classification")
			return
		}
		p, err := vault.Path(request.Path, false)
		if err != nil {
			s.failure(w, 400, err.Error())
			return
		}
		if err := s.store.Classify(p, *request.Secret); err != nil {
			s.failure(w, 400, err.Error())
			return
		}
		s.respond(w, map[string]bool{"ok": true})
	case "/api/reveal", "/api/copy", "/api/unset":
		var request struct {
			Path string `json:"path"`
		}
		if !s.body(w, r, &request) {
			return
		}
		p, err := vault.Path(request.Path, false)
		if err != nil {
			s.failure(w, 400, err.Error())
			return
		}
		if r.URL.Path == "/api/unset" {
			if err := s.store.Unset(p); err != nil {
				s.failure(w, 400, err.Error())
				return
			}
			s.respond(w, map[string]bool{"ok": true})
			return
		}
		d, err := s.store.View()
		if err != nil {
			s.failure(w, 400, err.Error())
			return
		}
		e, ok := d.Entries[p]
		if !ok {
			s.failure(w, 404, "Path not found")
			return
		}
		if r.URL.Path == "/api/copy" {
			if err := s.options.Copy(vault.Display(e.Value)); err != nil {
				s.failure(w, 400, err.Error())
				return
			}
			s.respond(w, map[string]bool{"ok": true})
			return
		}
		s.respond(w, map[string]string{"value": vault.Display(e.Value)})
	case "/api/set":
		var request struct {
			Path    string `json:"path"`
			Value   string `json:"value"`
			Secret  *bool  `json:"secret"`
			Replace bool   `json:"replace"`
			Type    string `json:"type"`
		}
		if !s.body(w, r, &request) {
			return
		}
		if request.Secret == nil {
			s.failure(w, 400, "Choose an explicit classification")
			return
		}
		p, err := vault.Path(request.Path, false)
		if err != nil {
			s.failure(w, 400, err.Error())
			return
		}
		var value json.RawMessage
		switch request.Type {
		case "string":
			value, _ = json.Marshal(request.Value)
		case "json":
			value = json.RawMessage(request.Value)
		default:
			s.failure(w, 400, "Choose string or JSON scalar")
			return
		}
		if err := s.store.Set(p, vault.Entry{Value: value, Secret: *request.Secret}, request.Replace); err != nil {
			s.failure(w, 409, err.Error())
			return
		}
		s.respond(w, map[string]bool{"ok": true})
	case "/api/share":
		var request struct {
			Path string `json:"path"`
			To   string `json:"to"`
		}
		if !s.body(w, r, &request) {
			return
		}
		p, err := vault.Path(request.Path, false)
		if err != nil {
			s.failure(w, 400, err.Error())
			return
		}
		packet, err := s.store.Share(p, request.To)
		if err != nil {
			s.failure(w, 400, err.Error())
			return
		}
		s.respond(w, map[string]string{"packet": string(packet)})
	case "/api/inspect", "/api/import":
		var request struct {
			Packet  string `json:"packet"`
			Path    string `json:"path"`
			Replace bool   `json:"replace"`
		}
		if !s.body(w, r, &request) {
			return
		}
		share, err := s.store.InspectShare([]byte(request.Packet))
		if err != nil {
			s.failure(w, 400, err.Error())
			return
		}
		if r.URL.Path == "/api/inspect" {
			s.respond(w, map[string]any{"path": share.Path, "secret": share.Entry.Secret, "type": vault.Type(share.Entry.Value)})
			return
		}
		p, err := vault.Path(request.Path, false)
		if err != nil {
			s.failure(w, 400, err.Error())
			return
		}
		if err := s.store.Set(p, share.Entry, request.Replace); err != nil {
			s.failure(w, 409, err.Error())
			return
		}
		s.respond(w, map[string]bool{"ok": true})
	default:
		s.failure(w, 404, "Not found")
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.failure(w, 405, "Method not allowed")
		return
	}
	var request struct {
		Token string `json:"token"`
	}
	if !s.body(w, r, &request) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.authenticated(r) {
		if s.used || !equal(request.Token, s.bootstrap) {
			s.failure(w, 401, "Open the private launcher created by workbench ui")
			return
		}
		s.used = true
		s.bootstrap = ""
		if s.onLogin != nil {
			s.onLogin()
		}
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: s.session, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.last.Store(time.Now().UnixNano())
	s.respond(w, map[string]string{"csrf": s.csrf})
}

func (s *Server) body(w http.ResponseWriter, r *http.Request, target any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		s.failure(w, 415, "JSON content type required")
		return false
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		s.failure(w, 400, "Invalid request")
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		s.failure(w, 400, "Invalid request")
		return false
	}
	return true
}

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.failure(w, 405, "Method not allowed")
		return
	}
	name, contentType := "", ""
	switch r.URL.Path {
	case "/favicon.ico":
		w.WriteHeader(http.StatusNoContent)
		return
	case "/":
		name, contentType = "index.html", "text/html; charset=utf-8"
	case "/app.js":
		name, contentType = "app.js", "text/javascript; charset=utf-8"
	case "/style.css":
		name, contentType = "style.css", "text/css; charset=utf-8"
	default:
		s.failure(w, 404, "Not found")
		return
	}
	b, err := assets.ReadFile("web/" + name)
	if err != nil {
		s.failure(w, 500, "Asset unavailable")
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(b)
}

func (s *Server) respond(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) failure(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func Serve(store *vault.Store, options Options) error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("cannot listen on loopback")
	}
	defer listener.Close()
	origin := "http://" + listener.Addr().String()
	s, err := New(store, origin, options)
	if err != nil {
		return err
	}
	// Opening a private launcher keeps the session token out of process argv and
	// CLI output. It is consumed once, then removed. No vault value goes in it.
	name, err := randomToken()
	if err != nil {
		return err
	}
	launcher := filepath.Join(store.Dir, ".ui-"+name+".html")
	html := `<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta http-equiv="refresh" content="0;url=` + origin + "/#" + s.bootstrap + `"><title>Open Workbench</title><a href="` + origin + "/#" + s.bootstrap + `">Open Workbench</a>`
	if err := vault.WriteOutput(launcher, []byte(html)); err != nil {
		return err
	}
	defer os.Remove(launcher)
	s.onLogin = func() { _ = os.Remove(launcher) }
	fmt.Fprintf(options.Out, "Workbench UI: %s\nPrivate launcher: %s\nStops after %s of inactivity. Ctrl+C to close.\n", origin, launcher, options.Timeout)
	if options.OpenBrowser {
		binary := "xdg-open"
		if runtime.GOOS == "darwin" {
			binary = "/usr/bin/open"
		}
		cmd := exec.Command(binary, launcher)
		if err := cmd.Run(); err != nil {
			fmt.Fprintln(options.Out, "Browser could not open automatically; open the private launcher above.")
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-result:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return errors.New("local UI server stopped unexpectedly")
		case <-ctx.Done():
			return shutdown(server)
		case <-ticker.C:
			if time.Since(time.Unix(0, s.last.Load())) >= options.Timeout {
				fmt.Fprintln(options.Out, "UI closed after inactivity.")
				return shutdown(server)
			}
		}
	}
}

func shutdown(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return errors.New("cannot finish UI shutdown")
	}
	return nil
}
