package ui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pedroloch/workbench/internal/testutil"
	"github.com/pedroloch/workbench/internal/vault"
)

func uiFixture(t *testing.T) (*Server, *vault.Store, *string) {
	t.Helper()
	store, err := vault.Init(filepath.Join(t.TempDir(), "vault"), &testutil.Ring{}, vault.InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal("SYNTHETIC-UI-SECRET")
	if err := store.Set(".service.credential", vault.Entry{Value: b, Secret: true}, false); err != nil {
		t.Fatal(err)
	}
	copied := new(string)
	server, err := New(store, "http://127.0.0.1:7777", Options{Timeout: time.Minute, Copy: func(v string) error { *copied = v; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return server, store, copied
}

func request(s *Server, method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(method, s.origin+path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", s.origin)
	r.Header.Set("X-Workbench-CSRF", csrf)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func login(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	w := request(s, "POST", "/api/session", map[string]string{"token": s.bootstrap}, nil, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("session cookie protections missing")
	}
	return cookies[0]
}

func TestUIRequiresAuthenticationHostOriginAndCSRF(t *testing.T) {
	s, _, _ := uiFixture(t)
	if w := request(s, "GET", "/api/list", nil, nil, ""); w.Code != 401 || strings.Contains(w.Body.String(), "SYNTHETIC") {
		t.Fatal("unauthenticated list accepted or leaked")
	}
	token := s.bootstrap
	cookie := login(t, s)
	if w := request(s, "POST", "/api/session", map[string]string{"token": token}, nil, ""); w.Code != 401 {
		t.Fatal("bootstrap token replay accepted")
	}
	if w := request(s, "POST", "/api/session", map[string]string{"token": ""}, cookie, ""); w.Code != 200 {
		t.Fatal("page reload could not restore session")
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Host = "attacker.example" },
		func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") },
		func(r *http.Request) { r.Header.Del("Origin") },
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		func(r *http.Request) { r.Header.Del("X-Workbench-CSRF") },
	} {
		r := httptest.NewRequest("POST", s.origin+"/api/reveal", strings.NewReader(`{"path":".service.credential"}`))
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", s.origin)
		r.Header.Set("X-Workbench-CSRF", s.csrf)
		mutate(r)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code == 200 || strings.Contains(w.Body.String(), "SYNTHETIC") {
			t.Fatal("invalid request accepted or leaked")
		}
	}
}

func TestUIListsNoValuesCopiesServerSideAndRevealsExplicitly(t *testing.T) {
	s, _, copied := uiFixture(t)
	cookie := login(t, s)
	w := request(s, "GET", "/api/list", nil, cookie, s.csrf)
	if w.Code != 200 || strings.Contains(w.Body.String(), "SYNTHETIC") || !strings.Contains(w.Body.String(), `"secret":true`) {
		t.Fatal("list exposed value or lost classification")
	}
	w = request(s, "POST", "/api/copy", map[string]string{"path": ".service.credential"}, cookie, s.csrf)
	if w.Code != 200 || *copied != "SYNTHETIC-UI-SECRET" || strings.Contains(w.Body.String(), "SYNTHETIC") {
		t.Fatal("copy contract broken")
	}
	w = request(s, "POST", "/api/reveal", map[string]string{"path": ".service.credential"}, cookie, s.csrf)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "SYNTHETIC-UI-SECRET") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("explicit reveal failed")
	}
	w = request(s, "GET", "/", nil, nil, "")
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || strings.Contains(w.Body.String(), s.session) {
		t.Fatal("static page protections missing")
	}
}

func TestUISetRequiresClassificationAndExplicitReplacement(t *testing.T) {
	s, store, _ := uiFixture(t)
	cookie := login(t, s)
	missing := map[string]any{"path": ".new.token", "value": "SYNTHETIC", "type": "string"}
	if w := request(s, "POST", "/api/set", missing, cookie, s.csrf); w.Code != 400 {
		t.Fatal("missing classification accepted")
	}
	data := map[string]any{"path": ".service.credential", "value": "SYNTHETIC-NEW", "type": "string", "secret": true, "replace": false}
	if w := request(s, "POST", "/api/set", data, cookie, s.csrf); w.Code != 409 {
		t.Fatal("silent replacement accepted")
	}
	data["replace"] = true
	if w := request(s, "POST", "/api/set", data, cookie, s.csrf); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	d, _ := store.View()
	if vault.Display(d.Entries[".service.credential"].Value) != "SYNTHETIC-NEW" {
		t.Fatal("edit did not persist")
	}
}

func TestClassificationChangesVisibilityWithoutReplacingOrDisclosingValue(t *testing.T) {
	s, store, _ := uiFixture(t)
	cookie := login(t, s)
	missing := map[string]any{"path": ".service.credential"}
	if w := request(s, "POST", "/api/classify", missing, cookie, s.csrf); w.Code != 400 {
		t.Fatal("classification was inferred")
	}
	for _, secret := range []bool{false, true} {
		w := request(s, "POST", "/api/classify", map[string]any{"path": ".service.credential", "secret": secret}, cookie, s.csrf)
		if w.Code != 200 || strings.Contains(w.Body.String(), "SYNTHETIC") {
			t.Fatal("classification failed or disclosed value")
		}
		d, err := store.View()
		if err != nil || d.Entries[".service.credential"].Secret != secret || vault.Display(d.Entries[".service.credential"].Value) != "SYNTHETIC-UI-SECRET" {
			t.Fatal("classification changed the value")
		}
	}
}

func TestUIShareInspectAndRemappedImport(t *testing.T) {
	sender, _, _ := uiFixture(t)
	recipient, store, _ := uiFixture(t)
	c1, c2 := login(t, sender), login(t, recipient)
	w := request(sender, "POST", "/api/share", map[string]string{"path": ".service.credential", "to": store.Identity()}, c1, sender.csrf)
	if w.Code != 200 || strings.Contains(w.Body.String(), "SYNTHETIC") {
		t.Fatal("share failed or exposed plaintext")
	}
	var shared struct {
		Packet string `json:"packet"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &shared); err != nil {
		t.Fatal(err)
	}
	w = request(recipient, "POST", "/api/inspect", map[string]string{"packet": shared.Packet}, c2, recipient.csrf)
	if w.Code != 200 || strings.Contains(w.Body.String(), "SYNTHETIC") || !strings.Contains(w.Body.String(), ".service.credential") {
		t.Fatal("inspection failed or exposed value")
	}
	w = request(recipient, "POST", "/api/import", map[string]any{"packet": shared.Packet, "path": ".received.token", "replace": false}, c2, recipient.csrf)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	d, _ := store.View()
	if !d.Entries[".received.token"].Secret {
		t.Fatal("share import lost classification")
	}
	if w := request(recipient, "POST", "/api/import", map[string]any{"packet": shared.Packet, "path": ".received.token", "replace": false}, c2, recipient.csrf); w.Code != 409 {
		t.Fatal("import overwrote silently")
	}
}

func TestSessionsOnDifferentPortsUseDifferentCookies(t *testing.T) {
	s, store, _ := uiFixture(t)
	second, err := New(store, "http://127.0.0.1:8888", s.options)
	if err != nil {
		t.Fatal(err)
	}
	if s.cookieName() == second.cookieName() {
		t.Fatal("separate UI ports share a cookie name")
	}
}

func TestPrivateLauncherCanNavigateToStaticPage(t *testing.T) {
	s, _, _ := uiFixture(t)
	r := httptest.NewRequest("GET", s.origin+"/", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<title>Workbench</title>") {
		t.Fatal("private file launcher cannot load the public static shell")
	}
}
