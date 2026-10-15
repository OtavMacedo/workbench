package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pedroloch/workbench/internal/testutil"
	"github.com/pedroloch/workbench/internal/vault"
)

func TestUnlockLetsCommandsWithoutTerminalOpenPassphraseVault(t *testing.T) {
	ring, session := &testutil.Ring{}, &testutil.Session{}
	dir := filepath.Join(t.TempDir(), "vault")
	s, err := vault.Init(dir, ring, vault.InitOptions{UsePassword: true, Password: "synthetic vault passphrase"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal("SYNTHETIC-UNLOCK-TOKEN")
	if err := s.Set(".token", vault.Entry{Value: b, Secret: true}, false); err != nil {
		t.Fatal(err)
	}
	h := &harness{store: s}
	h.app = New()
	h.app.Ring, h.app.Session = ring, session
	h.app.Out, h.app.Err, h.app.In = &h.out, &h.stderr, strings.NewReader("")
	injected := ""
	h.app.Exec = func(_ string, _ []string, env []string) error {
		for _, item := range env {
			if strings.HasPrefix(item, "WB_UNLOCK_TOKEN=") {
				injected = item
			}
		}
		return nil
	}
	exec := func() int { return h.run("exec", ".token=WB_UNLOCK_TOKEN", "--", "sh", "-c", "exit 0") }

	if exec() == 0 {
		t.Fatal("locked vault opened without a terminal")
	}
	if runtime.GOOS == "linux" && !strings.Contains(h.stderr.String(), "wkb unlock") {
		t.Fatal("locked vault error does not point to unlock:", h.stderr.String())
	}
	if h.run("unlock") == 0 {
		t.Fatal("unlock accepted a passphrase without a terminal")
	}
	passwordFile := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(passwordFile, []byte("synthetic vault passphrase"), 0600); err != nil {
		t.Fatal(err)
	}
	if h.run("--password-file", passwordFile, "unlock") == 0 || !strings.Contains(h.stderr.String(), "not --password-file") {
		t.Fatal("unlock accepted a passphrase file")
	}
	if session.TTL != 0 {
		t.Fatal("rejected unlock cached an identity")
	}

	// What the human's wkb unlock does after reading the passphrase in a terminal.
	opened, err := vault.Open(dir, ring, nil, func() (string, error) { return "synthetic vault passphrase", nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Unlock(session, time.Hour); err != nil {
		t.Fatal(err)
	}
	if exec() != 0 || injected != "WB_UNLOCK_TOKEN=SYNTHETIC-UNLOCK-TOKEN" {
		t.Fatal("unlocked vault did not inject the value:", h.stderr.String())
	}
	if h.run("unlock") == 0 {
		t.Fatal("unlock was extended without the passphrase")
	}
	if h.run("lock") != 0 || !strings.Contains(h.out.String(), "Locked") {
		t.Fatal(h.stderr.String())
	}
	if exec() == 0 {
		t.Fatal("lock kept the vault open")
	}
}
