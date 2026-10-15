package vault_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/pedroloch/workbench/internal/testutil"
	"github.com/pedroloch/workbench/internal/vault"
)

func fixture(t *testing.T) (*vault.Store, *testutil.Ring) {
	t.Helper()
	ring := &testutil.Ring{}
	s, err := vault.Init(filepath.Join(t.TempDir(), "vault"), ring, vault.InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return s, ring
}

func secret(value string) vault.Entry {
	b, _ := json.Marshal(value)
	return vault.Entry{Value: b, Secret: true}
}

func TestDiskEncryptionAndIndependentOpen(t *testing.T) {
	s, ring := fixture(t)
	if err := s.Set(".service.credential", secret("SYNTHETIC-SECRET-NEVER-PERSIST-CLEAR"), false); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"meta.json", "vault.age"} {
		p := filepath.Join(s.Dir, name)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("SYNTHETIC-SECRET")) || bytes.Contains(b, []byte("credential")) {
			t.Fatal("secret value or path persisted in plaintext")
		}
		info, _ := os.Stat(p)
		if info.Mode().Perm() != 0600 {
			t.Fatal("insecure file mode")
		}
	}
	second, err := vault.Open(s.Dir, ring, nil, func() (string, error) { t.Fatal("unexpected password prompt"); return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	d, err := second.View()
	if err != nil {
		t.Fatal(err)
	}
	if !d.Entries[".service.credential"].Secret || vault.Display(d.Entries[".service.credential"].Value) != "SYNTHETIC-SECRET-NEVER-PERSIST-CLEAR" {
		t.Fatal("round trip changed entry")
	}
}

func TestShareWrongRecipientTamperAndRemap(t *testing.T) {
	sender, _ := fixture(t)
	recipient, _ := fixture(t)
	wrong, _ := fixture(t)
	if err := sender.Set(".old.credential", secret("SYNTHETIC-SHARED-VALUE"), false); err != nil {
		t.Fatal(err)
	}
	packet, err := sender.Share(".old.credential", recipient.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(packet, []byte("SYNTHETIC")) || bytes.Contains(packet, []byte(".old.credential")) {
		t.Fatal("share leaked plaintext")
	}
	if _, err := wrong.InspectShare(packet); err == nil {
		t.Fatal("wrong recipient accepted")
	}
	raw, err := io.ReadAll(armor.NewReader(bytes.NewReader(packet)))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if _, err := recipient.InspectShare(raw); err == nil {
		t.Fatal("tampered packet accepted")
	}
	share, err := recipient.InspectShare(packet)
	if err != nil {
		t.Fatal(err)
	}
	if err := recipient.Set(".local.token", share.Entry, false); err != nil {
		t.Fatal(err)
	}
	if err := recipient.Set(".local.token", secret("replacement"), false); err == nil {
		t.Fatal("silent overwrite accepted")
	}
	d, _ := recipient.View()
	if vault.Display(d.Entries[".local.token"].Value) != "SYNTHETIC-SHARED-VALUE" {
		t.Fatal("conflict changed existing value")
	}
}

func TestTamperedVaultNeverReturnsPartialData(t *testing.T) {
	s, _ := fixture(t)
	if err := s.Set(".key", secret("SYNTHETIC"), false); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.Dir, "vault.age")
	b, _ := os.ReadFile(p)
	b[len(b)-1] ^= 1
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.View(); err == nil {
		t.Fatal("corrupted vault accepted")
	}
	if err := s.Set(".another", secret("SYNTHETIC"), false); err == nil {
		t.Fatal("corrupted vault overwritten")
	}
}

func TestPrivatePathsAndLinks(t *testing.T) {
	for _, mode := range []os.FileMode{0644, 0660} {
		t.Run(fmt.Sprintf("file-%o", mode), func(t *testing.T) {
			s, _ := fixture(t)
			if err := os.Chmod(filepath.Join(s.Dir, "vault.age"), mode); err != nil {
				t.Fatal(err)
			}
			if _, err := s.View(); err == nil {
				t.Fatal("insecure file accepted")
			}
		})
	}
	t.Run("directory", func(t *testing.T) {
		s, _ := fixture(t)
		_ = os.Chmod(s.Dir, 0755)
		if _, err := s.View(); err == nil {
			t.Fatal("insecure directory accepted")
		}
	})
	t.Run("parent", func(t *testing.T) {
		s, _ := fixture(t)
		_ = os.Chmod(filepath.Dir(s.Dir), 0777)
		t.Cleanup(func() { _ = os.Chmod(filepath.Dir(s.Dir), 0700) })
		if _, err := s.View(); err == nil {
			t.Fatal("writable parent accepted")
		}
	})
	t.Run("vault-symlink", func(t *testing.T) {
		s, _ := fixture(t)
		source := filepath.Join(s.Dir, "vault.age")
		target := filepath.Join(s.Dir, "other.age")
		_ = os.Rename(source, target)
		if err := os.Symlink(target, source); err != nil {
			t.Fatal(err)
		}
		if _, err := s.View(); err == nil {
			t.Fatal("vault symlink accepted")
		}
	})
	t.Run("lock-symlink", func(t *testing.T) {
		s, _ := fixture(t)
		lock := filepath.Join(s.Dir, ".lock")
		_ = os.Remove(lock)
		_ = os.Symlink(filepath.Join(s.Dir, "vault.age"), lock)
		if err := s.Set(".key", secret("SYNTHETIC"), false); err == nil {
			t.Fatal("lock symlink accepted")
		}
	})
	t.Run("dangling-output", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "out")
		_ = os.Symlink(filepath.Join(t.TempDir(), "missing"), p)
		if err := vault.WriteOutput(p, []byte("encrypted")); err == nil {
			t.Fatal("output symlink followed")
		}
	})
}

func TestConcurrentWritersKeepEveryUpdate(t *testing.T) {
	s, ring := fixture(t)
	second, err := vault.Open(s.Dir, ring, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := s
			if i%2 == 0 {
				store = second
			}
			if err := store.Set(fmt.Sprintf(".key%d", i), secret("SYNTHETIC"), false); err != nil {
				failures <- err
			}
		}(i)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	d, err := s.View()
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Entries) != 20 {
		t.Fatalf("lost updates: got %d", len(d.Entries))
	}
}

func TestPasswordVaultAndRecovery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	ring := &testutil.Ring{}
	s, err := vault.Init(dir, ring, vault.InitOptions{UsePassword: true, Password: "synthetic vault passphrase"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set(".credential", secret("SYNTHETIC-RECOVERY-VALUE"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Open(dir, ring, nil, func() (string, error) { return "wrong synthetic passphrase", nil }); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := vault.Open(dir, ring, nil, func() (string, error) { return "synthetic vault passphrase", nil }); err != nil {
		t.Fatal(err)
	}
	backup, err := s.Backup("synthetic recovery passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(backup, []byte("SYNTHETIC-RECOVERY")) {
		t.Fatal("backup leaked value")
	}
	identity, entries, err := vault.Recover(backup, "synthetic recovery passphrase")
	if err != nil {
		t.Fatal(err)
	}
	restored, err := vault.Init(filepath.Join(t.TempDir(), "restored"), ring, vault.InitOptions{Identity: identity, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	if restored.Identity() != s.Identity() {
		t.Fatal("recovery changed receiving identity")
	}
	d, _ := restored.View()
	if vault.Display(d.Entries[".credential"].Value) != "SYNTHETIC-RECOVERY-VALUE" {
		t.Fatal("recovery lost data")
	}
	if _, err := vault.Init(dir, ring, vault.InitOptions{}); err == nil {
		t.Fatal("init overwrote existing vault")
	}
}

func TestMinimumPassphraseCountsCharacters(t *testing.T) {
	for _, password := range []string{"short", "😀😀😀", "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"} {
		if _, err := vault.Init(filepath.Join(t.TempDir(), "vault"), &testutil.Ring{}, vault.InitOptions{UsePassword: true, Password: password}); err == nil {
			t.Fatal("short or invalid UTF-8 passphrase accepted")
		}
	}
}

func TestPathsClassificationAndStructure(t *testing.T) {
	for _, p := range []string{"", ".", ".a | .secret", ".a[999999999999999999999]", ".[0]", ".a[01]", ".a/b"} {
		if _, err := vault.Path(p, false); err == nil {
			t.Errorf("accepted invalid path %q", p)
		}
	}
	for _, p := range []string{".a[0].b", "a-b.token", ".a_key"} {
		if _, err := vault.Path(p, false); err != nil {
			t.Errorf("rejected valid path %q", p)
		}
	}
	var e vault.Entry
	if err := json.Unmarshal([]byte(`{"value":"synthetic"}`), &e); err == nil {
		t.Fatal("missing classification accepted")
	}
	data := map[string]any{"service": map[string]any{"credential": "SYNTHETIC", "host": "example.invalid"}, "ports": []any{80, 443}}
	entries, err := vault.Flatten(data, map[string]bool{".service.host": true})
	if err != nil {
		t.Fatal(err)
	}
	if !entries[".service.credential"].Secret || entries[".service.host"].Secret {
		t.Fatal("classification wrong")
	}
	d := vault.Document{Version: 1, Entries: entries}
	tree, err := d.Tree(".", true)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(tree)
	if strings.Contains(string(b), "SYNTHETIC") || !strings.Contains(string(b), "example.invalid") {
		t.Fatal("tree masking failed")
	}
	for name, entries := range map[string]map[string]vault.Entry{
		"scalar-parent":   {".a": secret("x"), ".a-foo": secret("x"), ".a.b": secret("x")},
		"mixed-container": {".a.x": secret("x"), ".a[0]": secret("x")},
		"sparse-array":    {".a[9]": secret("x")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := (vault.Document{Version: 1, Entries: entries}).Validate(); err == nil {
				t.Fatal("invalid structure accepted")
			}
		})
	}
	large := vault.Document{Version: 1, Entries: map[string]vault.Entry{".number": {Value: json.RawMessage("9007199254740993"), Secret: false}}}
	tree, err = large.Tree(".", true)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(tree)
	if !bytes.Contains(b, []byte("9007199254740993")) {
		t.Fatal("integer precision lost")
	}
}

func passwordFixture(t *testing.T) (string, *testutil.Ring) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	ring := &testutil.Ring{}
	s, err := vault.Init(dir, ring, vault.InitOptions{UsePassword: true, Password: "synthetic vault passphrase"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set(".credential", secret("SYNTHETIC-UNLOCK-VALUE"), false); err != nil {
		t.Fatal(err)
	}
	return dir, ring
}

func passphrase() (string, error) { return "synthetic vault passphrase", nil }
func noTerminal() (string, error) { return "", errors.New("no terminal") }

func TestUnlockOpensWithoutPassphraseUntilLocked(t *testing.T) {
	dir, ring := passwordFixture(t)
	session := &testutil.Session{}
	if _, err := vault.Open(dir, ring, session, noTerminal); err == nil {
		t.Fatal("locked vault opened without passphrase")
	}
	s, err := vault.Open(dir, ring, nil, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Unlock(session, time.Hour); err != nil || session.TTL != time.Hour {
		t.Fatal("unlock did not cache the identity with its ttl")
	}
	unlocked, err := vault.Open(dir, ring, session, noTerminal)
	if err != nil {
		t.Fatal(err)
	}
	d, err := unlocked.View()
	if err != nil || vault.Display(d.Entries[".credential"].Value) != "SYNTHETIC-UNLOCK-VALUE" {
		t.Fatal("unlocked vault cannot read its data")
	}
	if _, err := vault.Open(dir, ring, nil, noTerminal); err == nil {
		t.Fatal("open without cache skipped the passphrase")
	}
	if err := vault.Lock(dir, session); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Open(dir, ring, session, noTerminal); err == nil {
		t.Fatal("lock kept the vault open")
	}
}

func TestUnlockRejectsKeychainVaultsAndForeignIdentities(t *testing.T) {
	s, ring := fixture(t)
	session := &testutil.Session{}
	if err := s.Unlock(session, time.Hour); err == nil {
		t.Fatal("keychain vault unlocked")
	}
	if err := vault.Lock(s.Dir, session); err == nil {
		t.Fatal("keychain vault locked")
	}
	dir, ring := passwordFixture(t)
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct{ Account string }
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatal(err)
	}
	foreign, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	_ = session.Put(meta.Account, foreign.String(), time.Hour)
	if _, err := vault.Open(dir, ring, session, passphrase); err == nil {
		t.Fatal("foreign cached identity accepted")
	}
}
