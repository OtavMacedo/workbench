package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pedroloch/workbench/internal/testutil"
	"github.com/pedroloch/workbench/internal/vault"
)

type harness struct {
	app    *App
	store  *vault.Store
	out    bytes.Buffer
	stderr bytes.Buffer
}

func setup(t *testing.T) *harness {
	t.Helper()
	ring := &testutil.Ring{}
	dir := filepath.Join(t.TempDir(), "vault")
	s, err := vault.Init(dir, ring, vault.InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{store: s}
	h.app = New()
	h.app.Ring = ring
	h.app.Session = &testutil.Session{}
	h.app.Out = &h.out
	h.app.Err = &h.stderr
	h.app.In = strings.NewReader("")
	return h
}
func (h *harness) run(args ...string) int {
	h.out.Reset()
	h.stderr.Reset()
	return h.app.Run(append([]string{"--dir", h.store.Dir}, args...))
}
func TestCommandWorkflowAndSecretOutput(t *testing.T) {
	h := setup(t)
	h.app.In = strings.NewReader("SYNTHETIC-CREDENTIAL-KEEP-HIDDEN")
	if h.run("set", ".service.credential", "--stdin") != 0 {
		t.Fatal(h.stderr.String())
	}
	for _, args := range [][]string{{"get", ".service.credential"}, {"get", "."}, {"list"}, {"doctor"}, {"require", ".service.credential"}, {"require", ".service"}} {
		if h.run(args...) != 0 {
			t.Fatal(h.stderr.String())
		}
		if strings.Contains(h.out.String()+h.stderr.String(), "SYNTHETIC-CREDENTIAL") {
			t.Fatal("diagnostic leaked secret")
		}
	}
	h.app.In = strings.NewReader("https://example.invalid")
	if h.run("set", ".service.host", "--public", "--stdin") != 0 {
		t.Fatal(h.stderr.String())
	}
	if h.run("get", ".service.host") != 0 || !strings.Contains(h.out.String(), "https://example.invalid") {
		t.Fatal("public get failed")
	}
	copied := ""
	h.app.Copy = func(v string) error { copied = v; return nil }
	if h.run("copy", ".service.credential") != 0 || copied != "SYNTHETIC-CREDENTIAL-KEEP-HIDDEN" || strings.Contains(h.out.String(), "SYNTHETIC") {
		t.Fatal("copy contract broken")
	}
	if h.run("reveal", ".service.credential") == 0 {
		t.Fatal("automated reveal accepted")
	}
	if h.run("set", ".service.credential", "SYNTHETIC-ARGUMENT") == 0 || strings.Contains(h.stderr.String(), "SYNTHETIC-ARGUMENT") {
		t.Fatal("secret argument accepted or echoed")
	}
	h.app.In = strings.NewReader("SYNTHETIC-REPLACEMENT")
	if h.run("set", ".service.credential", "--stdin") == 0 {
		t.Fatal("silent overwrite")
	}
	d, _ := h.store.View()
	if vault.Display(d.Entries[".service.credential"].Value) != "SYNTHETIC-CREDENTIAL-KEEP-HIDDEN" {
		t.Fatal("failed overwrite changed data")
	}
}
func TestExecPassesOnlyEnvironmentAndKeepsArguments(t *testing.T) {
	h := setup(t)
	b, _ := json.Marshal("SYNTHETIC-EXEC-TOKEN")
	if err := h.store.Set(".token", vault.Entry{Value: b, Secret: true}, false); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WB_TEST_TOKEN", "old-value")
	called := false
	h.app.Exec = func(binary string, args, env []string) error {
		called = true
		if binary == "" || strings.Join(args, " ") != "sh -c exit 0" {
			t.Fatal("command arguments changed")
		}
		count := 0
		for _, item := range env {
			if strings.HasPrefix(item, "WB_TEST_TOKEN=") {
				count++
				if item != "WB_TEST_TOKEN=SYNTHETIC-EXEC-TOKEN" {
					t.Fatal("wrong injected token")
				}
			}
		}
		if count != 1 || strings.Contains(strings.Join(args, " "), "SYNTHETIC") {
			t.Fatal("token duplicated or in argv")
		}
		return nil
	}
	if h.run("exec", ".token=WB_TEST_TOKEN", "--", "sh", "-c", "exit 0") != 0 || !called {
		t.Fatal(h.stderr.String())
	}
	if strings.Contains(h.out.String()+h.stderr.String(), "SYNTHETIC") {
		t.Fatal("exec leaked token")
	}
}
func TestLegacyMigrationIsAtomicAndLeavesSourceUnchanged(t *testing.T) {
	h := setup(t)
	source := filepath.Join(t.TempDir(), "legacy.yaml")
	original := []byte("service:\n  credential: SYNTHETIC-MIGRATED\n  host: example.invalid\n")
	if err := os.WriteFile(source, original, 0600); err != nil {
		t.Fatal(err)
	}
	if h.run("migrate", source, "--public", ".service.host", "--yes") != 0 {
		t.Fatal(h.stderr.String())
	}
	after, _ := os.ReadFile(source)
	if !bytes.Equal(original, after) {
		t.Fatal("source modified")
	}
	d, _ := h.store.View()
	if !d.Entries[".service.credential"].Secret || d.Entries[".service.host"].Secret {
		t.Fatal("migration classification wrong")
	}
	if strings.Contains(h.out.String()+h.stderr.String(), "SYNTHETIC") {
		t.Fatal("migration leaked secret")
	}
	if h.run("migrate", source, "--yes") == 0 {
		t.Fatal("conflicting migration accepted")
	}
	if err := os.Chmod(source, 0644); err != nil {
		t.Fatal(err)
	}
	if h.run("migrate", source, "--yes", "--replace") == 0 {
		t.Fatal("insecure source accepted")
	}
}
func TestImportRequiresConfirmationAndSupportsRemapping(t *testing.T) {
	sender, recipient := setup(t), setup(t)
	b, _ := json.Marshal("SYNTHETIC-SHARE")
	if err := sender.store.Set(".source.token", vault.Entry{Value: b, Secret: true}, false); err != nil {
		t.Fatal(err)
	}
	packet, err := sender.store.Share(".source.token", recipient.store.Identity())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "share.wb")
	if err := os.WriteFile(file, packet, 0644); err != nil {
		t.Fatal(err)
	}
	if recipient.run("import", file, "--as", ".local.credential") == 0 {
		t.Fatal("unconfirmed import accepted")
	}
	if recipient.run("import", file, "--as", ".local.credential", "--yes") != 0 {
		t.Fatal(recipient.stderr.String())
	}
	if recipient.run("import", file, "--as", ".local.credential", "--yes") == 0 {
		t.Fatal("silent import replacement accepted")
	}
	d, _ := recipient.store.View()
	if !d.Entries[".local.credential"].Secret || vault.Display(d.Entries[".local.credential"].Value) != "SYNTHETIC-SHARE" {
		t.Fatal("remap failed")
	}
}

func TestClassifyRequiresExplicitChoiceAndPreservesValue(t *testing.T) {
	h := setup(t)
	b, _ := json.Marshal("SYNTHETIC-CLASSIFICATION")
	if err := h.store.Set(".host", vault.Entry{Value: b, Secret: true}, false); err != nil {
		t.Fatal(err)
	}
	if h.run("classify", ".host") == 0 || h.run("classify", ".host", "--public", "--secret") == 0 {
		t.Fatal("ambiguous classification accepted")
	}
	for _, option := range []string{"--public", "--secret"} {
		if h.run("classify", "host", option) != 0 || strings.Contains(h.out.String()+h.stderr.String(), "SYNTHETIC") {
			t.Fatal("classification failed or disclosed value")
		}
		d, _ := h.store.View()
		if !bytes.Equal(d.Entries[".host"].Value, b) || d.Entries[".host"].Secret != (option == "--secret") {
			t.Fatal("classification lost value or did not persist")
		}
	}
}
