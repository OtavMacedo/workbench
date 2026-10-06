package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age/armor"
	"github.com/pedroloch/workbench/internal/vault"
)

func TestUseAcceptsHeaderlessBase64WithoutPersisting(t *testing.T) {
	h := setup(t)
	before := snapshot(t, h.store.Dir)
	raw, _ := json.Marshal("SYNTHETIC-HEADERLESS")
	armored, err := vault.Seal(".temporary.value", vault.Entry{Value: raw, Secret: true}, h.store.Identity())
	if err != nil {
		t.Fatal(err)
	}
	binary, err := io.ReadAll(armor.NewReader(bytes.NewReader(armored)))
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.ReplaceAll(armored, []byte("-----BEGIN AGE ENCRYPTED FILE-----"), nil)
	body = bytes.ReplaceAll(body, []byte("-----END AGE ENCRYPTED FILE-----"), nil)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"wrapped base64", body},
		{"one line", []byte(base64.StdEncoding.EncodeToString(binary))},
		{"unpadded", []byte(base64.RawStdEncoding.EncodeToString(binary))},
		{"armor with surrounding whitespace", append(append([]byte(" \n"), armored...), []byte("\n\t")...)},
		{"binary", binary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h.app.Exec = func(_ string, _ []string, env []string) error {
				called = true
				found := false
				for _, item := range env {
					if item == "WB_HEADERLESS=SYNTHETIC-HEADERLESS" {
						found = true
					}
				}
				if !found {
					t.Fatal("child did not receive the exact value")
				}
				return nil
			}
			h.app.In = bytes.NewReader(tc.data)
			if h.run("use", "-", "--env", "WB_HEADERLESS", "--", "sh", "-c", "exit 0") != 0 || !called {
				t.Fatal(h.stderr.String())
			}
			if strings.Contains(h.out.String()+h.stderr.String(), "SYNTHETIC") {
				t.Fatal("value was disclosed")
			}
			for name, content := range snapshot(t, h.store.Dir) {
				if !bytes.Equal(before[name], content) {
					t.Fatal("temporary use modified vault", name)
				}
			}
		})
	}
	other := setup(t)
	wrong, _ := vault.Seal(".temporary.value", vault.Entry{Value: raw, Secret: true}, other.store.Identity())
	wrong = bytes.ReplaceAll(wrong, []byte("-----BEGIN AGE ENCRYPTED FILE-----"), nil)
	wrong = bytes.ReplaceAll(wrong, []byte("-----END AGE ENCRYPTED FILE-----"), nil)
	tampered := append([]byte(nil), binary...)
	tampered[len(tampered)-1] ^= 1
	h.app.Exec = func(string, []string, []string) error { t.Fatal("rejected packet executed"); return nil }
	for _, data := range [][]byte{
		wrong,
		[]byte(base64.StdEncoding.EncodeToString(tampered)),
		[]byte("invalid@@base64"),
		[]byte(base64.StdEncoding.EncodeToString([]byte("plaintext is not a packet"))),
	} {
		h.app.In = bytes.NewReader(data)
		if h.run("use", "-", "--env", "WB_HEADERLESS", "--", "sh", "-c", "exit 0") == 0 {
			t.Fatal("invalid packet accepted")
		}
	}
}

func TestTransientSecretWorkflowDoesNotPersist(t *testing.T) {
	h := setup(t)
	before := snapshot(t, h.store.Dir)
	secret := "SYNTHETIC-TEMPORARY-SECRET\n"
	h.app.In = strings.NewReader(secret)
	if h.run("seal", "--stdin") != 0 {
		t.Fatal(h.stderr.String())
	}
	packet := append([]byte(nil), h.out.Bytes()...)
	if !bytes.HasPrefix(packet, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) || strings.Contains(h.out.String()+h.stderr.String(), secret) {
		t.Fatal("seal output is not ciphertext only")
	}
	share, err := h.store.InspectShare(packet)
	if err != nil || !share.Entry.Secret || vault.Display(share.Entry.Value) != secret {
		t.Fatal("sealed value changed or lost secret classification")
	}
	t.Setenv("WB_TRANSIENT_TOKEN", "inherited")
	called := false
	h.app.Exec = func(binary string, args, env []string) error {
		called = true
		if binary == "" || strings.Join(args, " ") != "sh -c exit 0" {
			t.Fatal("child arguments changed")
		}
		count := 0
		for _, item := range env {
			if strings.HasPrefix(item, "WB_TRANSIENT_TOKEN=") {
				count++
				if item != "WB_TRANSIENT_TOKEN="+secret {
					t.Fatal("child did not receive exact value")
				}
			}
		}
		if count != 1 {
			t.Fatal("duplicate environment variable")
		}
		return nil
	}
	h.app.In = bytes.NewReader(packet)
	if h.run("use", "-", "--env", "WB_TRANSIENT_TOKEN", "--", "sh", "-c", "exit 0") != 0 || !called {
		t.Fatal(h.stderr.String())
	}
	if h.out.Len() != 0 || strings.Contains(h.stderr.String(), secret) {
		t.Fatal("temporary use disclosed secret")
	}
	after := snapshot(t, h.store.Dir)
	if len(before) != len(after) {
		t.Fatal("transient workflow created files")
	}
	for name, b := range before {
		if !bytes.Equal(b, after[name]) {
			t.Fatal("transient workflow modified vault", name)
		}
	}
	d, err := h.store.View()
	if err != nil || len(d.Entries) != 0 {
		t.Fatal("temporary value persisted")
	}
	// Persistence is a separate, explicit operation using the very same packet.
	h.app.In = bytes.NewReader(packet)
	if h.run("import", "-", "--as", ".saved.token", "--yes") != 0 {
		t.Fatal(h.stderr.String())
	}
	d, _ = h.store.View()
	if vault.Display(d.Entries[".saved.token"].Value) != secret {
		t.Fatal("explicit persistence failed")
	}
}

func snapshot(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string][]byte{}
	for _, entry := range entries {
		b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = b
	}
	return result
}

func TestSealForRecipientNeedsNoSenderVault(t *testing.T) {
	h := setup(t)
	dir := filepath.Join(t.TempDir(), "absent-vault")
	h.app.In = strings.NewReader("SYNTHETIC-REMOTE-TOKEN")
	if h.app.Run([]string{"--dir", dir, "seal", "--stdin", "--to", h.store.Identity(), "--as", ".remote.token"}) != 0 {
		t.Fatal(h.stderr.String())
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("seal created sender vault")
	}
	share, err := h.store.InspectShare(h.out.Bytes())
	if err != nil || share.Path != ".remote.token" {
		t.Fatal("recipient cannot inspect packet")
	}
}

func TestUseRejectsInvalidPacketsBeforeExecuting(t *testing.T) {
	h, other := setup(t), setup(t)
	raw, _ := json.Marshal("SYNTHETIC-REJECTED")
	packet, _ := vault.Seal(".temporary.value", vault.Entry{Value: raw, Secret: true}, h.store.Identity())
	nul, _ := json.Marshal("SYNTHETIC\x00NULL")
	nulPacket, _ := vault.Seal(".temporary.value", vault.Entry{Value: nul, Secret: true}, h.store.Identity())
	wrong, _ := vault.Seal(".temporary.value", vault.Entry{Value: raw, Secret: true}, other.store.Identity())
	for _, tc := range []struct {
		name string
		data []byte
		env  string
	}{
		{"wrong recipient", wrong, "TOKEN"},
		{"corrupt", []byte("not an age packet"), "TOKEN"},
		{"nul", nulPacket, "TOKEN"},
		{"invalid variable", packet, "TOKEN=bad"},
		{"missing variable", packet, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.app.Exec = func(string, []string, []string) error { t.Fatal("invalid packet reached child"); return nil }
			h.app.In = bytes.NewReader(tc.data)
			if h.run("use", "-", "--env", tc.env, "--", "sh", "-c", "exit 0") == 0 {
				t.Fatal("invalid use accepted")
			}
			if strings.Contains(h.out.String()+h.stderr.String(), "SYNTHETIC") {
				t.Fatal("error leaked value")
			}
		})
	}
}

func TestSealRejectsPlaintextArgumentsAndInvalidScalars(t *testing.T) {
	h := setup(t)
	if h.run("seal", "SYNTHETIC-ARGV") == 0 || strings.Contains(h.stderr.String(), "SYNTHETIC") {
		t.Fatal("plaintext argument accepted or echoed")
	}
	h.app.In = strings.NewReader(`{"credential":"SYNTHETIC-JSON"}`)
	if h.run("seal", "--stdin", "--json") == 0 || strings.Contains(h.out.String()+h.stderr.String(), "SYNTHETIC") {
		t.Fatal("invalid scalar accepted or disclosed")
	}
	h.app.In = strings.NewReader(strings.Repeat("x", (1<<20)+1))
	if h.run("seal", "--stdin") == 0 || h.out.Len() != 0 {
		t.Fatal("oversized input accepted")
	}
}
