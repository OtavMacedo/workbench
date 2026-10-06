package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallPreservesExistingCommands(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bin")
	content := []byte("synthetic executable")
	if err := installExecutable(dir, content, false); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "wkb")
	info, _ := os.Stat(file)
	if info.Mode().Perm() != 0755 {
		t.Fatal("installed file is not executable")
	}
	if err := installExecutable(dir, content, false); err != nil {
		t.Fatal("identical install failed", err)
	}
	replacement := []byte("updated executable")
	if err := installExecutable(dir, replacement, false); err == nil {
		t.Fatal("unconfirmed replacement")
	}
	b, _ := os.ReadFile(file)
	if !bytes.Equal(b, content) {
		t.Fatal("existing binary changed")
	}
	if err := installExecutable(dir, replacement, true); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(file)
	if !bytes.Equal(b, replacement) {
		t.Fatal("replacement not installed")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatal("installer left temporary files")
	}
}

func TestInstallPreservesLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(target, []byte("user command"), 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "wkb")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := installExecutable(dir, []byte("new command"), true); err == nil {
		t.Fatal("symlink overwritten")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "user command" {
		t.Fatal("external binary changed")
	}
	if info, _ := os.Lstat(link); info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("link replaced")
	}
}

func TestInstallCommandNeedsNoVault(t *testing.T) {
	a := New()
	var out, stderr bytes.Buffer
	a.Out, a.Err = &out, &stderr
	dir := t.TempDir()
	vault := filepath.Join(t.TempDir(), "absent")
	if a.Run([]string{"--dir", vault, "install", "--dir", dir}) != 0 {
		t.Fatal(stderr.String())
	}
	if _, err := os.Stat(vault); !os.IsNotExist(err) {
		t.Fatal("install touched vault")
	}
	installed, err := os.ReadFile(filepath.Join(dir, "wkb"))
	if err != nil || len(installed) == 0 {
		t.Fatal("no executable installed")
	}
}
