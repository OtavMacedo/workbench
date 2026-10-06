package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/pedroloch/workbench/skills"
)

func TestSkillInstallWorksWithoutVaultAndPreservesExistingWork(t *testing.T) {
	a := New()
	var out, stderr bytes.Buffer
	a.Out, a.Err = &out, &stderr
	dir := filepath.Join(t.TempDir(), "skills")
	absent := filepath.Join(t.TempDir(), "uninitialized")
	args := []string{"--dir", absent, "skill", "install", "--dir", dir}
	if a.Run(args) != 0 {
		t.Fatal(stderr.String())
	}
	file := filepath.Join(dir, "workbench", "SKILL.md")
	b, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(b, skills.Workbench) {
		t.Fatal("embedded skill not installed")
	}
	if _, err := os.Stat(absent); !os.IsNotExist(err) {
		t.Fatal("skill install touched vault")
	}
	if a.Run(args) != 0 {
		t.Fatal("identical reinstall failed")
	}
	old := []byte("existing custom instructions\n")
	if err := os.WriteFile(file, old, 0644); err != nil {
		t.Fatal(err)
	}
	if a.Run(args) == 0 {
		t.Fatal("unconfirmed overwrite")
	}
	b, _ = os.ReadFile(file)
	if !bytes.Equal(b, old) {
		t.Fatal("existing skill modified")
	}
	if a.Run(append(args, "--replace")) != 0 {
		t.Fatal(stderr.String())
	}
	b, _ = os.ReadFile(file)
	if !bytes.Equal(b, skills.Workbench) {
		t.Fatal("explicit replacement failed")
	}
}

func TestSkillInstallPreservesSymlinks(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[directory], func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "skills")
			outside := t.TempDir()
			original := []byte("user-owned skill\n")
			file := filepath.Join(outside, "SKILL.md")
			if err := os.WriteFile(file, original, 0644); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, "workbench")
			target := outside
			if !directory {
				link = filepath.Join(link, "SKILL.md")
				target = file
			}
			if err := os.MkdirAll(filepath.Dir(link), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			if err := installSkill(dir, true); err == nil {
				t.Fatal("symlink overwritten")
			}
			b, _ := os.ReadFile(file)
			if !bytes.Equal(b, original) {
				t.Fatal("external skill changed")
			}
			if info, _ := os.Lstat(link); info.Mode()&os.ModeSymlink == 0 {
				t.Fatal("link replaced")
			}
		})
	}
}

func TestSkillAgentDirectories(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(t.TempDir(), "claude"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "config"))
	codexHome := os.Getenv("CODEX_HOME")
	if codexHome == "" {
		codexHome = filepath.Join(home, ".codex")
	}
	for _, tc := range []struct{ agent, project, global string }{
		{"", ".agents/skills", filepath.Join(home, ".agents/skills")},
		{"pi", ".agents/skills", filepath.Join(home, ".agents/skills")},
		{"codex", ".agents/skills", filepath.Join(codexHome, "skills")},
		{"claude-code", ".claude/skills", filepath.Join(os.Getenv("CLAUDE_CONFIG_DIR"), "skills")},
		{"opencode", ".agents/skills", filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "opencode/skills")},
		{"cursor", ".agents/skills", filepath.Join(home, ".cursor/skills")},
	} {
		for _, global := range []bool{false, true} {
			want := tc.project
			if global {
				want = tc.global
			}
			got, err := skillDirectory(tc.agent, global)
			if err != nil || got != want {
				t.Fatalf("agent %q global=%v: %q, %v", tc.agent, global, got, err)
			}
		}
	}
	if _, err := skillDirectory("../../outside", false); err == nil {
		t.Fatal("unrecognized agent accepted")
	}
}
