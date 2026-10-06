package app

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pedroloch/workbench/skills"
	"golang.org/x/sys/unix"
)

func (a *App) skill(args []string) error {
	if len(args) == 0 || args[0] != "install" {
		return errors.New("usage: skill install [--agent codex|claude-code|opencode|pi|cursor] [--global] [--replace], or skill install --dir SKILLS_DIRECTORY")
	}
	f := flags("skill install")
	agent := f.String("agent", "", "target agent; defaults to shared .agents/skills")
	global := f.Bool("global", false, "install for the current user instead of the current project")
	dir := f.String("dir", "", "explicit skills directory, independent of agent and scope")
	replace := f.Bool("replace", false, "replace an existing regular SKILL.md")
	pos, err := parse(f, args[1:])
	if err != nil {
		return err
	}
	if len(pos) != 0 || (*dir != "" && (*agent != "" || *global)) {
		return errors.New("use --dir alone to select a skills directory, or select --agent and --global")
	}
	if *dir == "" {
		*dir, err = skillDirectory(*agent, *global)
		if err != nil {
			return err
		}
	}
	absolute, err := filepath.Abs(*dir)
	if err != nil {
		return errors.New("invalid skills directory")
	}
	if err := installSkill(absolute, *replace); err != nil {
		return err
	}
	fmt.Fprintln(a.Out, "Skill ready:", filepath.Join(absolute, "workbench", "SKILL.md"))
	return nil
}

func skillDirectory(agent string, global bool) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("cannot find home directory")
	}
	fromEnv := func(name, fallback string) string {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
		return filepath.Join(home, fallback)
	}
	project, user := ".agents/skills", filepath.Join(home, ".agents/skills")
	switch agent {
	case "", "pi":
	case "codex":
		user = filepath.Join(fromEnv("CODEX_HOME", ".codex"), "skills")
	case "claude-code":
		project = ".claude/skills"
		user = filepath.Join(fromEnv("CLAUDE_CONFIG_DIR", ".claude"), "skills")
	case "opencode":
		user = filepath.Join(fromEnv("XDG_CONFIG_HOME", ".config"), "opencode/skills")
	case "cursor":
		user = filepath.Join(home, ".cursor/skills")
	default:
		return "", errors.New("unsupported agent; use codex, claude-code, opencode, pi, cursor, or --dir")
	}
	if global {
		if !filepath.IsAbs(user) {
			return "", errors.New("agent configuration directory must be absolute")
		}
		return user, nil
	}
	return project, nil
}

func installSkill(dir string, replace bool) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errors.New("cannot create skills directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return errors.New("cannot open skills directory")
	}
	defer root.Close()
	if err := root.Mkdir("workbench", 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("cannot create workbench skill directory")
	}
	info, err := root.Lstat("workbench")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("existing workbench skill must be a real directory; links are preserved")
	}
	target, err := root.OpenRoot("workbench")
	if err != nil {
		return errors.New("cannot open workbench skill directory")
	}
	defer target.Close()
	if info, err := target.Lstat("SKILL.md"); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("existing SKILL.md must be a regular file; links are preserved")
		}
		f, err := target.OpenFile("SKILL.md", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return errors.New("cannot inspect existing skill")
		}
		b, readErr := io.ReadAll(io.LimitReader(f, int64(len(skills.Workbench)+1)))
		f.Close()
		if readErr != nil {
			return errors.New("cannot read existing skill")
		}
		if bytes.Equal(b, skills.Workbench) {
			return nil
		}
		if !replace {
			return errors.New("skill already exists; inspect it and use --replace to authorize an update")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect skill destination")
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return errors.New("cannot generate temporary skill filename")
	}
	name := ".tmp-" + hex.EncodeToString(id)
	f, err := target.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0644)
	if err != nil {
		return errors.New("cannot create skill update")
	}
	defer target.Remove(name)
	_, err = f.Write(skills.Workbench)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("cannot write skill update")
	}
	if replace {
		err = target.Rename(name, "SKILL.md")
	} else {
		// Linking commits a complete file atomically without replacing a concurrent install.
		err = target.Link(name, "SKILL.md")
	}
	if err != nil {
		return errors.New("cannot install skill; destination may have changed")
	}
	d, err := target.Open(".")
	if err != nil {
		return errors.New("skill installed but directory sync failed")
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return errors.New("skill installed but directory sync failed")
	}
	return nil
}
