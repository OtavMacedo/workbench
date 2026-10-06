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

	"golang.org/x/sys/unix"
)

func (a *App) install(args []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("cannot find home directory")
	}
	f := flags("install")
	dir := f.String("dir", filepath.Join(home, ".local", "bin"), "binary installation directory")
	replace := f.Bool("replace", false, "replace an existing regular wkb executable")
	pos, err := parse(f, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return errors.New("usage: install [--dir BIN_DIRECTORY] [--replace]")
	}
	source, err := os.Executable()
	if err != nil {
		return errors.New("cannot locate running executable")
	}
	info, err := os.Stat(source)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return errors.New("cannot read running executable")
	}
	content, err := os.ReadFile(source)
	if err != nil {
		return errors.New("cannot read running executable")
	}
	absolute, err := filepath.Abs(*dir)
	if err != nil {
		return errors.New("invalid installation directory")
	}
	if err := installExecutable(absolute, content, *replace); err != nil {
		return err
	}
	fmt.Fprintln(a.Out, "Installed:", filepath.Join(absolute, "wkb"))
	fmt.Fprintln(a.Out, "Keep this directory on your PATH. Next: wkb init, then wkb ui.")
	return nil
}

func installExecutable(dir string, content []byte, replace bool) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errors.New("cannot create installation directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return errors.New("cannot open installation directory")
	}
	defer root.Close()
	if info, err := root.Lstat("wkb"); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("existing wkb must be a regular file; links are preserved")
		}
		f, err := root.OpenFile("wkb", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return errors.New("cannot inspect existing wkb")
		}
		b, readErr := io.ReadAll(io.LimitReader(f, int64(len(content)+1)))
		f.Close()
		if readErr != nil {
			return errors.New("cannot read existing wkb")
		}
		if bytes.Equal(b, content) && info.Mode().Perm()&0100 != 0 {
			return nil
		}
		if !replace {
			return errors.New("wkb already exists; use --replace to authorize an update")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect installation destination")
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return errors.New("cannot generate installer filename")
	}
	temporary := ".wkb-" + hex.EncodeToString(id)
	f, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0700)
	if err != nil {
		return errors.New("cannot create executable update")
	}
	defer root.Remove(temporary)
	_, err = f.Write(content)
	if err == nil {
		err = f.Chmod(0755)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("cannot write executable update")
	}
	if replace {
		err = root.Rename(temporary, "wkb")
	} else {
		err = root.Link(temporary, "wkb")
	}
	if err != nil {
		return errors.New("cannot install wkb; destination may have changed")
	}
	d, err := root.Open(".")
	if err != nil {
		return errors.New("wkb installed but directory sync failed")
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return errors.New("wkb installed but directory sync failed")
	}
	return nil
}
