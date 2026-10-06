package vault

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func private(info os.FileInfo, dir bool) error {
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != dir || (!dir && !info.Mode().IsRegular()) {
		return errors.New("vault paths must be real directories and regular files, not links")
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("vault files must be 0600 and directories 0700")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return errors.New("vault paths must belong to the current user")
	}
	return nil
}

func openDirectory(dir string, create bool) (*os.Root, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, errors.New("invalid vault directory")
	}
	if create {
		if err := os.MkdirAll(filepath.Dir(absolute), 0700); err != nil {
			return nil, errors.New("cannot create vault parent")
		}
	}
	parent, err := os.Stat(filepath.Dir(absolute))
	if err != nil {
		return nil, errors.New("vault parent not found; run workbench init")
	}
	if parent.Mode().Perm()&0022 != 0 {
		return nil, errors.New("vault parent must not be writable by other users")
	}
	if create {
		if err := os.Mkdir(absolute, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, errors.New("cannot create vault directory")
		}
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, errors.New("vault not initialized; run workbench init")
	}
	if err := private(info, true); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, errors.New("cannot open vault directory")
	}
	opened, err := root.FS().Open(".")
	if err != nil {
		root.Close()
		return nil, errors.New("cannot inspect vault directory")
	}
	info, err = opened.Stat()
	opened.Close()
	if err != nil {
		root.Close()
		return nil, errors.New("cannot inspect vault directory")
	}
	if err := private(info, true); err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

func readPrivate(root *os.Root, name string) ([]byte, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s", name)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("cannot inspect vault file")
	}
	if err := private(info, false); err != nil {
		return nil, err
	}
	if info.Size() > MaxBlob {
		return nil, errors.New("vault file is too large")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxBlob+1))
	if err != nil || len(b) > MaxBlob {
		return nil, errors.New("cannot read vault file")
	}
	return b, nil
}

func writeAtomic(root *os.Root, name string, b []byte) error {
	if len(b) > MaxBlob {
		return errors.New("vault is too large")
	}
	if info, err := root.Lstat(name); err == nil {
		if err := private(info, false); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect destination")
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return errors.New("cannot generate temporary filename")
	}
	temporary := ".tmp-" + hex.EncodeToString(id)
	f, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("cannot create encrypted update")
	}
	defer root.Remove(temporary)
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("cannot save encrypted update")
	}
	if err := root.Rename(temporary, name); err != nil {
		return errors.New("cannot commit encrypted update")
	}
	d, err := root.Open(".")
	if err != nil {
		return errors.New("update committed but directory sync failed")
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return errors.New("update committed but directory sync failed")
	}
	return nil
}

func lock(root *os.Root) (func(), error) {
	f, err := root.OpenFile(".lock", os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errors.New("cannot open vault lock")
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, errors.New("cannot inspect vault lock")
	}
	if err := private(info, false); err != nil {
		f.Close()
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if (err != unix.EWOULDBLOCK && err != unix.EAGAIN) || time.Now().After(deadline) {
			f.Close()
			return nil, errors.New("vault is busy or cannot be locked")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, nil
}

// ReadInput never follows a final symlink or waits on a FIFO. Private is required
// for plaintext secrets; encrypted shares can be readable by other users.
func ReadInput(path string, requirePrivate bool) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open input file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	if requirePrivate {
		if err := private(info, false); err != nil {
			return nil, err
		}
	}
	if info.Size() > MaxBlob {
		return nil, errors.New("input is too large")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxBlob+1))
	if err != nil || len(b) > MaxBlob {
		return nil, errors.New("cannot read input")
	}
	return b, nil
}

// WriteOutput refuses to replace an existing file, even a dangling symlink.
func WriteOutput(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("output already exists or cannot be created")
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.New("cannot write output")
	}
	return nil
}
