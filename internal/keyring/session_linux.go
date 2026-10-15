//go:build linux

package keyring

import (
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

const sessionPrefix = "workbench:"

// Possessor: all. Same user: view, read and search. Terminals and agents often
// hold different session keyrings, so possession alone would not reach the key.
const sessionPermissions = 0x3f0b0000

func (Session) Get(account string) (string, error) {
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, "user", sessionPrefix+account, 0)
	if err != nil {
		return "", ErrLocked
	}
	b := make([]byte, 256)
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, b, 0)
	if err != nil || n > len(b) {
		return "", ErrLocked
	}
	return string(b[:n]), nil
}

// Put prepares the key in the process keyring and links it into the user
// keyring only after its expiry is set, so a crash cannot leave it without one.
func (Session) Put(account, identity string, ttl time.Duration) error {
	failed := errors.New("cannot unlock: kernel keyring unavailable")
	id, err := unix.AddKey("user", sessionPrefix+account, []byte(identity), unix.KEY_SPEC_PROCESS_KEYRING)
	if err != nil {
		return failed
	}
	defer unix.KeyctlInt(unix.KEYCTL_UNLINK, id, unix.KEY_SPEC_PROCESS_KEYRING, 0, 0)
	if err := unix.KeyctlSetperm(id, sessionPermissions); err != nil {
		return failed
	}
	if _, err := unix.KeyctlInt(unix.KEYCTL_SET_TIMEOUT, id, int(ttl/time.Second), 0, 0); err != nil {
		return failed
	}
	if _, err := unix.KeyctlInt(unix.KEYCTL_LINK, id, unix.KEY_SPEC_USER_KEYRING, 0, 0); err != nil {
		return failed
	}
	return nil
}

func (Session) Delete(account string) error {
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, "user", sessionPrefix+account, 0)
	if errors.Is(err, unix.ENOKEY) || errors.Is(err, unix.EKEYEXPIRED) || errors.Is(err, unix.EKEYREVOKED) {
		return nil
	}
	if err != nil {
		return errors.New("cannot lock: kernel keyring unavailable")
	}
	if _, err := unix.KeyctlInt(unix.KEYCTL_INVALIDATE, id, 0, 0, 0); err != nil {
		return errors.New("cannot lock: kernel keyring refused invalidation")
	}
	return nil
}
