package keyring

import (
	"errors"
	"time"
)

var ErrUnavailable = errors.New("native keychain unavailable; use init --password")
var ErrLocked = errors.New("vault is locked")

type Backend interface {
	Get(account string) (string, error)
	Set(account, value string) error
	Delete(account string) error
}

// Cache holds the identity of a passphrase vault after unlock, until its ttl expires.
type Cache interface {
	Get(account string) (string, error)
	Put(account, identity string, ttl time.Duration) error
	Delete(account string) error
}

type System struct{}

type Session struct{}
