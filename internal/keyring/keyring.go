package keyring

import "errors"

var ErrUnavailable = errors.New("native keychain unavailable; use init --password")

type Backend interface {
	Get(account string) (string, error)
	Set(account, value string) error
	Delete(account string) error
}

type System struct{}
