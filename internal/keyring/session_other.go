//go:build !linux

package keyring

import (
	"errors"
	"time"
)

var errSessionUnavailable = errors.New("unlock is only available on Linux")

func (Session) Get(string) (string, error)              { return "", ErrLocked }
func (Session) Put(string, string, time.Duration) error { return errSessionUnavailable }
func (Session) Delete(string) error                     { return errSessionUnavailable }
