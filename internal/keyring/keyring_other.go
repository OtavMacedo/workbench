//go:build !darwin || !cgo

package keyring

func (System) Get(string) (string, error) { return "", ErrUnavailable }
func (System) Set(string, string) error   { return ErrUnavailable }
func (System) Delete(string) error        { return ErrUnavailable }
