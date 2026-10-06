package testutil

import (
	"errors"
	"sync"
)

// Ring is an isolated fake. Tests never read the user's real Keychain.
type Ring struct {
	mu     sync.Mutex
	values map[string]string
}

func (r *Ring) Set(k, v string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.values == nil {
		r.values = map[string]string{}
	}
	if _, exists := r.values[k]; exists {
		return errors.New("already exists")
	}
	r.values[k] = v
	return nil
}
func (r *Ring) Get(k string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.values[k]
	if !ok {
		return "", errors.New("missing identity")
	}
	return v, nil
}
func (r *Ring) Delete(k string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.values, k)
	return nil
}
