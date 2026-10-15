package testutil

import (
	"sync"
	"time"

	"github.com/pedroloch/workbench/internal/keyring"
)

// Session is an isolated fake. Tests never touch the real kernel keyring.
type Session struct {
	mu     sync.Mutex
	values map[string]string
	TTL    time.Duration
}

func (s *Session) Get(k string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[k]
	if !ok {
		return "", keyring.ErrLocked
	}
	return v, nil
}
func (s *Session) Put(k, v string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.values == nil {
		s.values = map[string]string{}
	}
	s.values[k], s.TTL = v, ttl
	return nil
}
func (s *Session) Delete(k string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, k)
	return nil
}
