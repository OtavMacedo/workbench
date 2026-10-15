//go:build linux

package keyring

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func syntheticAccount(t *testing.T) string {
	t.Helper()
	if os.Getenv("WORKBENCH_TEST_KERNEL_KEYRING") != "1" {
		t.Skip("opt-in integration test; uses only a temporary synthetic kernel key")
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "test-" + hex.EncodeToString(b)
}

func TestKernelSessionRoundTripAcrossSessionKeyrings(t *testing.T) {
	account := syntheticAccount(t)
	s := Session{}
	if _, err := s.Get(account); !errors.Is(err, ErrLocked) {
		t.Fatal("missing key not reported as locked")
	}
	if err := s.Put(account, "SYNTHETIC-SESSION-TEST-ONLY", time.Minute); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Delete(account) })
	if v, err := s.Get(account); err != nil || v != "SYNTHETIC-SESSION-TEST-ONLY" {
		t.Fatal("kernel session round trip changed data")
	}
	// Another terminal or an agent usually runs under a different session keyring.
	result := make(chan error)
	go func() {
		runtime.LockOSThread() // the thread exits with its new session keyring
		if _, err := unix.KeyctlJoinSessionKeyring("workbench-test-" + account); err != nil {
			result <- err
			return
		}
		v, err := s.Get(account)
		if err == nil && v != "SYNTHETIC-SESSION-TEST-ONLY" {
			err = errors.New("changed data")
		}
		if err == nil {
			err = s.Delete(account)
		}
		result <- err
	}()
	if err := <-result; err != nil {
		t.Fatal("other session keyring cannot use or lock the key:", err)
	}
	if _, err := s.Get(account); !errors.Is(err, ErrLocked) {
		t.Fatal("lock from another session keyring kept the key")
	}
	if err := s.Delete(account); err != nil {
		t.Fatal("lock is not idempotent:", err)
	}
}

func TestKernelSessionExpires(t *testing.T) {
	account := syntheticAccount(t)
	s := Session{}
	if err := s.Put(account, "SYNTHETIC-SESSION-TEST-ONLY", time.Second); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Delete(account) })
	time.Sleep(2 * time.Second)
	if _, err := s.Get(account); !errors.Is(err, ErrLocked) {
		t.Fatal("expired key still unlocks")
	}
}
