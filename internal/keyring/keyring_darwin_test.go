//go:build darwin && cgo

package keyring

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
)

func TestNativeKeychainRoundTrip(t *testing.T) {
	if os.Getenv("WORKBENCH_TEST_KEYCHAIN") != "1" {
		t.Skip("opt-in integration test; uses only a temporary synthetic Keychain entry")
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	account := "test-" + hex.EncodeToString(b)
	r := System{}
	if err := r.Set(account, "SYNTHETIC-KEYCHAIN-TEST-ONLY"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Delete(account); err != nil {
			t.Error(err)
		}
	})
	v, err := r.Get(account)
	if err != nil {
		t.Fatal(err)
	}
	if v != "SYNTHETIC-KEYCHAIN-TEST-ONLY" {
		t.Fatal("native keychain round trip changed data")
	}
}
