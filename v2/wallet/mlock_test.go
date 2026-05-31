package wallet

import (
	"path/filepath"
	"testing"
)

func TestWalletCloseZeroizesMasterKey(t *testing.T) {
	w, err := NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	// Persist and reload to exercise the locked decryption path.
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")
	if err := w.Save(path, "secret"); err != nil {
		t.Fatal(err)
	}
	w2, err := Load(path, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if w2.Master == nil {
		t.Fatal("loaded wallet has nil master")
	}
	// Stash a reference to the underlying byte slice so we can verify
	// Close zeroizes it.
	backing := w2.Master
	w2.Close()
	for i, b := range backing {
		if b != 0 {
			t.Fatalf("byte %d of master not zeroed after Close: %02x", i, b)
		}
	}
	if w2.Master != nil {
		t.Error("Close did not nil out Master")
	}
}

func TestZeroizeAndLockBytes(t *testing.T) {
	b := []byte("supersecret")
	if err := LockBytes(b); err != nil {
		t.Logf("LockBytes returned %v (acceptable in restricted env)", err)
	}
	Zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zero", i)
		}
	}
	UnlockBytes(b)
}
