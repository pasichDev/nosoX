package wallet

import (
	"crypto/rand"
	"path/filepath"
	"testing"
)

// TestCoinbaseEndToEnd: allocate a coinbase record (with a fresh random
// blinding factor inside the package), sign with SignCoinbase, verify
// with VerifyCoinbase. If pubFromCoinbase has the wrong zeroBlind, this
// will fail because the verifier reconstructs the wrong public key.
func TestCoinbaseEndToEnd(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenCoinbaseStore(filepath.Join(dir, "coinbases.json"))
	if err != nil {
		t.Fatal(err)
	}
	const height = uint64(12345)
	const amount = int64(5_000_000_000)

	rec, err := store.Allocate(height, amount)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	sig, err := SignCoinbase(rec)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !VerifyCoinbase(rec.Height, rec.Amount, rec.Commit, sig) {
		t.Fatal("VerifyCoinbase rejected a freshly signed coinbase")
	}
	// Tampering checks.
	tamperedSig := append([]byte(nil), sig...)
	tamperedSig[10] ^= 0xff
	if VerifyCoinbase(rec.Height, rec.Amount, rec.Commit, tamperedSig) {
		t.Error("VerifyCoinbase accepted a tampered signature")
	}
	if VerifyCoinbase(rec.Height+1, rec.Amount, rec.Commit, sig) {
		t.Error("VerifyCoinbase accepted a signature for a different height")
	}
	if VerifyCoinbase(rec.Height, rec.Amount-1, rec.Commit, sig) {
		t.Error("VerifyCoinbase accepted a signature for a different amount")
	}
}

func TestCoinbaseUnknownCommitRejected(t *testing.T) {
	// A random Schnorr signature against a random commit must not verify.
	var fakeSig [65]byte
	rand.Read(fakeSig[:])
	var fakeCommit [33]byte
	fakeCommit[0] = 0x02
	rand.Read(fakeCommit[1:])
	if VerifyCoinbase(1, 100, fakeCommit, fakeSig[:]) {
		t.Error("random sig + random commit verified")
	}
}
