package wallet

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

const testMagic = uint32(0x4e4f5854)

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
	sig, err := SignCoinbase(testMagic, rec)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !VerifyCoinbase(testMagic, rec.Height, rec.Amount, rec.Commit, sig) {
		t.Fatal("VerifyCoinbase rejected a freshly signed coinbase")
	}
	// Tampering checks.
	tamperedSig := append([]byte(nil), sig...)
	tamperedSig[10] ^= 0xff
	if VerifyCoinbase(testMagic, rec.Height, rec.Amount, rec.Commit, tamperedSig) {
		t.Error("VerifyCoinbase accepted a tampered signature")
	}
	if VerifyCoinbase(testMagic, rec.Height+1, rec.Amount, rec.Commit, sig) {
		t.Error("VerifyCoinbase accepted a signature for a different height")
	}
	if VerifyCoinbase(testMagic, rec.Height, rec.Amount-1, rec.Commit, sig) {
		t.Error("VerifyCoinbase accepted a signature for a different amount")
	}
	// A signature made for one network must not verify on another.
	if VerifyCoinbase(testMagic+1, rec.Height, rec.Amount, rec.Commit, sig) {
		t.Error("VerifyCoinbase accepted a signature replayed on another network")
	}
}

func TestCoinbaseUnknownCommitRejected(t *testing.T) {
	// A random Schnorr signature against a random commit must not verify.
	var fakeSig [65]byte
	rand.Read(fakeSig[:])
	var fakeCommit [33]byte
	fakeCommit[0] = 0x02
	rand.Read(fakeCommit[1:])
	if VerifyCoinbase(testMagic, 1, 100, fakeCommit, fakeSig[:]) {
		t.Error("random sig + random commit verified")
	}
}

// A rotated (archived) coinbase file holds real reward keys. import-coinbase
// must read it along with the live file, and must work when the live file is
// missing (the miner crashed right after rotating).
func TestImportCoinbaseReadsArchivedRotations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "coinbases.json")
	cs, err := OpenCoinbaseStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for h := uint64(1); h <= 3; h++ {
		if _, err := cs.Allocate(h, 100); err != nil {
			t.Fatal(err)
		}
	}
	cs.mu.Lock()
	err = cs.rotateLocked()
	cs.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// live file is gone right after a rotation
	st := newWalletStore(t, "w")
	rep, err := st.ImportCoinbase(path)
	if err != nil || rep.Imported != 3 || rep.Files != 1 {
		t.Fatalf("archive-only import: %+v %v", rep, err)
	}
	for h := uint64(4); h <= 5; h++ {
		if _, err := cs.Allocate(h, 100); err != nil {
			t.Fatal(err)
		}
	}
	// A look-alike that is not an archive must be ignored.
	if err := os.WriteFile(path+".bak", []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err = st.ImportCoinbase(path)
	if err != nil || rep.Imported != 2 || rep.Duplicate != 3 || rep.Files != 2 {
		t.Fatalf("live + archive import: %+v %v", rep, err)
	}
	if _, err := st.ImportCoinbase(filepath.Join(dir, "nothing.json")); err == nil {
		t.Fatal("import of a missing file with no archives must fail")
	}
}
