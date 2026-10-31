package crypto

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
)

// TestRegenerateRangeSeed rewrites testdata/range_v5.json, the public seed
// proof of the range-proof fuzz corpus. It depends on the Pedersen H
// generator, so regenerate it whenever a domain tag changes:
//
//	NOSOX_REGEN_TESTDATA=1 go test ./v2/crypto -run TestRegenerateRangeSeed
//
// testdata/arithmetic_v5.json is the output of audit/reference_vectors.py.
func TestRegenerateRangeSeed(t *testing.T) {
	if os.Getenv("NOSOX_REGEN_TESTDATA") != "1" {
		t.Skip("set NOSOX_REGEN_TESTDATA=1 to rewrite testdata/range_v5.json")
	}
	blind := sha256.Sum256([]byte("NosoX public range-proof fuzz seed"))
	commit, err := PedersenCommit(12345, blind[:])
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ProveRangeBorromean(commit, blind[:], 12345)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRangeBorromean(commit, proof) {
		t.Fatal("fresh proof does not verify")
	}
	raw, err := json.Marshal(struct {
		Commit [33]byte
		Proof  []byte
	}{commit, proof})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("testdata/range_v5.json", raw, 0o644); err != nil {
		t.Fatal(err)
	}
}
