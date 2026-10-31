package crypto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// FuzzVerifyRangeBorromean checks that the verifier handles any byte
// payload without panicking. A crash here would let a malicious miner
// brick verifying nodes via crafted range proofs.
func FuzzVerifyRangeBorromean(f *testing.F) {
	// Fixed public seed bytes are retained so the initial corpus is reproducible.
	rawSeed, err := os.ReadFile("testdata/range_v5.json")
	if err != nil {
		f.Fatal(err)
	}
	var seed struct {
		Commit [33]byte
		Proof  []byte
	}
	if err = json.Unmarshal(rawSeed, &seed); err != nil {
		f.Fatal(err)
	}
	c := seed.Commit
	if !VerifyRangeBorromean(c, seed.Proof) {
		f.Fatal("invalid public proof seed")
	}
	f.Add(c[:], seed.Proof)
	f.Add(c[:], []byte{})
	f.Add(c[:], []byte{2})
	f.Fuzz(func(t *testing.T, commitBytes, raw []byte) {
		var commit [33]byte
		copy(commit[:], commitBytes)
		// VerifyRange must return false (never panic) on garbage.
		_ = VerifyRangeBorromean(commit, raw)
	})
}

// FuzzSchnorrVerify is the matching harness for Schnorr signatures.
func FuzzSchnorrVerify(f *testing.F) {
	rawSeed, err := os.ReadFile("testdata/arithmetic_v5.json")
	if err != nil {
		f.Fatal(err)
	}
	var seed struct {
		Public    string
		Message   string
		Signature string
	}
	if err = json.Unmarshal(rawSeed, &seed); err != nil {
		f.Fatal(err)
	}
	pub, err := hex.DecodeString(seed.Public)
	if err != nil {
		f.Fatal(err)
	}
	sig, err := hex.DecodeString(seed.Signature)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(pub, []byte(seed.Message), sig)
	f.Add([]byte{}, []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, pubBytes, msg, sig []byte) {
		var p [33]byte
		if len(pubBytes) >= 33 {
			copy(p[:], pubBytes[:33])
		} else {
			copy(p[:], pubBytes)
		}
		_ = SchnorrVerify(p, msg, sig)
	})
}
