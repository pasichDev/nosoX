package crypto

import (
	"crypto/rand"
	"testing"
)

func TestBorromeanRangeProofRoundTrip(t *testing.T) {
	for _, value := range []int64{0, 1, 100, 1_000_000, 1_000_000_000, 1<<40 + 7} {
		var blind [32]byte
		if _, err := rand.Read(blind[:]); err != nil {
			t.Fatal(err)
		}
		c, err := PedersenCommit(value, blind[:])
		if err != nil {
			t.Fatal(err)
		}
		proof, err := ProveRangeBorromean(c, blind[:], value)
		if err != nil {
			t.Fatalf("prove (%d): %v", value, err)
		}
		if !VerifyRangeBorromean(c, proof) {
			t.Errorf("good proof rejected for value %d", value)
		}
	}
}

func TestBorromeanRangeProofRejectsTampering(t *testing.T) {
	value := int64(42)
	var blind [32]byte
	rand.Read(blind[:])
	c, _ := PedersenCommit(value, blind[:])
	proof, _ := ProveRangeBorromean(c, blind[:], value)
	// Flip a single byte deep inside the proof body.
	if len(proof) < 100 {
		t.Fatal("proof unexpectedly small")
	}
	tampered := append([]byte(nil), proof...)
	tampered[100] ^= 0x55
	if VerifyRangeBorromean(c, tampered) {
		t.Error("tampered proof accepted")
	}
}

func TestBorromeanRangeProofRejectsWrongCommit(t *testing.T) {
	value := int64(42)
	var blind [32]byte
	rand.Read(blind[:])
	c, _ := PedersenCommit(value, blind[:])
	proof, _ := ProveRangeBorromean(c, blind[:], value)

	var blind2 [32]byte
	rand.Read(blind2[:])
	c2, _ := PedersenCommit(value, blind2[:])

	if VerifyRangeBorromean(c2, proof) {
		t.Error("proof verified against unrelated commit")
	}
}

func TestRangeProofPublicAPI(t *testing.T) {
	var blind [32]byte
	rand.Read(blind[:])
	v := int64(1_000_000)
	c, _ := PedersenCommit(v, blind[:])
	proof, err := ProveRange(c, blind[:], v)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRange(c, proof) {
		t.Error("public ProveRange→VerifyRange round trip failed")
	}
}
