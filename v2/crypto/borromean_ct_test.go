package crypto

import (
	"crypto/rand"
	"testing"
)

// TestBorromeanCTVerifiesUnderExistingVerifier proves wire compatibility:
// proofs produced by the constant-time prover MUST verify under the
// variable-time verifier. If this passes, switching ProveRange to the
// CT path is a transparent upgrade for every existing caller.
func TestBorromeanCTVerifiesUnderExistingVerifier(t *testing.T) {
	for _, value := range []int64{0, 1, 100, 1_000_000, 1_000_000_000, 1<<40 + 7} {
		var blind [32]byte
		if _, err := rand.Read(blind[:]); err != nil {
			t.Fatal(err)
		}
		c, err := PedersenCommit(value, blind[:])
		if err != nil {
			t.Fatal(err)
		}
		proof, err := ProveRangeBorromeanCT(c, blind[:], value)
		if err != nil {
			t.Fatalf("CT prove (v=%d): %v", value, err)
		}
		if !VerifyRangeBorromean(c, proof) {
			t.Errorf("CT proof for value %d did not verify", value)
		}
	}
}

func TestBorromeanCTRejectsNegativeValue(t *testing.T) {
	var blind [32]byte
	rand.Read(blind[:])
	c, _ := PedersenCommit(0, blind[:])
	if _, err := ProveRangeBorromeanCT(c, blind[:], -1); err == nil {
		t.Fatal("negative value should be rejected")
	}
}

func TestBorromeanCTRejectsBadBlindingLength(t *testing.T) {
	var c [33]byte
	if _, err := ProveRangeBorromeanCT(c, make([]byte, 31), 1); err == nil {
		t.Fatal("31-byte blinding should be rejected")
	}
}

// TestBorromeanCTTamperingRejected: the CT prover's output is just as
// resistant to bit-flip tampering as the variable-time one.
func TestBorromeanCTTamperingRejected(t *testing.T) {
	var blind [32]byte
	rand.Read(blind[:])
	value := int64(123_456_789)
	c, _ := PedersenCommit(value, blind[:])
	proof, err := ProveRangeBorromeanCT(c, blind[:], value)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), proof...)
	tampered[200] ^= 0xff
	if VerifyRangeBorromean(c, tampered) {
		t.Error("verifier accepted a tampered CT proof")
	}
}
