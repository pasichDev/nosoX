package crypto

import (
	"crypto/rand"
	"testing"
)

// TestSchnorrCTVerifiesUnderExistingVerifier confirms that signatures
// from the constant-time implementation verify under the existing
// (variable-time) SchnorrVerify. This is the cross-validation that
// proves the CT path produces wire-identical output.
func TestSchnorrCTVerifiesUnderExistingVerifier(t *testing.T) {
	for trial := 0; trial < 8; trial++ {
		var x [32]byte
		if _, err := rand.Read(x[:]); err != nil {
			t.Fatal(err)
		}
		x[0] &= 0x7f // safely below curve order
		pub, err := PublicFromScalar(x[:])
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("Noso constant-time Schnorr cross-test")

		sig, err := SchnorrSignConstantTime(x[:], msg)
		if err != nil {
			t.Fatalf("CT sign: %v", err)
		}
		if !SchnorrVerify(pub, msg, sig) {
			t.Fatalf("CT signature did not verify under standard verifier (trial %d)", trial)
		}
	}
}

func TestSchnorrCTRejectsZeroScalar(t *testing.T) {
	var x [32]byte // all zeros
	_, err := SchnorrSignConstantTime(x[:], []byte("msg"))
	if err == nil {
		t.Fatal("zero scalar should be rejected")
	}
}

func TestSchnorrCTRejectsBadLength(t *testing.T) {
	_, err := SchnorrSignConstantTime(make([]byte, 31), []byte("msg"))
	if err == nil {
		t.Fatal("31-byte scalar should be rejected")
	}
}
