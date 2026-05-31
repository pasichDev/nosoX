package crypto

import (
	"crypto/rand"
	"testing"
)

func TestSchnorrRoundTrip(t *testing.T) {
	var x [32]byte
	if _, err := rand.Read(x[:]); err != nil {
		t.Fatal(err)
	}
	x[0] &= 0x7f // ensure < curve order with high probability
	pub, err := PublicFromScalar(x[:])
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello noso")
	sig, err := SchnorrSign(x[:], msg)
	if err != nil {
		t.Fatal(err)
	}
	if !SchnorrVerify(pub, msg, sig) {
		t.Fatal("good signature failed to verify")
	}
	if SchnorrVerify(pub, []byte("tampered"), sig) {
		t.Fatal("tampered message verified")
	}
	// Different key should reject.
	var x2 [32]byte
	rand.Read(x2[:])
	x2[0] &= 0x7f
	pub2, _ := PublicFromScalar(x2[:])
	if SchnorrVerify(pub2, msg, sig) {
		t.Fatal("wrong-key verification succeeded")
	}
}
