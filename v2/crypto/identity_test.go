package crypto

import (
	"crypto/rand"
	"testing"
)

// TestPedersenZeroBlindingProducesValueH verifies that PedersenCommit with
// an all-zero blinding factor returns v·H (i.e. no G term contaminates it).
// This is the core invariant the coinbase verification depends on:
// commit_with_zero_blind(amount) == amount·H, so subtracting it from a
// real coinbase commit gives back r·G — the Schnorr public key.
func TestPedersenZeroBlindingProducesValueH(t *testing.T) {
	zero := make([]byte, 32) // all zero
	one := make([]byte, 32)
	one[31] = 1

	v := int64(1_000_000)
	c0, err := PedersenCommit(v, zero)
	if err != nil {
		t.Fatalf("PedersenCommit with zero blind: %v", err)
	}
	c1, err := PedersenCommit(v, one)
	if err != nil {
		t.Fatalf("PedersenCommit with blind=1: %v", err)
	}
	if c0 == c1 {
		t.Fatal("zero-blind commit equals one-blind commit — Pedersen broken")
	}
	// (c1 − c0) should decompress to G itself, because (v·H + 1·G) − v·H = G.
	g, err := PointSubtract(c1, c0)
	if err != nil {
		t.Fatalf("PointSubtract: %v", err)
	}
	// G is the curve base point. Encode it the same way the package does
	// internally by computing 1·G via ScalarBaseMult.
	gFromScalar, err := PublicFromScalar(one)
	if err != nil {
		t.Fatalf("PublicFromScalar: %v", err)
	}
	if g != gFromScalar {
		t.Fatalf("c1 - c0 != G: got %x want %x", g, gFromScalar)
	}
}

// TestCoinbaseSignVerifyRoundTrip catches the previous bug where zeroBlind
// used a non-zero scalar, causing the verifier to compute (r−1)·G instead
// of r·G and reject every coinbase. With the fix all should round-trip.
func TestCoinbaseSignVerifyRoundTrip(t *testing.T) {
	// Manually build a coinbase commit = r·G + amount·H.
	var r [32]byte
	if _, err := rand.Read(r[:]); err != nil {
		t.Fatal(err)
	}
	r[0] &= 0x7f // keep scalar safely below curve order
	amount := int64(5_000_000_000)

	commit, err := PedersenCommit(amount, r[:])
	if err != nil {
		t.Fatal(err)
	}

	// Recover pub = commit − amount·H, expecting r·G.
	amountCommit, err := PedersenCommit(amount, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PointSubtract(commit, amountCommit)
	if err != nil {
		t.Fatal(err)
	}
	rPub, err := PublicFromScalar(r[:])
	if err != nil {
		t.Fatal(err)
	}
	if pub != rPub {
		t.Fatalf("recovered pub differs from r·G:\n got  %x\n want %x", pub, rPub)
	}

	// Sign and verify a sample message.
	msg := []byte("coinbase test")
	sig, err := SchnorrSign(r[:], msg)
	if err != nil {
		t.Fatal(err)
	}
	if !SchnorrVerify(pub, msg, sig) {
		t.Fatal("Schnorr verification failed against recovered coinbase pub")
	}
}
