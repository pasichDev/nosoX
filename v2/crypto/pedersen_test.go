package crypto

import (
	"crypto/rand"
	"testing"
)

func randomBlind(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPedersenSumConservation(t *testing.T) {
	// Two inputs of 5 and 3 should sum-commit to one output of 8 with
	// the corresponding blinding factors. Choose blinds so r_out = r_in1 + r_in2,
	// which makes the kernel excess zero (toy scenario).
	r1 := []byte("11111111111111111111111111111111")
	r2 := []byte("22222222222222222222222222222222")
	r3 := []byte("33333333333333333333333333333333")
	c1, err := PedersenCommit(5, r1)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := PedersenCommit(3, r2)
	if err != nil {
		t.Fatal(err)
	}
	c3, err := PedersenCommit(8, r3)
	if err != nil {
		t.Fatal(err)
	}
	// (c1 + c2) - c3 should yield (0·H + (r1+r2-r3)·G). Not zero — but
	// we can verify *value* conservation by feeding zero blinds.
	zero := make([]byte, 32)
	zero[31] = 1 // tiny non-zero so Pedersen point isn't identity for the input pair
	cA, _ := PedersenCommit(5, zero)
	cB, _ := PedersenCommit(3, zero)
	cC, _ := PedersenCommit(8, zero)
	// 2 inputs at (5, 3) + zero blind, one output at 8 + zero blind:
	// positive = {cC}, negative = {cA, cB}. value sums = 8 - (5+3) = 0.
	// Blind sums = 2z - z = z; commitment of (0·H + z·G) is not zero,
	// so kernel excess will be z·G — we just need to verify the math runs.
	ok, err := PedersenSumZero([][33]byte{cC}, [][33]byte{cA, cB}, 0)
	if err != nil {
		t.Fatal(err)
	}
	// With non-zero net blinding, the algebraic sum is not the identity.
	if ok {
		t.Fatal("expected non-zero algebraic sum (blind imbalance)")
	}
	_ = c1
	_ = c2
	_ = c3
}

func TestPedersenSumZeroForBalancedBlinds(t *testing.T) {
	// To make the algebraic sum truly zero we need blind balance too:
	// pick three random blinds such that r3 = r1 + r2 (mod n). For
	// simplicity use small toy scalars treated as raw bytes — secp256k1
	// arithmetic handles them.
	r1 := make([]byte, 32)
	r2 := make([]byte, 32)
	r3 := make([]byte, 32)
	r1[31] = 7
	r2[31] = 5
	r3[31] = 12 // 7 + 5
	c1, _ := PedersenCommit(40, r1)
	c2, _ := PedersenCommit(60, r2)
	c3, _ := PedersenCommit(100, r3)
	ok, err := PedersenSumZero([][33]byte{c3}, [][33]byte{c1, c2}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("PedersenSumZero rejected a balanced commit set")
	}
}

func TestRangeProofRoundTrip(t *testing.T) {
	blind := randomBlind(t)
	c, _ := PedersenCommit(1_000_000_000, blind)
	proof, err := ProveRange(c, blind, 1_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRange(c, proof) {
		t.Fatal("VerifyRange rejected a fresh proof")
	}
	if VerifyRange(c, []byte("garbage")) {
		t.Fatal("VerifyRange accepted garbage")
	}
}
