package crypto

import (
	"math/big"
	"testing"
)

func TestRejectShapeOnlyRangeProof(t *testing.T) {
	one := make([]byte, 32)
	one[31] = 1
	c, _ := PedersenCommit(5, one)
	proof := make([]byte, 33)
	proof[0] = 1
	if VerifyRange(c, proof) {
		t.Fatal("accepted arbitrary proof shape without a range witness")
	}
}
func TestRejectIdentityPublicKeyForgery(t *testing.T) {
	one := make([]byte, 32)
	one[31] = 1
	R, _ := PublicFromScalar(one)
	sig := append(append([]byte{}, R[:]...), one...)
	if SchnorrVerify([33]byte{}, []byte("forged"), sig) {
		t.Fatal("identity key permits universal forgery")
	}
}
func TestRejectNoncanonicalPointAndScalar(t *testing.T) {
	var malformed [33]byte
	malformed[32] = 1
	if _, _, err := decompress(malformed); err == nil {
		t.Error("accepted noncanonical identity")
	}
	var p [33]byte
	p[0] = 2
	Curve().Params().P.FillBytes(p[1:])
	if _, _, err := decompress(p); err == nil {
		t.Error("accepted field coordinate >= p")
	}
	for _, x := range [][]byte{make([]byte, 32), Curve().Params().N.FillBytes(make([]byte, 32)), new(big.Int).Add(Curve().Params().N, big.NewInt(1)).FillBytes(make([]byte, 32))} {
		if _, err := PublicFromScalar(x); err == nil {
			t.Error("accepted zero or noncanonical public scalar")
		}
	}
	if _, err := PedersenCommit(1, Curve().Params().N.FillBytes(make([]byte, 32))); err == nil {
		t.Error("accepted noncanonical commitment scalar")
	}
	if _, err := PedersenSumZero(nil, nil, -1); err == nil {
		t.Error("accepted negative fee")
	}
}
func TestPointCancellationCanonicalIdentity(t *testing.T) {
	one := make([]byte, 32)
	one[31] = 1
	g, _ := PublicFromScalar(one)
	if _, err := PointSubtract(g, g); err == nil {
		t.Fatal("point subtraction returned identity as a public point")
	}
	c, _ := PedersenCommit(0, make([]byte, 32))
	if c != ([33]byte{}) {
		t.Fatal("noncanonical zero commitment")
	}
}

func TestORProofRejectsNoncanonicalResponseAndChallenge(t *testing.T) {
	// C=G with witness r=1. Simulate branch 1 using e1=0,s1=1,T1=G;
	// branch 0 uses k=1. Replacing e1 by n preserves the old modular
	// verification equations, but is a second encoding of the same proof.
	one := make([]byte, 32)
	one[31] = 1
	g, _ := PublicFromScalar(one)
	e0 := orChallenge(g, g, g)
	e0.Mod(e0, Curve().Params().N)
	s0 := new(big.Int).Add(e0, big.NewInt(1))
	s0.Mod(s0, Curve().Params().N)
	proof := append(append([]byte{}, g[:]...), g[:]...)
	proof = append(proof, padScalar(e0)...)
	proof = append(proof, make([]byte, 32)...)
	proof = append(proof, padScalar(s0)...)
	proof = append(proof, one...)
	if !bitOrVerify(g, proof) {
		t.Fatal("valid OR control rejected")
	}
	Curve().Params().N.FillBytes(proof[98:130])
	if bitOrVerify(g, proof) {
		t.Fatal("accepted challenge equal to n")
	}
}
func TestRangeProofOpeningAndEncodingBounds(t *testing.T) {
	one := make([]byte, 32)
	one[31] = 1
	c, _ := PedersenCommit(9, one)
	if _, err := ProveRange(c, one, 10); err == nil {
		t.Fatal("proved inconsistent opening")
	}
	proof, err := ProveRange(c, one, 9)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRange(c, proof) {
		t.Fatal("valid proof rejected")
	}
	wrong, _ := PedersenCommit(10, one)
	if VerifyRange(wrong, proof) {
		t.Fatal("proof not bound to commitment")
	}
	for _, bad := range [][]byte{proof[:len(proof)-1], append(append([]byte{}, proof...), 0), make([]byte, 1+rangeBits*(33+orProofSize))} {
		if VerifyRange(c, bad) {
			t.Fatal("malformed proof accepted")
		}
	}
	for _, offset := range []int{1, 1 + rangeBits*33, 1 + rangeBits*33 + 66} {
		bad := append([]byte{}, proof...)
		bad[offset] ^= 0xff
		if VerifyRange(c, bad) {
			t.Fatalf("mutation at %d accepted", offset)
		}
	}
}
