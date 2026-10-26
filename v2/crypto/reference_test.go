package crypto

import (
	"encoding/hex"
	"testing"
)

// Constants are produced by audit/reference_vectors.py, independent affine
// Python integer arithmetic. This is not a standard BIP340 vector or a proof
// of construction security. Scalars and nonce are public test-only constants.
func TestIndependentArithmeticVectors(t *testing.T) {
	decode := func(s string) []byte {
		t.Helper()
		b, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	var pub, want [33]byte
	copy(pub[:], decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
	copy(want[:], decode("03a4c11708fe5b25f6aae2d21ed0c6c423ab7790bd28db75aa30d5c972bf058c46"))
	one := make([]byte, 32)
	one[31] = 1
	got, err := PedersenCommit(42, one)
	if err != nil || got != want {
		t.Fatalf("commit vector mismatch: %x %v", got, err)
	}
	if hex.EncodeToString(generatorH.SerializeCompressed()) != "02f52ab971b6ddf928246252e335897fd9e1f03a8b21bca964bc1640a91d3e89d2" {
		t.Fatal("H generator vector mismatch")
	}
	sig := decode("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5b67da9a39287d190e9ec78297e43ff99ee2e4fac9f53713a8d8baa151ad24e30")
	msg := []byte("NosoX independent arithmetic vector")
	if !SchnorrVerify(pub, msg, sig) {
		t.Fatal("independent signature vector rejected")
	}
	sig[64] ^= 1
	if SchnorrVerify(pub, msg, sig) {
		t.Fatal("modified independent vector accepted")
	}
}
