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
	copy(want[:], decode("03338976778e63819ae0e18d42d3984dd81c267d09030a266031f284d920b0b0ee"))
	one := make([]byte, 32)
	one[31] = 1
	got, err := PedersenCommit(42, one)
	if err != nil || got != want {
		t.Fatalf("commit vector mismatch: %x %v", got, err)
	}
	if hex.EncodeToString(generatorH.SerializeCompressed()) != "0258d7c1aa50aee458408300fc0b1c1ec476be981c6f7ff8bfebb9525e6043985a" {
		t.Fatal("H generator vector mismatch")
	}
	sig := decode("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee54abc93aea886db9cdb710dd6fd1d42db9badea49a182ef37ceba5ba4bc550769")
	msg := []byte("NosoX independent arithmetic vector")
	if !SchnorrVerify(pub, msg, sig) {
		t.Fatal("independent signature vector rejected")
	}
	sig[64] ^= 1
	if SchnorrVerify(pub, msg, sig) {
		t.Fatal("modified independent vector accepted")
	}
}
