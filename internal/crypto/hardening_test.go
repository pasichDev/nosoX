package crypto

import (
	"encoding/base64"
	"testing"
)

func TestLegacyPrivateScalarBounds(t *testing.T) {
	for _, raw := range [][]byte{make([]byte, 32), {1}, make([]byte, 33)} {
		if _, err := ParsePrivateKey(base64.StdEncoding.EncodeToString(raw)); err == nil {
			t.Fatalf("accepted scalar length %d", len(raw))
		}
	}
}
func TestLegacyDERStrict(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignString([]byte("x"), kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(sig)
	if VerifyString([]byte("x"), base64.StdEncoding.EncodeToString(append(raw, 0)), kp.PublicKey) {
		t.Fatal("accepted trailing DER bytes")
	}
}
