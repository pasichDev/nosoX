package wallet

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSlatepackRoundTrip(t *testing.T) {
	s := NewOfferSlate(1_000_000_000, 1_000_000, 12340, "lunch")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s.SignPartial(RoleSender, priv)

	encoded, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if encoded == "" {
		t.Fatal("encoded slate empty")
	}

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Amount != s.Amount || decoded.Fee != s.Fee {
		t.Errorf("amount/fee mismatch: %+v vs %+v", decoded, s)
	}
	if !decoded.VerifyPartials() {
		t.Fatal("partial signature failed to verify after round-trip")
	}
}

func TestSlatepackBalancesEmptyTx(t *testing.T) {
	// A slate with no inputs/outputs and zero fee should satisfy the
	// balance check trivially.
	s := NewOfferSlate(0, 0, 0, "")
	if err := s.CheckBalance(); err != nil {
		t.Errorf("empty slate balance: %v", err)
	}
}
