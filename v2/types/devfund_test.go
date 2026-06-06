package types

import (
	"crypto/ed25519"
	"testing"
)

func TestDevFundPubKeyValid(t *testing.T) {
	pk := DevFundPubKey() // panics if malformed
	if len(pk) != ed25519.PublicKeySize {
		t.Fatalf("dev fund pubkey size = %d, want %d", len(pk), ed25519.PublicKeySize)
	}
}

func TestDevFundNoPremine(t *testing.T) {
	if DevFundGenesisAllocation != 0 {
		t.Fatalf("dev fund genesis allocation = %d, want 0 (fee-funded only, no premine)", DevFundGenesisAllocation)
	}
}
