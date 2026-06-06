package types

import "testing"

func TestDevFundPointValid(t *testing.T) {
	p := DevFundPoint() // panics if malformed
	if p[0] != 0x02 && p[0] != 0x03 {
		t.Fatalf("dev fund point not a compressed secp256k1 point (prefix 0x%02x)", p[0])
	}
}

func TestDevFundNoPremine(t *testing.T) {
	if DevFundGenesisAllocation != 0 {
		t.Fatalf("dev fund genesis allocation = %d, want 0 (fee-funded only, no premine)", DevFundGenesisAllocation)
	}
}
