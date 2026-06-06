package types

import (
	"crypto/ed25519"
	"encoding/hex"
)

// Transparent dev fund.
//
// NosoX has NO premine and NO hidden allocation. Development is funded only by
// an OPEN, on-chain message fee (see the messenger protocol): every paid
// message routes its fixed fee to the single dev address below. The address is
// a hard-coded, immutable protocol constant so the fee destination cannot be
// silently redirected — and it is fully public so anyone can audit every coin
// that ever reaches it on-chain.
//
// The matching private key is the project's; it is NOT in this repository.
// There is nothing secret about the *address* — only the spending key is held
// off-repo. This is the opposite of a hidden dev wallet: it is a published,
// verifiable recipient.
const (
	// DevFundPubKeyHex is the Ed25519 public key (32 bytes, hex) that receives
	// transparent message fees. Genesis allocation to it is ZERO.
	DevFundPubKeyHex = "099f0f0f049e8368209a50d6d0eddd336fee0faa89692da156b50fdcc9470a97"

	// DevFundGenesisAllocation is the coins minted to the dev fund at block 0.
	// ZERO by design — the dev fund is fee-funded only, never premined.
	DevFundGenesisAllocation int64 = 0
)

// DevFundPubKey returns the dev-fund recipient public key. Panics at startup if
// the constant is malformed (a build-time invariant, caught by tests).
func DevFundPubKey() ed25519.PublicKey {
	b, err := hex.DecodeString(DevFundPubKeyHex)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("types: invalid DevFundPubKeyHex")
	}
	return ed25519.PublicKey(b)
}
