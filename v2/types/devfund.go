package types

import "encoding/hex"

// Transparent dev fund.
//
// NosoX has NO premine and NO hidden allocation. Development is funded openly by
// NETWORK TRANSACTION FEES: the per-block total of kernel fees is paid to the
// single dev address below as a dedicated coinbase-class output, while the
// miner keeps the block subsidy.
//
// The dev address is a secp256k1 point P_dev = r_dev·G (the same curve the
// Pedersen commitments use). A block's dev-fund output for fee total F is the
// value-known commitment
//
//	C = F·H + P_dev
//
// which ANY validator can recompute and check from public data (F is the sum of
// public kernel fees, P_dev is this constant) — so the fee destination is
// immutable and fully auditable. Only the holder of the off-repo scalar r_dev
// can spend it. This is the opposite of a hidden dev wallet.
const (
	// DevFundPointHex is the 33-byte compressed secp256k1 point (hex) that
	// receives transparent per-block network fees. Spending scalar is held
	// off-repo (repo/noso/dev-wallet, gitignored).
	DevFundPointHex = "0364b94012c0a3484b9f0ed69088263fa47fb5258ec1ddb9186ebf0238b501323d"

	// DevFundGenesisAllocation is the coins minted to the dev fund at block 0.
	// ZERO by design — fee-funded only, never premined.
	DevFundGenesisAllocation int64 = 0
)

// DevFundPoint returns the dev-fund recipient point as a Commitment-sized array.
// Panics at startup if the constant is malformed (build-time invariant).
func DevFundPoint() Commitment {
	b, err := hex.DecodeString(DevFundPointHex)
	if err != nil || len(b) != 33 {
		panic("types: invalid DevFundPointHex")
	}
	var c Commitment
	copy(c[:], b)
	return c
}
