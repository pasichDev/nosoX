// Package types defines the canonical on-chain data structures for
// Noso v2. The protocol is a Mimblewimble variant with legacy compat:
//
//   - Native outputs are Pedersen commitments + range proofs. The actual
//     amount is never revealed on chain.
//   - Legacy outputs (only at genesis) wrap an original Pascal Noso
//     account (address hash + balance). They are spendable by signing
//     with the original secp256k1 ECDSA key, after which they convert
//     into native commitments via the normal MW spend path.
//   - Kernels carry the public commitment excess, signature, fee, and
//     a feature flag. Cut-through eliminates intermediate
//     outputs/kernels over time.
//
// Serialization is canonical — a hash of the marshaled bytes is the
// identity. Always write fields in declaration order, big-endian
// integers (network byte order), length-prefixed byte slices.
package types

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// Hash is a 32-byte SHA-256 digest used as identity for blocks,
// transactions, kernels, and commitments.
type Hash [32]byte

// String returns lowercase hex.
func (h Hash) String() string {
	const hex = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range h {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}

// IsZero reports whether the hash is all zero.
func (h Hash) IsZero() bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}

// Commitment is a 33-byte compressed secp256k1 point representing a
// Pedersen commitment Cv = v·H + r·G (v = amount in base units, r =
// blinding factor). On chain the value is never revealed.
type Commitment [33]byte

// Output identifies the unspent output set entry.
type Output struct {
	Features OutputFeatures
	Commit   Commitment
	// RangeProof is omitted for COINBASE outputs (which still must be
	// validated against block reward) and for LEGACY outputs (which
	// carry an explicit amount). For PLAIN outputs it MUST be present.
	RangeProof []byte
	// Legacy-only fields. Populated when Features ∈ {Legacy, LegacyGVT}.
	LegacyAddress string // original Pascal "N…" address
	LegacyAmount  int64  // base units (8 decimals) — for GVTs equals GVTBaseValue
	// GVTNumber is populated only when Features == LegacyGVT. The number
	// is the original v1 GVT slot (00..99); it doubles as the
	// non-fungible identifier so that transfers preserve identity rather
	// than just value.
	GVTNumber uint8
}

// OutputFeatures enumerates output kinds.
type OutputFeatures uint8

const (
	// OutputFeaturesPlain is a normal Mimblewimble output: commitment +
	// range proof, no explicit amount.
	OutputFeaturesPlain OutputFeatures = 0
	// OutputFeaturesCoinbase marks a coinbase output (only one per block,
	// produced by the miner). Subject to a maturity lock of CoinbaseLock
	// blocks before it can be spent.
	OutputFeaturesCoinbase OutputFeatures = 1
	// OutputFeaturesLegacy marks an output carried forward from the v1
	// sumary.psk via the genesis bundler. It records an old-Noso
	// address + balance and is spendable only by signing with the
	// original secp256k1 ECDSA key. Once spent, the resulting outputs
	// are normal MW commitments and the legacy identity is dropped.
	OutputFeaturesLegacy OutputFeatures = 2
	// OutputFeaturesLegacyGVT marks one of the 100 governance tokens
	// inherited from v1 gvts.psk. Identity (the GVTNumber 00..99) is
	// preserved on transfer; on redeem the output spends for
	// GVTBaseValue base units (70 NOSO) into a regular MW commitment.
	// Spend requires the original v1 owner's secp256k1 signature, same
	// as legacy balance UTXOs.
	OutputFeaturesLegacyGVT OutputFeatures = 3
	// OutputFeaturesDevFund marks the per-block transparent dev-fund output:
	// a value-known commitment F·H + DevFundPoint where F is the block's total
	// kernel fee. At most one per block; only present when F > 0. See
	// devfund.go and docs/v2/DEVFUND.md.
	OutputFeaturesDevFund OutputFeatures = 4
)

// GVTBaseValue is the NOSO-equivalent value of one inherited v1 GVT
// at redeem time, in base units (8 decimals). Matches the v1
// `GVTBaseValue` constant in nosogvts.pas.
const GVTBaseValue int64 = 70_000_000_000

// Input references an output being spent.
type Input struct {
	Features OutputFeatures
	Commit   Commitment
	// LegacySig is present iff Features == OutputFeaturesLegacy. It is
	// the Base64 DER ECDSA signature produced by the original secp256k1
	// key over the canonical spend message:
	//
	//   sig_input = "NOSOX-LEGACY-SPEND " + legacy_address + " " + commit_hex + " " + block_height_str
	LegacySig    string
	LegacyAddr   string // copy of the legacy address that owned this output
	LegacyAmount int64  // explicit amount (so the kernel can verify balance)
}

// Kernel binds inputs and outputs together with a signature over the
// excess (sum-of-output-commits − sum-of-input-commits − fee·H). The
// signature proves the spender knew the blinding factors.
type Kernel struct {
	Features KernelFeatures
	Fee      uint64
	// LockHeight: kernel is invalid before this block height.
	// Coinbase kernels use this to encode maturity; plain kernels
	// usually set 0.
	LockHeight uint64
	// Excess is the commitment to the excess blinding factor.
	Excess Commitment
	// ExcessSig is a Schnorr-style signature over the kernel hash by
	// the secret key represented by Excess (when scaled by G).
	ExcessSig []byte
}

// KernelFeatures enumerates kernel variants.
type KernelFeatures uint8

const (
	KernelFeaturesPlain    KernelFeatures = 0
	KernelFeaturesCoinbase KernelFeatures = 1
	// KernelFeaturesLegacyClaim is used when a transaction's only role
	// is to spend a single legacy output into native outputs. Carries
	// no fee (the network forgives the dust to incentivize migration).
	KernelFeaturesLegacyClaim KernelFeatures = 2
)

// Transaction is the basic unit submitted to the mempool. Inputs and
// outputs must sum (commitment-wise) to the excess plus fee·H.
type Transaction struct {
	Inputs  []Input
	Outputs []Output
	Kernels []Kernel
}

// BlockHeader carries the chain metadata. Hash(header) is the block ID
// and what the PoW must brute-force a nonce against.
type BlockHeader struct {
	Version     uint32
	Height      uint64
	Timestamp   int64 // unix seconds
	PrevHash    Hash
	OutputRoot  Hash    // Merkle root of the post-block UTXO set
	KernelRoot  Hash    // Merkle root of all kernels in this block
	TotalKernelOffset Commitment // sum-of-all-kernel-offsets (proof aggregation)
	Difficulty  uint64  // target as: hash <= MaxTarget / Difficulty
	Nonce       uint64
}

// Block bundles a header with its transaction body. Coinbase output and
// kernel are included like any other.
type Block struct {
	Header     BlockHeader
	Inputs     []Input
	Outputs    []Output
	Kernels    []Kernel
}

// Genesis settings — defaults for the canonical Noso v2 launch.
// Forkers can override these via a config file before generating their
// own genesis.
const (
	NetworkMagicMainnet uint32 = 0x4e4f5832 // "NOX2"
	NetworkMagicTestnet uint32 = 0x4e4f5854 // "NOXT"

	BlockVersion uint32 = 1

	// TargetBlockTime is the desired interval between blocks.
	TargetBlockTimeSeconds int64 = 120

	// CoinbaseLock is the number of confirmations before a coinbase
	// output can be spent. Standard Bitcoin/Grin practice.
	CoinbaseLock uint64 = 60

	// LWMA-3 (Zawy) parameters.
	DifficultyWindow = 90

	// MinDifficulty is the floor — networks bootstrap from very low
	// difficulty and ramp up. 1 means "any non-zero hash works".
	MinDifficulty uint64 = 1

	// Base units per coin (8 decimals — same as v1 for continuity).
	CoinUnits int64 = 100_000_000

	// Reward schedule mirrors v1 for continuity.
	InitialReward        int64 = 5_000_000_000
	BlockHalvingInterval uint64 = 210_000
	HalvingSteps         uint64 = 10
)

// BlockReward returns the coinbase reward for a given block height.
// Halving schedule matches the v1 chain so total emission stays
// predictable for holders.
func BlockReward(height uint64) int64 {
	if height == 0 {
		// Genesis is special: no coinbase, only legacy outputs.
		return 0
	}
	if height >= BlockHalvingInterval*(HalvingSteps+1) {
		return 0
	}
	halvings := height / BlockHalvingInterval
	return InitialReward >> halvings
}

// EncodeHeader serializes a BlockHeader for hashing / PoW.
func EncodeHeader(h *BlockHeader) []byte {
	buf := make([]byte, 0, 4+8+8+32+32+32+33+8+8)
	buf = binary.BigEndian.AppendUint32(buf, h.Version)
	buf = binary.BigEndian.AppendUint64(buf, h.Height)
	buf = binary.BigEndian.AppendUint64(buf, uint64(h.Timestamp))
	buf = append(buf, h.PrevHash[:]...)
	buf = append(buf, h.OutputRoot[:]...)
	buf = append(buf, h.KernelRoot[:]...)
	buf = append(buf, h.TotalKernelOffset[:]...)
	buf = binary.BigEndian.AppendUint64(buf, h.Difficulty)
	buf = binary.BigEndian.AppendUint64(buf, h.Nonce)
	return buf
}

// HeaderID returns SHA-256 of the canonical encoding. This is the block
// hash advertised on the wire and stored in PrevHash links.
func HeaderID(h *BlockHeader) Hash {
	return sha256.Sum256(EncodeHeader(h))
}

// EncodeKernel returns the canonical kernel-hash preimage.
func EncodeKernel(k *Kernel) []byte {
	buf := make([]byte, 0, 1+8+8+33)
	buf = append(buf, byte(k.Features))
	buf = binary.BigEndian.AppendUint64(buf, k.Fee)
	buf = binary.BigEndian.AppendUint64(buf, k.LockHeight)
	buf = append(buf, k.Excess[:]...)
	return buf
}

// KernelID returns SHA-256 of the canonical encoding.
func KernelID(k *Kernel) Hash {
	return sha256.Sum256(EncodeKernel(k))
}

// EncodeOutput returns a canonical preimage for hashing.
func EncodeOutput(o *Output) []byte {
	buf := []byte{byte(o.Features)}
	buf = append(buf, o.Commit[:]...)
	if o.Features == OutputFeaturesLegacy || o.Features == OutputFeaturesLegacyGVT {
		buf = append(buf, []byte(o.LegacyAddress)...)
		buf = binary.BigEndian.AppendUint64(buf, uint64(o.LegacyAmount))
	}
	if o.Features == OutputFeaturesLegacyGVT {
		buf = append(buf, o.GVTNumber)
	}
	// RangeProof omitted from the identity hash so that aggregating
	// kernels (cut-through) can rewrite proofs without changing IDs.
	return buf
}

// OutputID returns SHA-256 of the canonical preimage.
func OutputID(o *Output) Hash {
	return sha256.Sum256(EncodeOutput(o))
}

// WriteVarBytes is a length-prefix helper used by the wire encoders.
// 4-byte length prefix is more than enough for any field we send.
func WriteVarBytes(w io.Writer, b []byte) error {
	if len(b) > 1<<24 {
		return fmt.Errorf("v2/types: oversize var-bytes (%d)", len(b))
	}
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(b)))
	if _, err := w.Write(lp[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// LegacySpendMessage returns the canonical bytes a legacy spender must
// sign with their original secp256k1 ECDSA key.
func LegacySpendMessage(legacyAddr string, commit Commitment, blockHeight uint64) []byte {
	msg := fmt.Sprintf("NOSOX-LEGACY-SPEND %s %x %d", legacyAddr, commit[:], blockHeight)
	return []byte(msg)
}
