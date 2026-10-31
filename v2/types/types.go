// Package types defines the canonical on-chain data structures for
// NosoX. The protocol is a Mimblewimble variant:
//
//   - Outputs are Pedersen commitments + range proofs. The actual
//     amount is never revealed on chain.
//   - Kernels carry the public commitment excess, signature, fee, and
//     a feature flag. There is no cut-through: every kernel and output
//     stays in its block.
//
// Serialization is canonical — a hash of the marshaled bytes is the
// identity. Always write fields in declaration order, big-endian
// integers (network byte order), length-prefixed byte slices.
package types

import (
	"crypto/sha256"
	"encoding/binary"
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
	// RangeProof is omitted for COINBASE outputs, whose value is fixed by
	// consensus (block reward plus the block's kernel fees). For PLAIN outputs it
	// MUST be present.
	RangeProof []byte
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
	// Value 2 is deliberately unassigned. An earlier draft used it for a
	// dev-fund output; that output was removed before launch and the number is
	// not reused, so any output or input carrying feature 2 is rejected.
)

// Input references an output being spent.
type Input struct {
	Features OutputFeatures
	Commit   Commitment
}

// Kernel binds inputs and outputs together with a signature over the
// excess (sum-of-output-commits − sum-of-input-commits + fee·H, which equals
// the excess point of a balanced transaction). The signature proves the
// spender knew the blinding factors. A coinbase kernel's excess is instead the
// coinbase output commitment itself (value included) and its Fee is zero.
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
)

// Transaction is the basic unit submitted to the mempool. Outputs minus
// inputs plus fee·H must equal the sum of the kernel excesses (commitment-wise).
type Transaction struct {
	Inputs  []Input
	Outputs []Output
	Kernels []Kernel
}

// BlockHeader carries the chain metadata. Hash(header) is the block ID
// and what the PoW must brute-force a nonce against.
type BlockHeader struct {
	Version           uint32
	NetworkMagic      uint32 // chain domain, pinned by trusted genesis
	Height            uint64
	Timestamp         int64 // unix seconds
	PrevHash          Hash
	OutputRoot        Hash       // ordered commitment to all outputs and proofs
	KernelRoot        Hash       // ordered commitment to all inputs and signed kernels
	TotalKernelOffset Commitment // sum-of-all-kernel-offsets (proof aggregation)
	Difficulty        uint64     // target as: hash <= MaxTarget / Difficulty
	Nonce             uint64
}

// Block bundles a header with its transaction body. Coinbase output and
// kernel are included like any other.
type Block struct {
	Header  BlockHeader
	Inputs  []Input
	Outputs []Output
	Kernels []Kernel
}

// Genesis settings: network magic values for the NosoX networks.
const (
	NetworkMagicMainnet uint32 = 0x4e4f5832 // "NOX2"
	NetworkMagicTestnet uint32 = 0x4e4f5854 // "NOXT"

	// BlockVersion is the only accepted block format. Version 5 removed all
	// allocation-carrying outputs: genesis is empty and every coin is mined.
	BlockVersion uint32 = 5

	// TargetBlockTime is the desired interval between blocks.
	TargetBlockTimeSeconds int64 = 120

	// MaxFutureDriftSeconds is how far ahead of the validator's clock a block
	// timestamp may be. Chosen by simulation with the real difficulty
	// algorithm (v2/pow TestTimeWarpFutureLimit).
	MaxFutureDriftSeconds int64 = 540

	// MedianTimeSpan is the number of ancestors whose median timestamp a new
	// block must exceed.
	MedianTimeSpan = 11

	// CoinbaseLock is the number of confirmations before a coinbase
	// output can be spent. Standard Bitcoin/Grin practice.
	CoinbaseLock uint64 = 60

	// LWMA-3 (Zawy) parameters.
	DifficultyWindow = 90

	// MinDifficulty is the floor — networks bootstrap from very low
	// difficulty and ramp up. 1 means "any non-zero hash works".
	MinDifficulty uint64 = 1

	// Base units per coin (8 decimals).
	CoinUnits int64 = 100_000_000

	// Reward schedule.
	InitialReward        int64  = 5_000_000_000
	BlockHalvingInterval uint64 = 210_000
	HalvingSteps         uint64 = 10
)

// BlockReward returns the coinbase reward for a given block height.
// The genesis block has no reward; issuance starts at height 1.
func BlockReward(height uint64) int64 {
	if height == 0 {
		// Genesis carries no outputs at all.
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
	buf := make([]byte, 0, 4+4+8+8+32+32+32+33+8+8)
	buf = binary.BigEndian.AppendUint32(buf, h.Version)
	buf = binary.BigEndian.AppendUint32(buf, h.NetworkMagic)
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
	buf := []byte("NosoX/kernel/v5\x00")
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

// KernelSigningMessage returns the message a plain kernel signature covers:
// SHA256("NosoX/kernel-sig/v5\x00" || BE32(magic) || KernelID). Binding the
// network magic keeps a signature made for one network from validating on
// another. KernelID is derived from the kernel itself (ExcessSig is not
// part of it), so a signer may call this before the signature exists.
func KernelSigningMessage(magic uint32, k *Kernel) []byte {
	id := KernelID(k)
	h := sha256.New()
	h.Write([]byte("NosoX/kernel-sig/v5\x00"))
	var m [4]byte
	binary.BigEndian.PutUint32(m[:], magic)
	h.Write(m[:])
	h.Write(id[:])
	return h.Sum(nil)
}

// EncodeOutput returns a canonical preimage for hashing.
func EncodeOutput(o *Output) []byte {
	buf := []byte("NosoX/output/v5\x00")
	buf = append(buf, byte(o.Features))
	buf = append(buf, o.Commit[:]...)
	return appendField(buf, o.RangeProof)
}

// OutputID returns SHA-256 of the canonical preimage.
func OutputID(o *Output) Hash {
	return sha256.Sum256(EncodeOutput(o))
}
