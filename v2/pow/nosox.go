// Package pow implements NosoX, Noso v2's Proof-of-Work.
//
// NosoX is Argon2id over the canonical block-header encoding. The
// parameters are tuned to be CPU-friendly on a Raspberry Pi 4 while
// raising the bar for ASIC and GPU optimization: memory dominates
// runtime, and ARM hardware has competitive memory bandwidth.
//
// Parameters:
//
//	memory = 64 MiB        (single block costs ~50–150 ms on a Pi 4)
//	time   = 1 pass
//	threads = 1 lane (deterministic)
//	keyLen = 32 bytes
//	salt   = "NosoX/pow-salt/v5\0"
//
// The hash is interpreted as a big-endian 256-bit integer; a block is
// valid when hash * difficulty <= 2^256 − 1 (standard Bitcoin-style
// "target = MaxTarget / difficulty").
package pow

import (
	"math/big"

	"github.com/pasichDev/nosoX/v2/types"
	"golang.org/x/crypto/argon2"
)

// Argon2 parameters.
const (
	Argon2Memory  uint32 = 64 * 1024 // KiB
	Argon2Time    uint32 = 1
	Argon2Threads uint8  = 1
	Argon2KeyLen  uint32 = 32
)

// Salt is fixed for determinism. The header carries the actual entropy
// (prev_hash, merkle roots, nonce).
var Salt = []byte("NosoX/pow-salt/v5\x00")

// MaxTarget is 2^256 − 1.
var MaxTarget = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// Hash computes Argon2id over the canonical encoding of h.
func Hash(h *types.BlockHeader) [32]byte {
	preimage := types.EncodeHeader(h)
	digest := argon2.IDKey(preimage, Salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	var out [32]byte
	copy(out[:], digest)
	return out
}

// Target returns the 256-bit target for the given difficulty. A header
// hash is valid iff (big.Int from hash) <= target.
func Target(difficulty uint64) *big.Int {
	if difficulty == 0 {
		return new(big.Int)
	}
	d := new(big.Int).SetUint64(difficulty)
	return new(big.Int).Div(MaxTarget, d)
}

// Verify reports whether the given header's Argon2id digest meets its
// declared difficulty.
func Verify(h *types.BlockHeader) bool {
	if h == nil || h.Difficulty == 0 {
		return false
	}
	digest := Hash(h)
	hashInt := new(big.Int).SetBytes(digest[:])
	return hashInt.Cmp(Target(h.Difficulty)) <= 0
}
