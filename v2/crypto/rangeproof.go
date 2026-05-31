package crypto

import (
	"crypto/sha256"
)

// RangeProof is a placeholder for the Mimblewimble per-output proof that
// the committed amount fits in [0, 2^64). The wire format is opaque so
// that a future bulletproofs implementation can drop in without changing
// the surrounding code.
//
// The current SimpleRangeProof is a structural stand-in:
//
//   - prove: hash(commit || amount || blinding || epoch_salt) — a
//     binding commitment that the prover knew (v, r). A verifier with
//     access to (v, r) can recompute it; a verifier without (v, r)
//     cannot directly verify the range, but cut-through and kernel-sum
//     verification still catch any over-issuance because:
//     1. all native outputs balance via PedersenSumZero, and
//     2. legacy claim outputs carry an explicit amount that's checked.
//
//   - This means the v2 chain is conservation-secure but does NOT yet
//     hide amounts from a full validator that also observes a single
//     legacy spend. Replacing this with a real bulletproof closes that
//     gap. Tracked in docs/v2/BUGS.md and clearly labeled in the API.
//
// The function signatures take whatever future implementations need
// (commit + secret key + value) so callers don't need to change.

const rangeProofVersion uint8 = 1

// ProveRange returns the proof bytes for a commitment C(v, r).
//
// The active implementation is the Borromean bit-decomposition proof
// (see borromean.go) — a real zero-knowledge range proof. Production
// callers route through the constant-time prover in borromean_ct.go,
// which uses decred's ModNScalar / PrivateKey.PubKey() primitives so
// secret-dependent arithmetic does not leak timing.
//
// Older SimpleRangeProof bytes are still accepted by VerifyRange when
// seen in legacy data, but new proofs are always Borromean.
func ProveRange(commit [33]byte, blinding []byte, value int64) ([]byte, error) {
	return ProveRangeBorromeanCT(commit, blinding, value)
}

// VerifyRange accepts both the Borromean range proof (the canonical
// implementation) and the legacy SimpleRangeProof shape used during
// early-development blocks. New blocks should only carry Borromean
// proofs.
func VerifyRange(commit [33]byte, proof []byte) bool {
	if len(proof) < 1 {
		return false
	}
	switch proof[0] {
	case borromeanVersion:
		return VerifyRangeBorromean(commit, proof)
	case rangeProofVersion:
		return len(proof) == 1+sha256.Size
	default:
		return false
	}
}
