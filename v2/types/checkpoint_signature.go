package types

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// LauncherPubkey is the Ed25519 public key whose corresponding private
// key signs the canonical checkpoint list. Empty by default — the
// launcher fills this in for their release.
//
// The signed payload is `canonicalCheckpointHash(MainnetCheckpoints)`
// and the matching signature must satisfy
// `ed25519.Verify(LauncherPubkey, hash, MainnetCheckpointsSig)`.
//
// A daemon refuses to start if a non-empty LauncherPubkey is configured
// but MainnetCheckpointsSig does not verify.
var LauncherPubkey ed25519.PublicKey

// MainnetCheckpointsSig is the Ed25519 signature over the canonical
// hash of MainnetCheckpoints. Bake this in via the launcher release
// process.
var MainnetCheckpointsSig []byte

// canonicalCheckpointHash returns a SHA-256 of the canonical encoding
// of the supplied checkpoint list. Encoding format:
//
//	"NosoX-Checkpoints-v1\n"
//	for each checkpoint (sorted by Height ascending):
//	    8-byte big-endian Height
//	    32-byte raw Hash
//
// Sorting makes the hash independent of the source-order of the slice.
func CanonicalCheckpointHash(list []Checkpoint) [32]byte {
	sorted := append([]Checkpoint(nil), list...)
	// Insertion sort — list is small (~100 entries).
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j-1].Height > sorted[j].Height; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	h := sha256.New()
	h.Write([]byte("NosoX-Checkpoints-v1\n"))
	var hb [8]byte
	for _, cp := range sorted {
		binary.BigEndian.PutUint64(hb[:], cp.Height)
		h.Write(hb[:])
		h.Write(cp.Hash[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// VerifyCheckpointList confirms the supplied signature is a valid
// Ed25519 signature by pubkey over CanonicalCheckpointHash(list).
//
//	pubkey == nil  → returns nil (no enforcement, launcher hasn't
//	                  baked in a key yet — dev mode)
//	pubkey != nil and sig == nil → returns ErrUnsignedCheckpoints
//	pubkey != nil and sig is wrong → returns ErrBadCheckpointSig
func VerifyCheckpointList(pubkey ed25519.PublicKey, sig []byte, list []Checkpoint) error {
	if pubkey == nil {
		return nil
	}
	if len(sig) == 0 {
		return ErrUnsignedCheckpoints
	}
	hash := CanonicalCheckpointHash(list)
	if !ed25519.Verify(pubkey, hash[:], sig) {
		return ErrBadCheckpointSig
	}
	return nil
}

// VerifyBakedCheckpoints checks the package-level LauncherPubkey +
// MainnetCheckpointsSig against MainnetCheckpoints. The daemon calls
// this at startup; a failure means the binary was tampered with or
// the checkpoint list is out of sync with the signature.
func VerifyBakedCheckpoints() error {
	return VerifyCheckpointList(LauncherPubkey, MainnetCheckpointsSig, MainnetCheckpoints)
}

// ErrUnsignedCheckpoints means a LauncherPubkey is baked in but no
// signature accompanies the checkpoint list. Treat the binary as
// untrusted.
var ErrUnsignedCheckpoints = errors.New("types: LauncherPubkey set but checkpoint signature missing")

// ErrBadCheckpointSig means the signature on the checkpoint list does
// not verify under LauncherPubkey. The binary was either modified or
// the launcher signed a different list — either way refuse to run.
var ErrBadCheckpointSig = errors.New("types: checkpoint list signature does not verify")
