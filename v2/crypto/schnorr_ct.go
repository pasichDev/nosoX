package crypto

// Constant-time SchnorrSign implementation.
//
// The existing SchnorrSign in schnorr.go calls
// `elliptic.Curve.ScalarBaseMult(x.Bytes())` and `big.Int` arithmetic,
// both of which leak timing on the secret scalars.
//
// This file provides `schnorrSignCT` that uses decred's
// `secp256k1.PrivateKey` and `ModNScalar` types. Internally they:
//
//   - Multiply `k·G` via a fixed-base table with byte-level masking
//     designed to be branch- and lookup-free (constant-time).
//   - Add scalars modulo n via the `ModNScalar` type, which performs
//     reductions in fixed time.
//
// The wire output is byte-identical to the existing schnorrSign
// (R(33) || s(32) compressed) so verifiers don't care which
// implementation produced the signature.

import (
	"crypto/rand"
	"errors"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// SchnorrSignConstantTime is the side-channel-resistant signing
// primitive. Recommended for production. The variable-time SchnorrSign
// is kept for backward-compatibility and round-trip tests.
func SchnorrSignConstantTime(x []byte, msg []byte) ([]byte, error) {
	if len(x) != 32 {
		return nil, errors.New("schnorr: bad scalar length")
	}
	// Wrap x as a secp256k1.PrivateKey. The constructor performs
	// scalar reduction in constant time and the PubKey method uses the
	// fixed-base table for constant-time multiplication.
	var xScalar secp.ModNScalar
	if overflow := xScalar.SetByteSlice(x); overflow {
		return nil, errors.New("schnorr: scalar overflows curve order")
	}
	if xScalar.IsZero() {
		return nil, errors.New("schnorr: scalar must be non-zero")
	}
	priv := secp.NewPrivateKey(&xScalar)
	pubBytes := priv.PubKey().SerializeCompressed()
	var pub [33]byte
	copy(pub[:], pubBytes)

	// Random nonce k. Rejection-sample until k is in [1, n).
	var kScalar secp.ModNScalar
	for tries := 0; tries < 16; tries++ {
		var kBytes [32]byte
		if _, err := rand.Read(kBytes[:]); err != nil {
			return nil, err
		}
		if overflow := kScalar.SetByteSlice(kBytes[:]); !overflow && !kScalar.IsZero() {
			break
		}
	}
	if kScalar.IsZero() {
		return nil, errors.New("schnorr: failed to sample nonce")
	}

	// R = k·G. PubKey-from-private-key uses constant-time fixed-base.
	rPriv := secp.NewPrivateKey(&kScalar)
	rBytes := rPriv.PubKey().SerializeCompressed()
	var R [33]byte
	copy(R[:], rBytes)

	// e = H(R || P || msg) mod n.
	eHash := schnorrChallenge(R, pub, msg)
	var eScalar secp.ModNScalar
	eBytes := eHash.Bytes()
	eBuf := make([]byte, 32)
	copy(eBuf[32-len(eBytes):], eBytes)
	eScalar.SetByteSlice(eBuf)

	// s = k + e·x (mod n). ModNScalar.Mul + Add are constant-time.
	var s secp.ModNScalar
	s.Mul2(&eScalar, &xScalar)
	s.Add(&kScalar)

	// Encode.
	sig := make([]byte, schnorrSigSize)
	copy(sig[:33], R[:])
	sBytes := s.Bytes()
	copy(sig[33:], sBytes[:])
	return sig, nil
}
