package crypto

// Scalar-based Schnorr implementation. The exported historical name is kept
// for API compatibility. It is NOT a constant-time signing guarantee:
// decred PrivateKey.PubKey calls ScalarBaseMultNonConst. A reviewed secret
// multiplication implementation is required before side-channel-sensitive use.

import (
	"crypto/rand"
	"errors"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// SchnorrSignConstantTime retains its historical name; see the warning above.
func SchnorrSignConstantTime(x []byte, msg []byte) ([]byte, error) {
	if len(x) != 32 {
		return nil, errors.New("schnorr: bad scalar length")
	}
	// Parse the scalar without silently reducing out-of-range secrets.
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
	sampled := false
	for tries := 0; tries < 16; tries++ {
		var kBytes [32]byte
		if _, err := rand.Read(kBytes[:]); err != nil {
			return nil, err
		}
		if overflow := kScalar.SetByteSlice(kBytes[:]); !overflow && !kScalar.IsZero() {
			sampled = true
			break
		}
	}
	if !sampled {
		return nil, errors.New("schnorr: failed to sample nonce")
	}

	// R = k·G. PubKey uses variable-time multiplication.
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
