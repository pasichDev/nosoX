package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

// Schnorr signatures on secp256k1.
//
// Sig = (R, s) where:
//
//	k is a random nonce, k ∈ [1, n-1]
//	R = k·G   (compressed point, 33 bytes)
//	e = H(R || P || msg)   where P is the public key
//	s = k + e·x  (mod n)   where x is the private scalar
//
// Verification recomputes e and checks s·G == R + e·P.
//
// Encoded as 65 bytes = R(33) || s(32). Caller can map this to whatever
// wire field they like (Kernel.ExcessSig, etc).

const schnorrSigSize = 65

// SchnorrSign signs msg with the secret scalar x. The corresponding
// public key P = x·G must be derivable; we recompute it here so callers
// don't pass it twice.
//
// Delegates to the scalar-based implementation in schnorr_ct.go.
// That implementation does not guarantee constant-time execution.
// The alternate body below is retained as
// `schnorrSignVarTime` for cross-validation tests.
func SchnorrSign(x []byte, msg []byte) ([]byte, error) {
	return SchnorrSignConstantTime(x, msg)
}

// schnorrSignVarTime is the original variable-time signer. Kept around
// so the test suite can confirm cross-compatibility, but never called
// from production paths.
func schnorrSignVarTime(x []byte, msg []byte) ([]byte, error) {
	if len(x) != 32 {
		return nil, errors.New("schnorr: bad scalar length")
	}
	curve := Curve()
	xi := new(big.Int).SetBytes(x)
	if xi.Sign() == 0 || xi.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("schnorr: scalar out of range")
	}

	// Public key P = x·G.
	pubX, pubY := curve.ScalarBaseMult(x)
	pub := compress(pubX, pubY)

	// Random nonce k.
	var kBytes [32]byte
	if _, err := rand.Read(kBytes[:]); err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(kBytes[:])
	k.Mod(k, curve.Params().N)
	if k.Sign() == 0 {
		k.SetInt64(1)
	}

	// R = k·G.
	rX, rY := curve.ScalarBaseMult(k.Bytes())
	R := compress(rX, rY)

	// e = H(R || P || msg) mod n.
	e := schnorrChallenge(R, pub, msg)
	e.Mod(e, curve.Params().N)

	// s = k + e·x mod n.
	s := new(big.Int).Mul(e, xi)
	s.Add(s, k)
	s.Mod(s, curve.Params().N)

	sig := make([]byte, schnorrSigSize)
	copy(sig[:33], R[:])
	sb := s.Bytes()
	copy(sig[33+32-len(sb):], sb)
	return sig, nil
}

// SchnorrVerify reports whether sig is a valid Schnorr signature over msg
// by the public key pub.
func SchnorrVerify(pub [33]byte, msg []byte, sig []byte) bool {
	if len(sig) != schnorrSigSize || !ValidPublicPoint(pub) {
		return false
	}
	curve := Curve()
	var R [33]byte
	copy(R[:], sig[:33])
	if !ValidPublicPoint(R) {
		return false
	}
	s := new(big.Int).SetBytes(sig[33:])
	if s.Sign() <= 0 || s.Cmp(curve.Params().N) >= 0 {
		return false
	}

	pX, pY, err := decompress(pub)
	if err != nil {
		return false
	}
	rX, rY, err := decompress(R)
	if err != nil {
		return false
	}

	e := schnorrChallenge(R, pub, msg)
	e.Mod(e, curve.Params().N)

	// Check s·G == R + e·P.
	sgX, sgY := curve.ScalarBaseMult(s.Bytes())
	epX, epY := curve.ScalarMult(pX, pY, e.Bytes())
	expectedX, expectedY := curve.Add(rX, rY, epX, epY)
	return sgX.Cmp(expectedX) == 0 && sgY.Cmp(expectedY) == 0
}

// PublicFromScalar returns the compressed public key for a scalar. Useful
// for callers who don't want to do the elliptic-curve math themselves.
func PublicFromScalar(x []byte) ([33]byte, error) {
	if len(x) != 32 {
		return [33]byte{}, errors.New("schnorr: bad scalar length")
	}
	curve := Curve()
	xi := new(big.Int).SetBytes(x)
	if xi.Sign() == 0 || xi.Cmp(curve.Params().N) >= 0 {
		return [33]byte{}, errors.New("schnorr: scalar out of range")
	}
	pX, pY := curve.ScalarBaseMult(x)
	return compress(pX, pY), nil
}

func schnorrChallenge(R [33]byte, pub [33]byte, msg []byte) *big.Int {
	h := sha256.New()
	h.Write([]byte("Noso-v2-Schnorr"))
	h.Write(R[:])
	h.Write(pub[:])
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(msg)))
	h.Write(l[:])
	h.Write(msg)
	return new(big.Int).SetBytes(h.Sum(nil))
}
