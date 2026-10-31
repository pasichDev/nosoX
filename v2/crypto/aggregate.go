package crypto

import (
	"math/big"
)

// Helpers for two-party Schnorr aggregation (wallet slates). They expose the
// exact challenge used by SchnorrVerify so an aggregated signature is verified
// against byte-identical hashing, and a partial-signature check so a party can
// validate the other side's contribution before combining.
//
// All operations here use big.Int curve arithmetic and are VARIABLE-TIME. They
// are only ever applied to public values (points, challenges and partial
// signatures that are about to be published).

// SchnorrChallengeScalar returns e = H(R||P||len(msg)||msg) under the Schnorr domain of schnorr.go,
// reduced mod n, as a 32-byte big-endian scalar. It calls the same
// schnorrChallenge that SchnorrVerify uses, so there is one implementation.
func SchnorrChallengeScalar(R, P [33]byte, msg []byte) [32]byte {
	e := schnorrChallenge(R, P, msg)
	e.Mod(e, Curve().Params().N)
	var out [32]byte
	b := e.Bytes()
	copy(out[32-len(b):], b)
	return out
}

// VerifyPartialSchnorr reports whether s·G == R + e·P, where (R, P) are one
// participant's public nonce and public excess and e is the (shared) challenge.
// s must be a canonical non-zero scalar and R, P must be valid non-identity
// points.
func VerifyPartialSchnorr(s [32]byte, R, P [33]byte, e [32]byte) bool {
	curve := Curve()
	n := curve.Params().N
	si := new(big.Int).SetBytes(s[:])
	if si.Sign() == 0 || si.Cmp(n) >= 0 {
		return false
	}
	ei := new(big.Int).SetBytes(e[:])
	if ei.Cmp(n) >= 0 || !ValidPublicPoint(R) || !ValidPublicPoint(P) {
		return false
	}
	rX, rY, err := decompress(R)
	if err != nil {
		return false
	}
	pX, pY, err := decompress(P)
	if err != nil {
		return false
	}
	sgX, sgY := curve.ScalarBaseMult(s[:])
	if ei.Sign() == 0 {
		return sgX.Cmp(rX) == 0 && sgY.Cmp(rY) == 0
	}
	epX, epY := curve.ScalarMult(pX, pY, e[:])
	wantX, wantY := curve.Add(rX, rY, epX, epY)
	return sgX.Cmp(wantX) == 0 && sgY.Cmp(wantY) == 0
}
