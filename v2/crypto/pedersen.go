// Package crypto in v2 implements Mimblewimble primitives over secp256k1
// using btcec, plus the Argon2id-based NosoX PoW (separate file).
//
// Pedersen commitments:
//
//	C(v, r) = v·H + r·G
//
// where G is the standard secp256k1 generator and H is a NUMS
// ("Nothing-Up-My-Sleeve") point with no known discrete log w.r.t. G.
// We derive H deterministically by hashing the bytes of G's encoding and
// using the resulting digest as an X-coord candidate (try-and-increment).
//
// Range proofs in this implementation are intentionally simple — a
// 64-bit non-negative amount check via a NUMS-rooted sigma-style proof
// that is structurally complete but not as compact as Bulletproofs.
// The interface is shaped so a future drop-in upgrade (bulletproofs,
// halo, etc.) requires zero changes elsewhere in the code.
package crypto

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

// Curve returns secp256k1.
func Curve() *btcec.KoblitzCurve { return btcec.S256() }

// generatorH is the secondary base point for Pedersen value commits.
// Derived once at init time from SHA-256("Noso v2 Pedersen H point") using
// try-and-increment over the X coordinate. The resulting Y is fixed at
// "smaller" parity for determinism.
var generatorH *btcec.PublicKey

func init() {
	seed := sha256.Sum256([]byte("Noso v2 Pedersen H point"))
	x := new(big.Int).SetBytes(seed[:])
	for {
		x.Mod(x, Curve().Params().P)
		if p, ok := liftX(x); ok {
			generatorH = p
			return
		}
		x.Add(x, big.NewInt(1))
	}
}

// liftX returns the secp256k1 point with the given X coordinate and
// even Y, if such a point exists.
func liftX(x *big.Int) (*btcec.PublicKey, bool) {
	p := Curve().Params().P
	xCubed := new(big.Int).Exp(x, big.NewInt(3), p)
	rhs := new(big.Int).Add(xCubed, Curve().Params().B)
	rhs.Mod(rhs, p)
	y := new(big.Int).ModSqrt(rhs, p)
	if y == nil {
		return nil, false
	}
	if y.Bit(0) == 1 {
		y.Sub(p, y)
	}
	return newPubKey(x, y), true
}

func newPubKey(x, y *big.Int) *btcec.PublicKey {
	var xf btcec.FieldVal
	var yf btcec.FieldVal
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(xb[32-len(xBytes):], xBytes)
	copy(yb[32-len(yBytes):], yBytes)
	xf.SetBytes((*[32]byte)(xb))
	yf.SetBytes((*[32]byte)(yb))
	return btcec.NewPublicKey(&xf, &yf)
}

// PedersenCommit returns C(v, r) = v·H + r·G as a 33-byte compressed point.
// `v` is the amount (>= 0). `r` is the blinding factor as a 32-byte scalar.
func PedersenCommit(v int64, r []byte) ([33]byte, error) {
	if v < 0 {
		return [33]byte{}, errors.New("pedersen: negative amount")
	}
	if len(r) != 32 {
		return [33]byte{}, errors.New("pedersen: blinding factor must be 32 bytes")
	}
	curve := Curve()

	// v · H
	vBytes := new(big.Int).SetInt64(v).Bytes()
	vHx, vHy := curve.ScalarMult(generatorH.X(), generatorH.Y(), vBytes)

	// r · G
	rGx, rGy := curve.ScalarBaseMult(r)

	// (v·H) + (r·G)
	sumX, sumY := curve.Add(vHx, vHy, rGx, rGy)

	return compress(sumX, sumY), nil
}

// PedersenSumZero reports whether the algebraic sum of the given
// (positive_commits) − (negative_commits) − (fee·H) equals the identity
// (point at infinity). This is the central conservation check of MW.
func PedersenSumZero(positive, negative [][33]byte, fee int64) (bool, error) {
	curve := Curve()
	accX, accY := big.NewInt(0), big.NewInt(0)
	add := func(b [33]byte, neg bool) error {
		x, y, err := decompress(b)
		if err != nil {
			return err
		}
		if neg {
			y = new(big.Int).Sub(curve.Params().P, y)
		}
		if accX.Sign() == 0 && accY.Sign() == 0 {
			accX, accY = x, y
		} else {
			accX, accY = curve.Add(accX, accY, x, y)
		}
		return nil
	}
	for _, c := range positive {
		if err := add(c, false); err != nil {
			return false, err
		}
	}
	for _, c := range negative {
		if err := add(c, true); err != nil {
			return false, err
		}
	}
	if fee > 0 {
		// subtract fee · H
		fBytes := new(big.Int).SetInt64(fee).Bytes()
		fHx, fHy := curve.ScalarMult(generatorH.X(), generatorH.Y(), fBytes)
		fHy = new(big.Int).Sub(curve.Params().P, fHy)
		accX, accY = curve.Add(accX, accY, fHx, fHy)
	}
	// Identity (point at infinity) = (0, 0) for our chosen encoding.
	return accX.Sign() == 0 && accY.Sign() == 0, nil
}

// compress encodes (x, y) into a 33-byte compressed format: 02|03 +
// big-endian X.
func compress(x, y *big.Int) [33]byte {
	var out [33]byte
	if x == nil || y == nil {
		return out // identity → all zeros
	}
	if y.Bit(0) == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	xb := x.Bytes()
	copy(out[1+32-len(xb):], xb)
	return out
}

// decompress restores (x, y) from the 33-byte compressed encoding.
func decompress(c [33]byte) (*big.Int, *big.Int, error) {
	if c[0] == 0 {
		// Identity sentinel: caller uses (0, 0) for the empty sum.
		return big.NewInt(0), big.NewInt(0), nil
	}
	if c[0] != 0x02 && c[0] != 0x03 {
		return nil, nil, errors.New("pedersen: bad compressed prefix")
	}
	x := new(big.Int).SetBytes(c[1:])
	p := Curve().Params().P
	xCubed := new(big.Int).Exp(x, big.NewInt(3), p)
	rhs := new(big.Int).Add(xCubed, Curve().Params().B)
	rhs.Mod(rhs, p)
	y := new(big.Int).ModSqrt(rhs, p)
	if y == nil {
		return nil, nil, errors.New("pedersen: invalid X (no Y exists)")
	}
	if (c[0] == 0x02) != (y.Bit(0) == 0) {
		y.Sub(p, y)
	}
	return x, y, nil
}
