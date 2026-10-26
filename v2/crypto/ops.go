package crypto

import (
	"errors"
	"math/big"
)

// PointSubtract returns a - b on secp256k1, encoded as compressed points.
// Used by the chain validator to recover the coinbase's public key
// (commit - amount·H) from header-visible data.
func PointSubtract(a, b [33]byte) ([33]byte, error) {
	curve := Curve()
	ax, ay, err := decompress(a)
	if err != nil {
		return [33]byte{}, err
	}
	bx, by, err := decompress(b)
	if err != nil {
		return [33]byte{}, err
	}
	// -b: negate Y over the field.
	by2 := new(big.Int).Sub(curve.Params().P, by)
	rx, ry := curve.Add(ax, ay, bx, by2)
	if rx == nil || ry == nil || (rx.Sign() == 0 && ry.Sign() == 0) {
		return [33]byte{}, errors.New("crypto: PointSubtract identity")
	}
	return compress(rx, ry), nil
}

// PointAdd returns a + b on secp256k1, encoded as compressed points. Used to
// build the transparent dev-fund commitment F·H + DevFundPoint.
func PointAdd(a, b [33]byte) ([33]byte, error) {
	curve := Curve()
	ax, ay, err := decompress(a)
	if err != nil {
		return [33]byte{}, err
	}
	bx, by, err := decompress(b)
	if err != nil {
		return [33]byte{}, err
	}
	rx, ry := curve.Add(ax, ay, bx, by)
	if rx == nil || ry == nil || (rx.Sign() == 0 && ry.Sign() == 0) {
		return [33]byte{}, errors.New("crypto: PointAdd identity")
	}
	return compress(rx, ry), nil
}
