package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 is required by Noso signing alg.
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"

	btcec "github.com/btcsuite/btcd/btcec/v2"
)

// KeyPair holds a Noso key pair encoded the way `wallet.pkw` and the wire
// protocol expect: public = Base64(uncompressed EC point), private =
// Base64(32-byte big-endian unsigned scalar).
type KeyPair struct {
	PrivateKey string // 44 Base64 chars (32-byte scalar)
	PublicKey  string // 88 Base64 chars (65-byte uncompressed EC point)
}

// IsValid checks the canonical lengths the Dart client enforces
// (`keys_pair.dart:25-27`). Length-only check is intentional — that's all
// the existing code does.
func (k KeyPair) IsValid() bool {
	return len(k.PublicKey) == 88 && len(k.PrivateKey) == 44
}

// curve returns the secp256k1 curve from btcd. btcec.S256() implements
// elliptic.Curve so it plugs into Go's stdlib ecdsa package.
func curve() elliptic.Curve { return btcec.S256() }

// GenerateKeyPair creates a fresh secp256k1 key pair using crypto/rand.
// Output strings are formatted exactly the way the Pascal `GenerateECKeyPair`
// and Dart `generateKeyPair` would produce them.
func GenerateKeyPair() (KeyPair, error) {
	priv, err := ecdsa.GenerateKey(curve(), rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return encodeKeyPair(priv), nil
}

func encodeKeyPair(priv *ecdsa.PrivateKey) KeyPair {
	d := priv.D.Bytes()
	if len(d) < 32 {
		d = append(make([]byte, 32-len(d)), d...)
	}
	pub := elliptic.Marshal(curve(), priv.X, priv.Y) //nolint:staticcheck // uncompressed point is required
	return KeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(d),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
	}
}

// ParsePrivateKey decodes a Base64 private key string into an *ecdsa.PrivateKey
// with the secp256k1 curve and the public component derived.
func ParsePrivateKey(b64 string) (*ecdsa.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > 32 {
		return nil, errors.New("crypto.ParsePrivateKey: invalid scalar length")
	}
	d := new(big.Int).SetBytes(raw)
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve()
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = curve().ScalarBaseMult(d.Bytes())
	return priv, nil
}

// ParsePublicKey decodes a Base64 public key into an *ecdsa.PublicKey.
// Accepts the 65-byte uncompressed format. Returns an error for anything else.
func ParsePublicKey(b64 string) (*ecdsa.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	x, y := elliptic.Unmarshal(curve(), raw) //nolint:staticcheck
	if x == nil {
		return nil, errors.New("crypto.ParsePublicKey: invalid EC point")
	}
	return &ecdsa.PublicKey{Curve: curve(), X: x, Y: y}, nil
}

// ecdsaSig is the ASN.1 DER container Noso uses.
type ecdsaSig struct {
	R, S *big.Int
}

// SignString signs the SHA-1 digest of `message` with `privateKeyB64` and
// returns a Base64-encoded ASN.1 DER signature, byte-compatible with the
// Pascal `GetStringSigned` and Dart `signMessage` output.
//
// The `message` argument is treated as raw bytes — pre-Base64-decoded by
// the caller if the protocol requires it. (Pascal's `GetStringSigned`
// Base64-decodes its input first; pass that decoded form here.)
func SignString(message []byte, privateKeyB64 string) (string, error) {
	priv, err := ParsePrivateKey(privateKeyB64)
	if err != nil {
		return "", err
	}
	h := sha1.Sum(message) //nolint:gosec
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		return "", err
	}
	der, err := asn1.Marshal(ecdsaSig{R: r, S: s})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// VerifyString verifies a Base64+DER signature against the SHA-1 digest of
// `message` using `publicKeyB64`. Returns false on any parse or
// verification failure — matches Pascal `VerifySignedString`, which
// swallows all exceptions.
func VerifyString(message []byte, signatureB64, publicKeyB64 string) bool {
	pub, err := ParsePublicKey(publicKeyB64)
	if err != nil {
		return false
	}
	der, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}
	var sig ecdsaSig
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return false
	}
	h := sha1.Sum(message) //nolint:gosec
	return ecdsa.Verify(pub, h[:], sig.R, sig.S)
}
