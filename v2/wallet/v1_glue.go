package wallet

import (
	v1crypto "github.com/noso-project/noso-go/internal/crypto"
)

// v1cryptoSignWrapper wraps the v1 archive package's secp256k1+SHA1
// ECDSA signer. Used by the NosoX builder to produce
// LegacySpendMessage signatures.
func v1cryptoSignWrapper(privateKeyB64 string, msg []byte) (string, error) {
	return v1crypto.SignString(msg, privateKeyB64)
}
