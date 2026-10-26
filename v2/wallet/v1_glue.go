package wallet

import (
	"encoding/base64"
	"errors"
	"github.com/btcsuite/btcd/btcec/v2"
	v1crypto "github.com/pasichDev/noso-go/internal/crypto"
)

// v1cryptoSignWrapper wraps the v1 archive package's secp256k1+SHA1
// ECDSA signer. Used by the NosoX builder to produce
// LegacySpendMessage signatures.
func v1cryptoSignWrapper(privateKeyB64 string, msg []byte) (string, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(privateKeyB64)
	if err != nil || len(raw) != 32 {
		return "", errors.New("wallet: invalid legacy secret")
	}
	defer Zeroize(raw)
	var scalar btcec.ModNScalar
	if scalar.SetByteSlice(raw) || scalar.IsZero() {
		return "", errors.New("wallet: invalid legacy scalar")
	}
	return v1crypto.SignString(msg, privateKeyB64)
}
