package wallet

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Envelope versions. Version 1 (Argon2id t=1, 64 MiB, p=1, parameters implicit,
// no additional data on the keystore) is read for migration only; everything
// this package writes is version 2: the Argon2id parameters are stored in the
// file and, together with the version, label and salt, authenticated as AEAD
// additional data, so none of them can be altered without breaking decryption.
const (
	envelopeV1 = 1
	envelopeV2 = 2
)

// KDFParams are the Argon2id parameters stored in a version 2 envelope.
type KDFParams struct {
	T      uint32 `json:"t"` // passes
	MemKiB uint32 `json:"m"` // memory in KiB
	P      uint8  `json:"p"` // lanes
}

// legacyKDF is what version 1 envelopes used implicitly.
var legacyKDF = KDFParams{T: 1, MemKiB: 64 * 1024, P: 1}

// kdfDefault is used for every new envelope. 256 MiB, t=3, p=4 (see
// docs/wallet.md for the measured cost). kdfFloor is the weakest setting a v2
// file may declare; both are variables only so the package tests can run with
// cheap parameters. Nothing outside tests changes them.
var (
	productionKDF = KDFParams{T: 3, MemKiB: 256 * 1024, P: 4}
	kdfDefault    = productionKDF
	kdfFloor      = KDFParams{T: 3, MemKiB: 256 * 1024, P: 1}
)

const (
	kdfMaxT      = 16
	kdfMaxMemKiB = 1 << 20 // 1 GiB: a crafted file must not demand more
	kdfMaxP      = 16
)

func (p KDFParams) validate() error {
	if p.T < kdfFloor.T || p.MemKiB < kdfFloor.MemKiB || p.P < kdfFloor.P {
		return errors.New("wallet: key derivation parameters are weaker than the minimum")
	}
	if p.T > kdfMaxT || p.MemKiB > kdfMaxMemKiB || p.P > kdfMaxP || p.P == 0 || uint64(p.MemKiB) < 8*uint64(p.P) {
		return errors.New("wallet: key derivation parameters out of range")
	}
	return nil
}

func deriveKey(passphrase string, salt []byte, p KDFParams) []byte {
	return argon2.IDKey([]byte(passphrase), salt, p.T, p.MemKiB, p.P, 32)
}

const (
	labelKeystore = "noso-wallet-keystore"
	labelState    = "noso-wallet-outputs"
	// legacyStateAAD is what version 1 state files used.
	legacyStateAAD = "noso-wallet-outputs-v1"
)

// envelopeAAD binds label, version, salt and KDF parameters to the ciphertext.
func envelopeAAD(label string, version int, salt []byte, p KDFParams) []byte {
	b := []byte(label)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint32(b, uint32(version))
	b = binary.BigEndian.AppendUint32(b, p.T)
	b = binary.BigEndian.AppendUint32(b, p.MemKiB)
	b = append(b, p.P)
	b = binary.BigEndian.AppendUint16(b, uint16(len(salt)))
	return append(b, salt...)
}

// MinPassphraseLen is the minimum length (in characters) of a new passphrase.
const MinPassphraseLen = 12

// ValidatePassphrase enforces the policy for NEW passphrases. Existing wallets
// are never locked out by it: opening a wallet does not apply it.
func ValidatePassphrase(p string) error {
	if utf8.RuneCountInString(p) < MinPassphraseLen {
		return fmt.Errorf("wallet: passphrase must be at least %d characters", MinPassphraseLen)
	}
	return nil
}

// macGen authenticates a generation counter with a key derived from the state key.
func macGen(key []byte, gen uint64) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("noso-wallet-generation/v1"))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], gen)
	m.Write(b[:])
	return m.Sum(nil)
}
