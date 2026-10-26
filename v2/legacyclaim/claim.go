// Package legacyclaim implements the version4 experimental ownership procedure.
// Chain validation consumes the active source separately; this package does not
// authenticate historical balances or their economic legitimacy.
package legacyclaim

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	legacy "github.com/pasichDev/noso-go/internal/crypto"
)

// Context is chosen by the verifier, never taken on trust from a proof. The
// destination digest commits to the exact v4 claim leg using DestinationDigest.
// It excludes ownership signatures and binds the complete output and kernel IDs.
type Context struct {
	Network                uint32
	Genesis                [32]byte
	DestinationTransaction [32]byte
}

// Source must be loaded from independently authenticated, active source state.
// Commitment is the canonical compressed Pedersen source point identifying an
// active allocation. Address and amount must come from that allocation. Hashing
// claimant-supplied metadata establishes no trust. This helper cannot establish the authenticity or uniqueness of a source.
type Source struct {
	Commitment [33]byte
	Address    string
	Amount     int64
}

// Proof uses the historical public-key TEXT, because that text is the address
// preimage. Signatures use the NEW SHA256 procedure, not the historical SHA1 one.
type Proof struct {
	PublicKeyBase64 string
	SignatureBase64 string
}

// DestinationDigest binds a v4 claim leg to one exact Plain output and one
// exact LegacyClaim kernel. Both IDs exclude the ECDSA proof, avoiding a cycle;
// OutputID includes its range proof, KernelID excludes its Schnorr signature.
func DestinationDigest(outputID, kernelID [32]byte) [32]byte {
	message := []byte("NosoX/legacy-claim-leg/v4\x00")
	message = append(message, outputID[:]...)
	message = append(message, kernelID[:]...)
	return sha256.Sum256(message)
}

// Digest returns SHA256 of the versioned canonical claim message. Network is
// uint32 big-endian; address has a uint32 big-endian byte length; the source point
// is 33 bytes and other digests are fixed 32 bytes;
// the strictly positive amount is uint64 big-endian base units. There is no
// height, timestamp, nonce, or signature in the message.
func Digest(ctx Context, source Source) ([32]byte, error) {
	if ctx.Network == 0 {
		return [32]byte{}, errors.New("legacyclaim: missing network")
	}
	if ctx.Genesis == [32]byte{} || ctx.DestinationTransaction == [32]byte{} || source.Commitment == [33]byte{} {
		return [32]byte{}, errors.New("legacyclaim: missing commitment")
	}
	if source.Amount <= 0 || len(source.Address) > 64 || !legacy.IsValidAddress(source.Address) || source.Address[0] != 'N' {
		return [32]byte{}, errors.New("legacyclaim: invalid regular source")
	}
	if source.Commitment[0] != 2 && source.Commitment[0] != 3 {
		return [32]byte{}, errors.New("legacyclaim: noncanonical source point")
	}
	if _, err := secp.ParsePubKey(source.Commitment[:]); err != nil {
		return [32]byte{}, errors.New("legacyclaim: invalid source point")
	}
	message := []byte("NosoX/legacy-ownership/SHA256/v1\x00")
	message = binary.BigEndian.AppendUint32(message, ctx.Network)
	message = append(message, ctx.Genesis[:]...)
	message = append(message, source.Commitment[:]...)
	message = appendText(message, source.Address)
	message = binary.BigEndian.AppendUint64(message, uint64(source.Amount))
	message = append(message, ctx.DestinationTransaction[:]...)
	return sha256.Sum256(message), nil
}

func appendText(dst []byte, text string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(text)))
	return append(dst, text...)
}

func decodeCanonical(text string, max int) ([]byte, error) {
	if len(text) == 0 || len(text) > max {
		return nil, errors.New("legacyclaim: invalid Base64 length")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != text {
		return nil, errors.New("legacyclaim: noncanonical Base64")
	}
	return raw, nil
}

// Verify checks possession of the key for a trusted source and exact context.
// The caller must separately consume the active source atomically to prevent
// duplicate claims. This helper alone does not authorize any historical snapshot.
func Verify(ctx Context, source Source, proof Proof) error {
	digest, err := Digest(ctx, source)
	if err != nil {
		return err
	}
	raw, err := decodeCanonical(proof.PublicKeyBase64, 88)
	if err != nil {
		return err
	}
	if len(raw) != 65 || raw[0] != 4 {
		return errors.New("legacyclaim: expected uncompressed public key")
	}
	pub, err := secp.ParsePubKey(raw)
	if err != nil {
		return errors.New("legacyclaim: invalid public point")
	}
	address, err := legacy.AddressFromPublicKey(proof.PublicKeyBase64, legacy.AddressTypeRegular)
	if err != nil || address != source.Address {
		return errors.New("legacyclaim: key does not own source")
	}
	der, err := decodeCanonical(proof.SignatureBase64, 96)
	if err != nil {
		return err
	}
	sig, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		return errors.New("legacyclaim: invalid strict DER signature")
	}
	s := sig.S()
	if s.IsOverHalfOrder() {
		return errors.New("legacyclaim: high-S signature forbidden by new procedure")
	}
	if !sig.Verify(digest[:], pub) {
		return errors.New("legacyclaim: signature verification failed")
	}
	return nil
}
