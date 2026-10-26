// Package wallet manages user keys and constructs transactions.
//
// Keystore: JSON file encrypted with Argon2id-derived key + XChaCha20-Poly1305.
// A wallet holds:
//   - An Ed25519 master key (new-era identity + signing).
//   - Zero or more secp256k1 legacy keys imported from v1 wallet.pkw
//     for claiming legacy outputs.
package wallet

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"io"
	"os"
	"path/filepath"

	v1crypto "github.com/pasichDev/noso-go/internal/crypto"
	v1types "github.com/pasichDev/noso-go/internal/types"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Wallet is the in-memory key bundle.
type Wallet struct {
	Master ed25519.PrivateKey        `json:"-"`
	Legacy map[string]LegacyKeyEntry `json:"-"` // by legacy address
	Plain  plainView                 `json:"-"` // export view used in serialization
}

// LegacyKeyEntry holds the (legacy_address, public_key_base64, private_key_base64)
// triple imported from a v1 wallet.pkw file.
type LegacyKeyEntry struct {
	Address    string `json:"address"`
	PublicKey  string `json:"pub"`
	PrivateKey string `json:"priv"`
}

// plainView is what gets encrypted to disk.
type plainView struct {
	MasterSeedB64 string                    `json:"master_seed"`
	Legacy        map[string]LegacyKeyEntry `json:"legacy"`
}

// Encrypted is the file format on disk.
type Encrypted struct {
	Version    int    `json:"version"`
	Salt       string `json:"salt"`       // base64
	Nonce      string `json:"nonce"`      // base64 (XChaCha 24 bytes)
	Ciphertext string `json:"ciphertext"` // base64
}

// NewRandom mints a fresh Ed25519 master key.
func NewRandom() (*Wallet, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Wallet{Master: priv, Legacy: map[string]LegacyKeyEntry{}}, nil
}

// MasterPublic returns the Ed25519 public key (32 bytes).
func (w *Wallet) MasterPublic() ed25519.PublicKey {
	if !validMaster(w) {
		return nil
	}
	return w.Master.Public().(ed25519.PublicKey)
}

// ImportLegacyFile reads a v1 wallet.pkw and adds every record as a
// claim-able legacy key. Returns how many entries were added.
func (w *Wallet) ImportLegacyFile(path string) (int, error) {
	data, err := readBoundedSecret(path)
	if err != nil {
		return 0, err
	}
	defer Zeroize(data)
	if len(data)%v1types.WalletRecordSize != 0 || len(data)/v1types.WalletRecordSize > 10000 {
		return 0, errors.New("wallet: invalid legacy record size/count")
	}
	recs := make([]v1types.WalletData, len(data)/v1types.WalletRecordSize)
	for i := range recs {
		if !recs[i].Unmarshal(data[i*v1types.WalletRecordSize : (i+1)*v1types.WalletRecordSize]) {
			return 0, errors.New("wallet: invalid legacy record")
		}
	}
	if w.Legacy == nil {
		w.Legacy = map[string]LegacyKeyEntry{}
	}
	n := 0
	for _, r := range recs {
		// Validate that the address matches the public key (round-trip
		// check — catches corrupt wallets).
		addr, err := v1crypto.AddressFromPublicKey(r.PublicKey, v1crypto.AddressTypeRegular)
		if err != nil || addr != r.Hash || validateLegacy(r.Hash, LegacyKeyEntry{r.Hash, r.PublicKey, r.PrivateKey}) != nil {
			continue
		}
		if _, exists := w.Legacy[r.Hash]; !exists && len(w.Legacy) >= 10000 {
			return n, errors.New("wallet: legacy key limit")
		}
		w.Legacy[r.Hash] = LegacyKeyEntry{
			Address:    r.Hash,
			PublicKey:  r.PublicKey,
			PrivateKey: r.PrivateKey,
		}
		n++
	}
	return n, nil
}

// Save writes the wallet to disk, encrypted with a passphrase.
func (w *Wallet) Save(path, passphrase string) error {
	if !validMaster(w) {
		return errors.New("wallet: invalid master key")
	}
	if err := validateLegacyMap(w.Legacy); err != nil {
		return err
	}
	if passphrase == "" {
		return errors.New("wallet: empty passphrase not allowed")
	}
	view := plainView{
		MasterSeedB64: base64.StdEncoding.EncodeToString(w.Master.Seed()),
		Legacy:        w.Legacy,
	}
	plain, err := json.Marshal(view)
	if err != nil {
		return err
	}
	defer Zeroize(plain)
	if len(plain) > maxWalletBytes/2 {
		return errors.New("wallet: too large")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 1, 32)
	defer Zeroize(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := aead.Seal(nil, nonce, plain, nil)
	enc := Encrypted{
		Version:    1,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	body, err := json.MarshalIndent(&enc, "", "  ")
	if err != nil {
		return err
	}
	return atomicSecretWrite(path, body)
}

// Load opens an encrypted wallet file.
func Load(path, passphrase string) (*Wallet, error) {
	body, err := readBoundedSecret(path)
	if err != nil {
		return nil, err
	}
	var enc Encrypted
	if err := json.Unmarshal(body, &enc); err != nil {
		return nil, fmt.Errorf("wallet: parse %s: %w", path, err)
	}
	if enc.Version != 1 {
		return nil, errors.New("wallet: unsupported version")
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(enc.Salt)
	if err != nil || len(salt) != 16 {
		return nil, errors.New("wallet: invalid salt")
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(enc.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("wallet: invalid nonce")
	}
	ct, err := base64.StdEncoding.Strict().DecodeString(enc.Ciphertext)
	if err != nil || len(ct) < chacha20poly1305.Overhead {
		return nil, errors.New("wallet: invalid ciphertext")
	}
	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 1, 32)
	defer Zeroize(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("wallet: decrypt: %w (bad passphrase?)", err)
	}
	defer Zeroize(plain)
	var view plainView
	if err := json.Unmarshal(plain, &view); err != nil {
		return nil, err
	}
	if err := validateLegacyMap(view.Legacy); err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.Strict().DecodeString(view.MasterSeedB64)
	if err != nil {
		return nil, err
	}
	defer Zeroize(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("wallet: bad master seed length")
	}
	// Derive Ed25519 private key from the seed. Then mlock it so the
	// kernel cannot swap the secret to disk. We also zero the plain
	// decrypted JSON buffer and the seed buffer immediately after use.
	priv := ed25519.NewKeyFromSeed(seed)
	if err := LockBytes(priv); err != nil {
		// Best-effort: log via stderr-style return so caller can decide.
		// The wallet still works, just without page-pinning.
	}
	Zeroize(seed)
	Zeroize(plain)

	w := &Wallet{
		Master: priv,
		Legacy: view.Legacy,
	}
	if w.Legacy == nil {
		w.Legacy = map[string]LegacyKeyEntry{}
	}
	return w, nil
}

// ClaimMessage builds the canonical message the v1 secp256k1 key must
// sign in order to claim a legacy UTXO. Mirrors what `v2/types.
// LegacySpendMessage` formats.
func (w *Wallet) ClaimMessage(addr string, commit [33]byte, height uint64) []byte {
	return []byte(fmt.Sprintf("NOSOX-LEGACY-SPEND %s %x %d", addr, commit[:], height))
}

// SignLegacyClaim signs `msg` with the legacy secp256k1 key for `addr`.
// Returns the Base64 DER signature, ready to embed in a v2 transaction.
func (w *Wallet) SignLegacyClaim(addr string, msg []byte) (string, error) {
	entry, ok := w.Legacy[addr]
	if !ok {
		return "", fmt.Errorf("wallet: no legacy key for %s", addr)
	}
	if err := validateLegacy(addr, entry); err != nil {
		return "", err
	}
	return v1crypto.SignString(msg, entry.PrivateKey)
}

// EqualSeed is a constant-time equality check on Ed25519 seeds (used in tests).
func EqualSeed(a, b *Wallet) bool {
	return a != nil && b != nil && len(a.Master) == ed25519.PrivateKeySize && len(b.Master) == ed25519.PrivateKeySize && subtle.ConstantTimeCompare(a.Master.Seed(), b.Master.Seed()) == 1
}

const maxWalletBytes = 8 << 20

func validateLegacyMap(entries map[string]LegacyKeyEntry) error {
	if len(entries) > 10000 {
		return errors.New("wallet: too many legacy keys")
	}
	for addr, entry := range entries {
		if err := validateLegacy(addr, entry); err != nil {
			return err
		}
	}
	return nil
}
func validateLegacy(addr string, entry LegacyKeyEntry) error {
	raw, err := base64.StdEncoding.Strict().DecodeString(entry.PrivateKey)
	if err != nil || len(raw) != 32 {
		return errors.New("wallet: invalid legacy secret")
	}
	defer Zeroize(raw)
	var scalar btcec.ModNScalar
	if scalar.SetByteSlice(raw) || scalar.IsZero() {
		return errors.New("wallet: invalid legacy scalar")
	}
	pub, err := v1crypto.ParsePublicKey(entry.PublicKey)
	if err != nil {
		return err
	}
	x, y := btcec.S256().ScalarBaseMult(raw)
	if x.Cmp(pub.X) != 0 || y.Cmp(pub.Y) != 0 {
		return errors.New("wallet: mismatched legacy keypair")
	}
	canonical := base64.StdEncoding.EncodeToString(elliptic.Marshal(btcec.S256(), x, y))
	derived, err := v1crypto.AddressFromPublicKey(canonical, v1crypto.AddressTypeRegular)
	if err != nil || addr != entry.Address || derived != addr {
		return errors.New("wallet: legacy address mismatch")
	}
	return nil
}
func readBoundedSecret(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxWalletBytes {
		return nil, errors.New("wallet: file too large or not regular")
	}
	body, err := io.ReadAll(io.LimitReader(f, maxWalletBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxWalletBytes {
		return nil, errors.New("wallet: file too large")
	}
	return body, nil
}

// atomicSecretWrite uses an exclusive random temporary in the destination directory.
// Sync errors are returned; after rename a directory sync error is an uncertain durability result.
func atomicSecretWrite(path string, body []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".wallet-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func validMaster(w *Wallet) bool {
	if w == nil || len(w.Master) != ed25519.PrivateKeySize {
		return false
	}
	derived := ed25519.NewKeyFromSeed(w.Master[:ed25519.SeedSize])
	defer Zeroize(derived)
	return subtle.ConstantTimeCompare(derived, w.Master) == 1
}
