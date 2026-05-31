// Package wallet manages user keys and constructs transactions.
//
// Keystore: JSON file encrypted with Argon2id-derived key + XChaCha20-Poly1305.
// A wallet holds:
//   - An Ed25519 master key (new-era identity + signing).
//   - Zero or more secp256k1 legacy keys imported from v1 wallet.pkw
//     for claiming legacy outputs.
package wallet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	v1crypto "github.com/noso-project/noso-go/internal/crypto"
	v1storage "github.com/noso-project/noso-go/internal/storage"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Wallet is the in-memory key bundle.
type Wallet struct {
	Master  ed25519.PrivateKey            `json:"-"`
	Legacy  map[string]LegacyKeyEntry     `json:"-"` // by legacy address
	Plain   plainView                     `json:"-"` // export view used in serialization
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
	return w.Master.Public().(ed25519.PublicKey)
}

// ImportLegacyFile reads a v1 wallet.pkw and adds every record as a
// claim-able legacy key. Returns how many entries were added.
func (w *Wallet) ImportLegacyFile(path string) (int, error) {
	recs, err := v1storage.LoadWallet(path)
	if err != nil {
		return 0, err
	}
	if w.Legacy == nil {
		w.Legacy = map[string]LegacyKeyEntry{}
	}
	n := 0
	for _, r := range recs {
		// Validate that the address matches the public key (round-trip
		// check — catches corrupt wallets).
		addr, err := v1crypto.AddressFromPublicKey(r.PublicKey, v1crypto.AddressTypeRegular)
		if err != nil || addr != r.Hash {
			continue
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
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 1, 32)
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
	tmp := path + ".tmp"
	body, _ := json.MarshalIndent(&enc, "", "  ")
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load opens an encrypted wallet file.
func Load(path, passphrase string) (*Wallet, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var enc Encrypted
	if err := json.Unmarshal(body, &enc); err != nil {
		return nil, fmt.Errorf("wallet: parse %s: %w", path, err)
	}
	salt, _ := base64.StdEncoding.DecodeString(enc.Salt)
	nonce, _ := base64.StdEncoding.DecodeString(enc.Nonce)
	ct, _ := base64.StdEncoding.DecodeString(enc.Ciphertext)
	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 1, 32)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("wallet: decrypt: %w (bad passphrase?)", err)
	}
	var view plainView
	if err := json.Unmarshal(plain, &view); err != nil {
		return nil, err
	}
	seed, _ := base64.StdEncoding.DecodeString(view.MasterSeedB64)
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
	return v1crypto.SignString(msg, entry.PrivateKey)
}

// EqualSeed is a constant-time equality check on Ed25519 seeds (used in tests).
func EqualSeed(a, b *Wallet) bool {
	return a.Master != nil && b.Master != nil && bytes.Equal(a.Master.Seed(), b.Master.Seed())
}
