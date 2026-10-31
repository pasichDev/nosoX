// Package wallet manages user keys and constructs transactions.
//
// Keystore: JSON file encrypted with Argon2id-derived key + XChaCha20-Poly1305.
// A wallet holds:
//   - An Ed25519 master key (identity + signing).
package wallet

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
)

// Wallet is the in-memory key bundle.
type Wallet struct {
	Master ed25519.PrivateKey `json:"-"`
	Plain  plainView          `json:"-"` // export view used in serialization
	// LockErr is the mlock failure for Master, if any (page pinning is best effort).
	LockErr error `json:"-"`
	// Legacy is set by Load when the file was a version 1 keystore (weak KDF,
	// no authenticated parameters). Call Upgrade to rewrite it as version 2.
	Legacy bool `json:"-"`
}

// plainView is what gets encrypted to disk.
type plainView struct {
	MasterSeedB64 string `json:"master_seed"`
}

// Encrypted is the file format on disk (keystore and state share it).
type Encrypted struct {
	Version    int        `json:"version"`
	KDF        *KDFParams `json:"kdf,omitempty"` // version 2: Argon2id parameters
	Salt       string     `json:"salt"`          // base64
	Nonce      string     `json:"nonce"`         // base64 (XChaCha 24 bytes)
	Ciphertext string     `json:"ciphertext"`    // base64
}

// NewRandom mints a fresh Ed25519 master key.
func NewRandom() (*Wallet, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Wallet{Master: priv}, nil
}

// MasterPublic returns the Ed25519 public key (32 bytes).
func (w *Wallet) MasterPublic() ed25519.PublicKey {
	if !validMaster(w) {
		return nil
	}
	return w.Master.Public().(ed25519.PublicKey)
}

// seal encrypts the wallet as a version 2 envelope.
func (w *Wallet) seal(passphrase string) ([]byte, error) {
	view := plainView{MasterSeedB64: base64.StdEncoding.EncodeToString(w.Master.Seed())}
	plain, err := json.Marshal(view)
	if err != nil {
		return nil, err
	}
	defer Zeroize(plain)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	kdf := kdfDefault
	key := deriveKey(passphrase, salt, kdf)
	defer Zeroize(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plain, envelopeAAD(labelKeystore, envelopeV2, salt, kdf))
	enc := Encrypted{
		Version:    envelopeV2,
		KDF:        &kdf,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	return json.MarshalIndent(&enc, "", "  ")
}

// Create writes a NEW wallet file. It refuses to touch an existing wallet or
// an existing state file for that path (an overwrite would orphan the old
// master key and everything the state file holds), applies the passphrase
// policy, and never replaces anything: the file is published with a hard link,
// which fails if the name is taken.
func (w *Wallet) Create(path, passphrase string) error {
	if !validMaster(w) {
		return errors.New("wallet: invalid master key")
	}
	if err := ValidatePassphrase(passphrase); err != nil {
		return err
	}
	for _, p := range []string{path, StatePath(path)} {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("wallet: %s already exists; choose a new path (an existing wallet is never overwritten)", p)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	body, err := w.seal(passphrase)
	if err != nil {
		return err
	}
	return atomicSecretCreate(path, body)
}

// Save (over)writes the wallet file, encrypted with a passphrase. It is the
// path for deliberate replacement; new wallets use Create. It is NOT a
// passphrase change: it re-keys only the keystore, and the output state
// (<wallet>.outputs) stays keyed with the old passphrase and would no longer
// open. There is no re-key command.
func (w *Wallet) Save(path, passphrase string) error {
	if !validMaster(w) {
		return errors.New("wallet: invalid master key")
	}
	if err := ValidatePassphrase(passphrase); err != nil {
		return err
	}
	body, err := w.seal(passphrase)
	if err != nil {
		return err
	}
	return atomicSecretWrite(path, body)
}

// Upgrade rewrites a version 1 keystore as version 2 with the same passphrase
// (the passphrase policy is not applied: the file was already encrypted with it).
func (w *Wallet) Upgrade(path, passphrase string) error {
	if !validMaster(w) {
		return errors.New("wallet: invalid master key")
	}
	if passphrase == "" {
		return errors.New("wallet: empty passphrase not allowed")
	}
	body, err := w.seal(passphrase)
	if err != nil {
		return err
	}
	// The old file may hold more than the master seed (imported legacy keys that
	// this format does not carry). Keep it, byte for byte, before replacing it.
	if _, err := BackupBeforeUpgrade(path); err != nil {
		return fmt.Errorf("wallet: not upgrading, the old keystore could not be backed up: %w", err)
	}
	if err := atomicSecretWrite(path, body); err != nil {
		return err
	}
	w.Legacy = false
	return nil
}

// UpgradeBackupSuffix names the copy of a version 1 keystore kept by Upgrade.
const UpgradeBackupSuffix = ".v1.bak"

// BackupBeforeUpgrade copies the keystore at path to path+UpgradeBackupSuffix
// (mode 0600, fsynced, never overwriting an earlier backup) and returns the
// backup path. The copy keeps the weak version 1 encryption.
func BackupBeforeUpgrade(path string) (string, error) {
	bak := path + UpgradeBackupSuffix
	if _, err := os.Lstat(bak); err == nil {
		return bak, nil // an earlier backup is never replaced
	} else if !os.IsNotExist(err) {
		return "", err
	}
	body, err := readBoundedSecret(path)
	if err != nil {
		return "", err
	}
	defer Zeroize(body)
	return bak, atomicSecretCreate(bak, body)
}

// Load opens an encrypted wallet file. Version 1 files are accepted (and
// flagged Legacy) so an existing wallet can be migrated; anything else is
// rejected.
func Load(path, passphrase string) (*Wallet, error) {
	body, err := readBoundedSecret(path)
	if err != nil {
		return nil, err
	}
	var enc Encrypted
	if err := json.Unmarshal(body, &enc); err != nil {
		return nil, fmt.Errorf("wallet: parse %s: %w", path, err)
	}
	var kdf KDFParams
	var aad []byte
	legacy := false
	salt, err := base64.StdEncoding.Strict().DecodeString(enc.Salt)
	if err != nil || len(salt) != 16 {
		return nil, errors.New("wallet: invalid salt")
	}
	switch enc.Version {
	case envelopeV1:
		kdf, legacy = legacyKDF, true
	case envelopeV2:
		if enc.KDF == nil {
			return nil, errors.New("wallet: missing key derivation parameters")
		}
		kdf = *enc.KDF
		if err := kdf.validate(); err != nil {
			return nil, err
		}
		aad = envelopeAAD(labelKeystore, envelopeV2, salt, kdf)
	default:
		return nil, errors.New("wallet: unsupported version")
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(enc.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("wallet: invalid nonce")
	}
	ct, err := base64.StdEncoding.Strict().DecodeString(enc.Ciphertext)
	if err != nil || len(ct) < chacha20poly1305.Overhead {
		return nil, errors.New("wallet: invalid ciphertext")
	}
	key := deriveKey(passphrase, salt, kdf)
	defer Zeroize(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("wallet: decrypt: %w (bad passphrase?)", err)
	}
	defer Zeroize(plain)
	var view plainView
	if err := json.Unmarshal(plain, &view); err != nil {
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
	// Best effort: the wallet works without page pinning, but the caller can
	// inspect LockErr and warn.
	lockErr := LockBytes(priv)
	Zeroize(seed)
	Zeroize(plain)

	return &Wallet{Master: priv, LockErr: lockErr, Legacy: legacy}, nil
}

// EqualSeed is a constant-time equality check on Ed25519 seeds (used in tests).
func EqualSeed(a, b *Wallet) bool {
	return a != nil && b != nil && len(a.Master) == ed25519.PrivateKeySize && len(b.Master) == ed25519.PrivateKeySize && subtle.ConstantTimeCompare(a.Master.Seed(), b.Master.Seed()) == 1
}

const maxWalletBytes int64 = 8 << 20

func readBoundedSecret(path string) ([]byte, error) { return readBounded(path, maxWalletBytes) }

// readBounded reads a regular file of at most limit bytes.
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("wallet: file too large or not regular")
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("wallet: file too large")
	}
	return body, nil
}

// writeTemp writes body to an exclusive random temporary (0600 on Unix) in the
// destination directory and syncs it.
func writeTemp(path string, body []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".wallet-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// ErrWrittenUnconfirmed means the new file is in place but a later durability
// step failed: the data is NOT lost and not rolled back, only its survival of a
// crash is unconfirmed. Callers must not report such a write as "not written".
var ErrWrittenUnconfirmed = errors.New("wallet: file written but its durability could not be confirmed")

// atomicSecretWrite replaces path with body: exclusive temporary + fsync +
// rename + directory sync (Windows: write-through rename). Errors before the
// rename mean nothing changed; an error after it wraps ErrWrittenUnconfirmed.
func atomicSecretWrite(path string, body []byte) error {
	tmp, err := writeTemp(path, body)
	if err != nil {
		return err
	}
	if err := replaceFile(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := syncDirFn(path); err != nil {
		return fmt.Errorf("%w: %v", ErrWrittenUnconfirmed, err)
	}
	return nil
}

// atomicSecretCreate publishes body at path only if path does not exist.
func atomicSecretCreate(path string, body []byte) error {
	tmp, err := writeTemp(path, body)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, path); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("wallet: %s already exists", path)
		}
		return err
	}
	if err := syncDirFn(path); err != nil {
		return fmt.Errorf("%w: %v", ErrWrittenUnconfirmed, err)
	}
	return nil
}

func validMaster(w *Wallet) bool {
	if w == nil || len(w.Master) != ed25519.PrivateKeySize {
		return false
	}
	derived := ed25519.NewKeyFromSeed(w.Master[:ed25519.SeedSize])
	defer Zeroize(derived)
	return subtle.ConstantTimeCompare(derived, w.Master) == 1
}
