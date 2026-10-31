package wallet

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestLoadRejectsMalformedEnvelopeWithoutPanic(t *testing.T) {
	for _, e := range []Encrypted{{Version: 1}, {Version: 2, Salt: "AA==", Nonce: "AA==", Ciphertext: "AA=="}} {
		p := filepath.Join(t.TempDir(), "wallet.json")
		b, _ := json.Marshal(e)
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("malformed wallet panicked: %v", r)
				}
			}()
			if _, err := Load(p, "test"); err == nil {
				t.Error("accepted malformed envelope")
			}
		}()
	}
}
func TestSaveIgnoresAttackerStaticTempAndProtectsMode(t *testing.T) {
	w, err := NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0644); err != nil {
		t.Fatal(err)
	}
	// A symlink at the old static temp name AND one at the wallet path itself,
	// both pointing at a file the attacker wants overwritten.
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Skip(err)
	}
	if err := os.Symlink(victim, path); err != nil {
		t.Skip(err)
	}
	if err := w.Save(path, testPass); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(victim)
	if string(b) != "untouched" {
		t.Fatal("a planted symlink was followed")
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("the wallet path is still a symlink: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".wallet-*")); len(left) != 0 {
		t.Fatalf("temporary files left behind: %v", left)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	loaded, err := Load(path, testPass)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if !EqualSeed(w, loaded) {
		t.Fatal("saved seed differs")
	}
	if _, err := Load(path, "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
}
func TestSecretReadBoundsAndInvalidMaster(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxWalletBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Load(path, "test"); err == nil {
		t.Fatal("oversized wallet accepted")
	}
	if err := (&Wallet{}).Save(path, "test"); err == nil {
		t.Fatal("invalid master accepted")
	}
}
func TestCoinbaseFailedPersistenceDoesNotPublishRecord(t *testing.T) {
	store := &CoinbaseStore{path: filepath.Join(t.TempDir(), "absent", "coins")}
	if _, err := store.Allocate(1, 5); err == nil {
		t.Fatal("expected missing directory error")
	}
	if len(store.All()) != 0 {
		t.Fatal("failed allocation retained in memory")
	}
}
func TestCoinbaseStoreRejectsCorruptRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coins")
	body, _ := json.Marshal([]CoinbaseRecord{{Amount: 1}})
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCoinbaseStore(path); err == nil {
		t.Fatal("corrupt coinbase record accepted")
	}
}

// Keystores written before an old key section was dropped carry an extra
// JSON key. It must be ignored on load, not rejected, and the master
// key must be intact; re-saving must not write the section back.
func TestLoadIgnoresUnknownKeystoreSection(t *testing.T) {
	w, err := NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	plain, err := json.Marshal(map[string]any{
		"master_seed": base64.StdEncoding.EncodeToString(w.Master.Seed()),
		"legacy": map[string]any{"Nobsolete": map[string]string{
			"address": "Nobsolete", "pub": "bogus", "priv": "bogus",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	key := argon2.IDKey([]byte(testPass), salt, 1, 64*1024, 1, 32)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	enc := Encrypted{
		Version:    1,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, nil)),
	}
	body, _ := json.Marshal(enc)
	path := filepath.Join(t.TempDir(), "old-wallet.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path, testPass)
	if err != nil {
		t.Fatalf("keystore with obsolete legacy section rejected: %v", err)
	}
	defer loaded.Close()
	if !EqualSeed(w, loaded) {
		t.Fatal("master seed differs after load")
	}
	if err := loaded.Save(path, testPass); err != nil {
		t.Fatal(err)
	}
	again, err := Load(path, testPass)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if !EqualSeed(w, again) {
		t.Fatal("master seed differs after re-save")
	}
}
