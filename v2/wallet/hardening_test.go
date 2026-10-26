package wallet

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
func TestSlateRejectsMissingAndMalformedPartials(t *testing.T) {
	s := NewOfferSlate(1, 0, 0, "")
	if s.VerifyPartials() {
		t.Error("empty signatures accepted")
	}
	s.PartSigs = []PartialSig{{By: RoleSender, Pub: []byte{1}, Sig: make([]byte, 64)}}
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("malformed public key panicked: %v", r)
		}
	}()
	if s.VerifyPartials() {
		t.Error("malformed partial accepted")
	}
}
func TestSlateSignatureBindsBodyFields(t *testing.T) {
	s := NewOfferSlate(1, 0, 0, "")
	_, priv, _ := ed25519.GenerateKey(nil)
	s.SignPartial(RoleSender, priv)
	s.Memo = "changed"
	if s.VerifyPartials() {
		t.Error("memo mutation retained signature validity")
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
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Skip(err)
	}
	if err := w.Save(path, "password"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(victim)
	if string(b) != "untouched" {
		t.Fatal("static temp followed symlink")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	loaded, err := Load(path, "password")
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
func TestSlateRejectsOverflowAndUnsupportedVersion(t *testing.T) {
	s := NewOfferSlate(1, ^uint64(0), 0, "")
	if err := s.CheckBalance(); err == nil {
		t.Fatal("overflow fee accepted")
	}
	s.Fee = 0
	s.Version = 2
	encoded, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(encoded); err == nil {
		t.Fatal("unsupported version accepted")
	}
	s.Version = 1
	s.Stage = StageOffer
	encoded, err = s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base58Decode(encoded[len("SLATEPACK1."):])
	raw[0] = byte(StageFinal)
	if _, err := Decode("SLATEPACK1." + base58Encode(raw)); err == nil {
		t.Fatal("header/body stage mismatch accepted")
	}
}

func TestSlateSignatureBindsSignerRole(t *testing.T) {
	s := NewOfferSlate(1, 0, 0, "")
	_, priv, _ := ed25519.GenerateKey(nil)
	if err := s.SignPartial(RoleSender, priv); err != nil {
		t.Fatal(err)
	}
	s.PartSigs[0].By = RoleReceiver
	if s.VerifyPartials() {
		t.Fatal("signer role could be relabeled")
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
