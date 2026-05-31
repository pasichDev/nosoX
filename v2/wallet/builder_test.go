package wallet

import (
	"crypto/sha256"
	"fmt"
	"testing"

	v2crypto "github.com/noso-project/noso-go/v2/crypto"
	"github.com/noso-project/noso-go/v2/types"

	v1crypto "github.com/noso-project/noso-go/internal/crypto"
)

// helper: synthesize a v1 keypair + address into the wallet's legacy
// section so we can drive the claim builder in isolation.
func seedLegacyKey(t *testing.T, w *Wallet) (addr string, blind [32]byte, commit types.Commitment, balance int64) {
	t.Helper()
	kp, err := v1crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	addr, err = v1crypto.AddressFromPublicKey(kp.PublicKey, v1crypto.AddressTypeRegular)
	if err != nil {
		t.Fatal(err)
	}
	w.Legacy[addr] = LegacyKeyEntry{
		Address:    addr,
		PublicKey:  kp.PublicKey,
		PrivateKey: kp.PrivateKey,
	}
	balance = 1_000_000_000
	blind = sha256.Sum256([]byte("NosoX legacy blind " + addr))
	commit, err = v2crypto.PedersenCommit(balance, blind[:])
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestLegacyClaimRoundTrip(t *testing.T) {
	w, _ := NewRandom()
	addr, _, commit, balance := seedLegacyKey(t, w)
	tx, plain, err := w.BuildLegacyClaim(addr, balance, commit, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.Inputs) != 1 || len(tx.Outputs) != 1 || len(tx.Kernels) != 1 {
		t.Fatalf("shape: ins=%d outs=%d kernels=%d", len(tx.Inputs), len(tx.Outputs), len(tx.Kernels))
	}
	if tx.Inputs[0].Features != types.OutputFeaturesLegacy {
		t.Errorf("input features = %d, want Legacy", tx.Inputs[0].Features)
	}
	if tx.Outputs[0].Features != types.OutputFeaturesPlain {
		t.Errorf("output features = %d, want Plain", tx.Outputs[0].Features)
	}
	if plain.Value != balance {
		t.Errorf("plain value = %d, want %d", plain.Value, balance)
	}
	// The kernel excess sig must verify against the excess pubkey.
	k := &tx.Kernels[0]
	kHash := types.KernelID(k)
	if !v2crypto.SchnorrVerify(k.Excess, kHash[:], k.ExcessSig) {
		t.Fatal("kernel excess Schnorr sig fails to verify")
	}
	// Range proof on the new Plain output must verify.
	if !v2crypto.VerifyRange(tx.Outputs[0].Commit, tx.Outputs[0].RangeProof) {
		t.Fatal("output range proof fails to verify")
	}
}

func TestGVTRedeemRoundTrip(t *testing.T) {
	w, _ := NewRandom()
	kp, _ := v1crypto.GenerateKeyPair()
	addr, _ := v1crypto.AddressFromPublicKey(kp.PublicKey, v1crypto.AddressTypeRegular)
	w.Legacy[addr] = LegacyKeyEntry{Address: addr, PublicKey: kp.PublicKey, PrivateKey: kp.PrivateKey}

	const slot = uint8(7)
	blind := sha256.Sum256([]byte(fmt.Sprintf("NosoX legacy GVT blind %02d %s", slot, addr)))
	commit, _ := v2crypto.PedersenCommit(types.GVTBaseValue, blind[:])

	tx, plain, err := w.BuildGVTRedeem(slot, addr, commit, 200)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Value != types.GVTBaseValue {
		t.Errorf("redeemed value = %d, want %d", plain.Value, types.GVTBaseValue)
	}
	if tx.Inputs[0].Features != types.OutputFeaturesLegacyGVT {
		t.Errorf("input features = %d, want LegacyGVT", tx.Inputs[0].Features)
	}
	k := &tx.Kernels[0]
	kHash := types.KernelID(k)
	if !v2crypto.SchnorrVerify(k.Excess, kHash[:], k.ExcessSig) {
		t.Fatal("redeem kernel sig fails to verify")
	}
}

func TestGVTTransferPreservesIdentity(t *testing.T) {
	w, _ := NewRandom()
	kp, _ := v1crypto.GenerateKeyPair()
	addr, _ := v1crypto.AddressFromPublicKey(kp.PublicKey, v1crypto.AddressTypeRegular)
	w.Legacy[addr] = LegacyKeyEntry{Address: addr, PublicKey: kp.PublicKey, PrivateKey: kp.PrivateKey}

	const slot = uint8(13)
	srcBlind := sha256.Sum256([]byte(fmt.Sprintf("NosoX legacy GVT blind %02d %s", slot, addr)))
	srcCommit, _ := v2crypto.PedersenCommit(types.GVTBaseValue, srcBlind[:])

	var recvBlind [32]byte
	recvBlind[0] = 0xaa
	recvBlind[31] = 0x01

	tx, err := w.BuildGVTTransfer(slot, addr, srcCommit, recvBlind, 300)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Outputs[0].Features != types.OutputFeaturesLegacyGVT {
		t.Errorf("transferred output features = %d, want LegacyGVT", tx.Outputs[0].Features)
	}
	if tx.Outputs[0].GVTNumber != slot {
		t.Errorf("transferred GVT slot = %d, want %d", tx.Outputs[0].GVTNumber, slot)
	}
	// New commit must equal Pedersen(GVTBaseValue, recvBlind)
	want, _ := v2crypto.PedersenCommit(types.GVTBaseValue, recvBlind[:])
	if tx.Outputs[0].Commit != want {
		t.Error("transferred commit mismatch")
	}
}
