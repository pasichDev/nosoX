package wallet

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/pasichDev/noso-go/v2/legacyclaim"
	"testing"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"

	v1crypto "github.com/pasichDev/noso-go/internal/crypto"
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
	tx, plain, err := w.BuildLegacyClaimV4(LegacyClaimContext{Network: types.NetworkMagicTestnet, Genesis: sha256.Sum256([]byte("synthetic trusted genesis"))}, types.Output{Features: types.OutputFeaturesLegacy, Commit: commit, LegacyAddress: addr, LegacyAmount: balance})
	if err != nil {
		t.Fatal(err)
	}
	assertV4Leg(t, tx)
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

	tx, plain, err := w.BuildGVTRedeemV4(LegacyClaimContext{Network: types.NetworkMagicTestnet, Genesis: sha256.Sum256([]byte("synthetic trusted genesis"))}, types.Output{Features: types.OutputFeaturesLegacyGVT, Commit: commit, LegacyAddress: addr, LegacyAmount: types.GVTBaseValue, GVTNumber: slot})
	if err != nil {
		t.Fatal(err)
	}
	assertV4Leg(t, tx)
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

// Identity-preserving transfers would mint non-genesis LegacyGVT outputs and
// have no reviewed authorization procedure. Reject the old API explicitly;
// positive redemption coverage remains above under mandatory v4 context.
func TestOldLegacyBuildersRequireContext(t *testing.T) {
	w, _ := NewRandom()
	addr, _, commit, balance := seedLegacyKey(t, w)
	if tx, _, err := w.BuildLegacyClaim(addr, balance, commit, 100); !errors.Is(err, ErrLegacyContextRequired) || tx != nil {
		t.Fatal("old claim API must reject")
	}
	if tx, _, err := w.BuildGVTRedeem(7, addr, commit, 100); !errors.Is(err, ErrLegacyContextRequired) || tx != nil {
		t.Fatal("old redeem API must reject")
	}
	if tx, err := w.BuildGVTTransfer(7, addr, commit, [32]byte{}, 100); !errors.Is(err, ErrGVTTransferUnsupported) || tx != nil {
		t.Fatal("GVT identity transfer must reject")
	}
}

func assertV4Leg(t *testing.T, tx *types.Transaction) {
	t.Helper()
	in := tx.Inputs[0]
	out := tx.Outputs[0]
	k := tx.Kernels[0]
	if in.LegacyOutputID != types.OutputID(&out) || in.LegacyKernelID != types.KernelID(&k) || k.Features != types.KernelFeaturesLegacyClaim || k.Fee != 0 || k.LockHeight != 0 {
		t.Fatal("invalid explicit leg")
	}
	ctx := legacyclaim.Context{Network: types.NetworkMagicTestnet, Genesis: sha256.Sum256([]byte("synthetic trusted genesis")), DestinationTransaction: legacyclaim.DestinationDigest(in.LegacyOutputID, in.LegacyKernelID)}
	if err := legacyclaim.Verify(ctx, legacyclaim.Source{Commitment: in.Commit, Address: in.LegacyAddr, Amount: in.LegacyAmount}, legacyclaim.Proof{PublicKeyBase64: in.LegacyPubKey, SignatureBase64: in.LegacySig}); err != nil {
		t.Fatal(err)
	}
	difference, err := v2crypto.PointSubtract(out.Commit, in.Commit)
	if err != nil || difference != k.Excess {
		t.Fatal("leg conservation failed")
	}
	if !v2crypto.VerifyRange(out.Commit, out.RangeProof) {
		t.Fatal("range proof invalid")
	}
}
