package wallet

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/legacyclaim"
	"github.com/pasichDev/noso-go/v2/types"
)

// LegacyClaimContext identifies an explicitly trusted deployment. It must come
// from the target chain's pinned genesis and network, not an untrusted peer.
type LegacyClaimContext struct {
	Network uint32
	Genesis types.Hash
}

// BuildLegacyClaimV4 converts one authenticated legacy source into a Plain
// output. The actual imported historical key signs the exact destination leg.
// This establishes ownership, not historical issuance or mainnet eligibility.
func (w *Wallet) BuildLegacyClaimV4(ctx LegacyClaimContext, source types.Output) (*types.Transaction, PlainOutput, error) {
	if source.Features != types.OutputFeaturesLegacy {
		return nil, PlainOutput{}, errors.New("wallet: expected legacy balance source")
	}
	return w.buildLegacyClaimV4(ctx, source)
}

// BuildGVTRedeemV4 redeems the existing 700-NOSO GVT allocation value unchanged.
// GVT transfers preserving slot identity remain unsupported by this procedure.
func (w *Wallet) BuildGVTRedeemV4(ctx LegacyClaimContext, source types.Output) (*types.Transaction, PlainOutput, error) {
	if source.Features != types.OutputFeaturesLegacyGVT || source.GVTNumber >= 100 || source.LegacyAmount != types.GVTBaseValue {
		return nil, PlainOutput{}, errors.New("wallet: invalid legacy GVT source")
	}
	return w.buildLegacyClaimV4(ctx, source)
}

func (w *Wallet) buildLegacyClaimV4(ctx LegacyClaimContext, source types.Output) (*types.Transaction, PlainOutput, error) {
	if w == nil || ctx.Network == 0 || ctx.Genesis.IsZero() || source.LegacyAmount <= 0 || len(source.RangeProof) != 0 {
		return nil, PlainOutput{}, errors.New("wallet: invalid claim context/source")
	}
	entry, ok := w.Legacy[source.LegacyAddress]
	if !ok {
		return nil, PlainOutput{}, errors.New("wallet: missing imported legacy key")
	}
	if err := validateLegacy(source.LegacyAddress, entry); err != nil {
		return nil, PlainOutput{}, err
	}
	secret, err := base64.StdEncoding.Strict().DecodeString(entry.PrivateKey)
	defer Zeroize(secret)
	if err != nil || len(secret) != 32 || base64.StdEncoding.EncodeToString(secret) != entry.PrivateKey {
		return nil, PlainOutput{}, errors.New("wallet: noncanonical legacy secret")
	}
	var scalar secp.ModNScalar
	if scalar.SetByteSlice(secret) || scalar.IsZero() {
		return nil, PlainOutput{}, errors.New("wallet: invalid legacy scalar")
	}
	key := secp.PrivKeyFromBytes(secret)
	defer key.Zero()
	if base64.StdEncoding.EncodeToString(key.PubKey().SerializeUncompressed()) != entry.PublicKey {
		return nil, PlainOutput{}, errors.New("wallet: noncanonical historical public key")
	}
	blind := sha256.Sum256([]byte("NosoX legacy blind " + source.LegacyAddress))
	if source.Features == types.OutputFeaturesLegacyGVT {
		blind = sha256.Sum256([]byte(fmt.Sprintf("NosoX legacy GVT blind %02d %s", source.GVTNumber, source.LegacyAddress)))
	}
	expected, err := v2crypto.PedersenCommit(source.LegacyAmount, blind[:])
	if err != nil || expected != source.Commit {
		return nil, PlainOutput{}, errors.New("wallet: source does not match canonical legacy allocation commitment")
	}
	out, err := NewPlainOutput(source.LegacyAmount)
	if err != nil {
		return nil, PlainOutput{}, err
	}
	excessScalar := scalarSub(out.Blinding[:], blind[:])
	defer Zeroize(excessScalar[:])
	excess, err := v2crypto.PublicFromScalar(excessScalar[:])
	if err != nil {
		return nil, PlainOutput{}, err
	}
	kernel := types.Kernel{Features: types.KernelFeaturesLegacyClaim, Excess: excess}
	kernelID := types.KernelID(&kernel)
	kernel.ExcessSig, err = v2crypto.SchnorrSign(excessScalar[:], kernelID[:])
	if err != nil {
		return nil, PlainOutput{}, err
	}
	outputID := types.OutputID(&out.Output)
	claimCtx := legacyclaim.Context{Network: ctx.Network, Genesis: ctx.Genesis, DestinationTransaction: legacyclaim.DestinationDigest(outputID, kernelID)}
	trusted := legacyclaim.Source{Commitment: source.Commit, Address: source.LegacyAddress, Amount: source.LegacyAmount}
	digest, err := legacyclaim.Digest(claimCtx, trusted)
	if err != nil {
		return nil, PlainOutput{}, err
	}
	proof := legacyclaim.Proof{PublicKeyBase64: entry.PublicKey, SignatureBase64: base64.StdEncoding.EncodeToString(ecdsa.Sign(key, digest[:]).Serialize())}
	if err := legacyclaim.Verify(claimCtx, trusted, proof); err != nil {
		return nil, PlainOutput{}, err
	}
	input := types.Input{Features: source.Features, Commit: source.Commit, LegacyAddr: source.LegacyAddress, LegacyAmount: source.LegacyAmount, LegacyPubKey: proof.PublicKeyBase64, LegacySig: proof.SignatureBase64, LegacyOutputID: outputID, LegacyKernelID: kernelID}
	return &types.Transaction{Inputs: []types.Input{input}, Outputs: []types.Output{out.Output}, Kernels: []types.Kernel{kernel}}, out, nil
}
