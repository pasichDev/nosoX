package chain

import (
	"errors"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/legacyclaim"
	"github.com/pasichDev/noso-go/v2/types"
)

// validateLegacyClaims authorizes explicit claim legs in the flat block body.
// No transaction boundary, claimant metadata, height or nonce establishes trust.
// Active source state and the canonical stored genesis choose the context.
func (c *Chain) validateLegacyClaims(b *types.Block) error {
	outputs := make(map[types.Hash]*types.Output, len(b.Outputs))
	for i := range b.Outputs {
		o := &b.Outputs[i]
		id := types.OutputID(o)
		if _, exists := outputs[id]; exists {
			return errors.New("chain: duplicate claim destination ID")
		}
		outputs[id] = o
	}
	kernels := make(map[types.Hash]*types.Kernel, len(b.Kernels))
	for i := range b.Kernels {
		k := &b.Kernels[i]
		id := types.KernelID(k)
		if _, exists := kernels[id]; exists {
			return errors.New("chain: duplicate claim kernel ID")
		}
		kernels[id] = k
	}
	usedOutputs := map[types.Hash]bool{}
	usedKernels := map[types.Hash]bool{}
	var context *legacyclaim.Context
	for _, in := range b.Inputs {
		if in.Features != types.OutputFeaturesLegacy && in.Features != types.OutputFeaturesLegacyGVT {
			continue
		}
		if context == nil {
			g, err := c.store.BlockAt(0)
			if err != nil {
				return err
			}
			tip, ok := c.store.Tip()
			if !ok || tip.NetworkMagic == 0 || g.Header.NetworkMagic != tip.NetworkMagic {
				return errors.New("chain: unavailable claim network context")
			}
			context = &legacyclaim.Context{Network: tip.NetworkMagic, Genesis: types.HeaderID(&g.Header)}
		}
		source, ok := c.store.UTXOByCommit(in.Commit)
		if !ok {
			return ErrDoubleSpend
		}
		if source.Features != in.Features || source.LegacyAddress != in.LegacyAddr || source.LegacyAmount != in.LegacyAmount {
			return errors.New("chain: untrusted claim metadata")
		}
		o, outputExists := outputs[in.LegacyOutputID]
		k, kernelExists := kernels[in.LegacyKernelID]
		if !outputExists || !kernelExists || in.LegacyOutputID.IsZero() || in.LegacyKernelID.IsZero() || usedOutputs[in.LegacyOutputID] || usedKernels[in.LegacyKernelID] {
			return errors.New("chain: absent or shared claim leg")
		}
		if o.Features != types.OutputFeaturesPlain || k.Features != types.KernelFeaturesLegacyClaim || k.Fee != 0 || k.LockHeight != 0 {
			return errors.New("chain: invalid claim leg features")
		}
		context.DestinationTransaction = legacyclaim.DestinationDigest(in.LegacyOutputID, in.LegacyKernelID)
		if err := legacyclaim.Verify(*context, legacyclaim.Source{Commitment: source.Commit, Address: source.LegacyAddress, Amount: source.LegacyAmount}, legacyclaim.Proof{PublicKeyBase64: in.LegacyPubKey, SignatureBase64: in.LegacySig}); err != nil {
			return err
		}
		difference, err := v2crypto.PointSubtract(o.Commit, source.Commit)
		if err != nil || difference != k.Excess {
			return errors.New("chain: claim leg does not conserve source value")
		}
		if !v2crypto.SchnorrVerify(k.Excess, in.LegacyKernelID[:], k.ExcessSig) {
			return errors.New("chain: invalid claim kernel authorization")
		}
		usedOutputs[in.LegacyOutputID], usedKernels[in.LegacyKernelID] = true, true
	}
	for id, k := range kernels {
		if k.Features == types.KernelFeaturesLegacyClaim && !usedKernels[id] {
			return errors.New("chain: unreferenced legacy claim kernel")
		}
	}
	return nil
}
