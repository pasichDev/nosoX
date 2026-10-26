package chain

import (
	"errors"
	"fmt"
	"math"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

func cloneBlock(b *types.Block) *types.Block {
	if b == nil {
		return nil
	}
	out := *b
	out.Inputs = append([]types.Input(nil), b.Inputs...)
	out.Outputs = append([]types.Output(nil), b.Outputs...)
	out.Kernels = append([]types.Kernel(nil), b.Kernels...)
	for i := range out.Outputs {
		out.Outputs[i].RangeProof = append([]byte(nil), out.Outputs[i].RangeProof...)
	}
	for i := range out.Kernels {
		out.Kernels[i].ExcessSig = append([]byte(nil), out.Kernels[i].ExcessSig...)
	}
	return &out
}

func validateStructure(b *types.Block) error {
	if b == nil {
		return errors.New("chain: nil block")
	}
	if b.Header.Version != types.BlockVersion {
		return errors.New("chain: unsupported version")
	}
	if b.Header.TotalKernelOffset != (types.Commitment{}) {
		return errors.New("chain: offsets unsupported")
	}
	if b.Header.Difficulty == 0 || b.Header.Timestamp < 0 {
		return errors.New("chain: invalid header")
	}
	if err := bodyBounds(b); err != nil {
		return err
	}
	o, k := types.BlockRoots(b)
	if b.Header.OutputRoot != o || b.Header.KernelRoot != k {
		return errors.New("chain: body roots mismatch")
	}
	return nil
}

func bodyBounds(b *types.Block) error {
	_, err := BodyResourceBytes(b)
	return err
}

func validateGenesis(b *types.Block) error {
	if err := validateStructure(b); err != nil {
		return err
	}
	if b.Header.Height != 0 || !b.Header.PrevHash.IsZero() || len(b.Inputs) != 0 || len(b.Kernels) != 0 {
		return errors.New("chain: invalid trusted genesis")
	}
	seen := map[types.Commitment]bool{}
	addresses := map[string]bool{}
	gvts := map[uint8]bool{}
	for _, o := range b.Outputs {
		if seen[o.Commit] {
			return errors.New("chain: duplicate genesis commitment")
		}
		seen[o.Commit] = true
		if o.Features != types.OutputFeaturesLegacy && o.Features != types.OutputFeaturesLegacyGVT {
			return errors.New("chain: invalid genesis allocation feature")
		}
		if o.LegacyAddress == "" || o.LegacyAmount < 0 || len(o.RangeProof) != 0 {
			return errors.New("chain: invalid genesis allocation")
		}
		if !v2crypto.ValidPublicPoint(o.Commit) {
			return ErrBadOutput
		}
		if o.Features == types.OutputFeaturesLegacy {
			if addresses[o.LegacyAddress] {
				return errors.New("chain: duplicate legacy allocation")
			}
			addresses[o.LegacyAddress] = true
		}
		if o.Features == types.OutputFeaturesLegacyGVT {
			if o.GVTNumber >= 100 || gvts[o.GVTNumber] || o.LegacyAmount != types.GVTBaseValue {
				return errors.New("chain: invalid GVT allocation")
			}
			gvts[o.GVTNumber] = true
		}
	}
	return nil
}

func (c *Chain) verifyHistory(store Store, genesis *types.Block) error {
	if persistent, ok := store.(*BadgerStore); ok {
		return c.streamingVerifyHistory(persistent, genesis)
	}
	g, err := store.BlockAt(0)
	if err != nil {
		return err
	}
	if types.HeaderID(&g.Header) != types.HeaderID(&genesis.Header) {
		return errors.New("chain: stored genesis differs from trusted genesis")
	}
	if err := validateGenesis(g); err != nil {
		return err
	}
	staged := newMemStore()
	if err := staged.WriteBlock(g); err != nil {
		return err
	}
	check := &Chain{store: staged, checkpoints: c.checkpoints, now: c.now}
	tip, ok := store.Tip()
	if !ok {
		return errors.New("chain: invalid persisted tip")
	}
	for h := uint64(1); h <= tip.Height; h++ {
		b, err := store.BlockAt(h)
		if err != nil {
			return err
		}
		if err = check.validate(b); err != nil {
			return fmt.Errorf("chain: invalid persisted block %d: %w", h, err)
		}
		if err = staged.WriteBlock(b); err != nil {
			return err
		}
	}
	if s, ok := store.(*BadgerStore); ok {
		return s.verifyState(staged.orderedBlocks())
	}
	return nil
}

// ValidateTransaction checks admission against the next canonical block state.
// Fee destination outputs and subsidy are constructed separately by the miner.
func (c *Chain) ValidateTransaction(tx *types.Transaction) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if tx == nil {
		return errors.New("chain: nil transaction")
	}
	tip, ok := c.store.Tip()
	if !ok || tip.Height == math.MaxUint64 {
		return errors.New("chain: unavailable tip")
	}
	b := &types.Block{Header: types.BlockHeader{Height: tip.Height + 1}, Inputs: tx.Inputs, Outputs: tx.Outputs, Kernels: tx.Kernels}
	if len(b.Inputs) == 0 || len(b.Outputs) == 0 || len(b.Kernels) == 0 {
		return errors.New("chain: empty transaction")
	}
	if err := bodyBounds(b); err != nil {
		return err
	}
	reserveOutputs, reserveKernels := 0, 0
	if types.BlockReward(b.Header.Height) > 0 {
		reserveOutputs++
		reserveKernels++
	}
	if TotalKernelFee(b) > 0 {
		reserveOutputs++
	}
	if len(b.Outputs)+reserveOutputs > types.MaxBlockOutputs || len(b.Kernels)+reserveKernels > types.MaxBlockKernels {
		return errors.New("chain: transaction leaves no mandatory block capacity")
	}
	n, err := BodyResourceBytes(b)
	if err != nil {
		return err
	}
	if n+uint64(reserveOutputs*128+reserveKernels*(128+65)) > types.MaxBlockBodyBytes {
		return ErrResourceBudget
	}
	return c.validateBody(b, false)
}

func (c *Chain) validateBody(b *types.Block, block bool) error {
	inputs := map[types.Commitment]bool{}
	for i, in := range b.Inputs {
		if !v2crypto.ValidPublicPoint(in.Commit) {
			return ErrBadOutput
		}
		if inputs[in.Commit] {
			return errors.New("chain: duplicate input")
		}
		inputs[in.Commit] = true
		stored, ok := c.store.UTXOByCommit(in.Commit)
		if !ok {
			return ErrDoubleSpend
		}
		if in.Features != stored.Features || in.LegacyAddr != stored.LegacyAddress || in.LegacyAmount != stored.LegacyAmount {
			return errors.New("chain: input metadata mismatch")
		}
		switch stored.Features {
		case types.OutputFeaturesLegacy, types.OutputFeaturesLegacyGVT:
			// Explicit v4 claim legs are checked against trusted state below.
		case types.OutputFeaturesPlain, types.OutputFeaturesCoinbase, types.OutputFeaturesDevFund:
			if in.LegacySig != "" || in.LegacyPubKey != "" || !in.LegacyOutputID.IsZero() || !in.LegacyKernelID.IsZero() || in.LegacyAddr != "" || in.LegacyAmount != 0 {
				return errors.New("chain: unexpected legacy authorization")
			}
		default:
			return errors.New("chain: unsupported input feature")
		}
		if stored.Features == types.OutputFeaturesCoinbase {
			start := uint64(0)
			if b.Header.Height >= types.CoinbaseLock {
				start = b.Header.Height - types.CoinbaseLock + 1
			}
			for h := start; h < b.Header.Height; h++ {
				old, err := c.store.BlockAt(h)
				if err != nil {
					return err
				}
				for _, o := range old.Outputs {
					if o.Commit == in.Commit {
						return fmt.Errorf("chain: immature coinbase input %d", i)
					}
				}
			}
		}
	}
	outputs := map[types.Commitment]bool{}
	cbOuts := 0
	var cb *types.Output
	for i := range b.Outputs {
		o := &b.Outputs[i]
		if !v2crypto.ValidPublicPoint(o.Commit) {
			return ErrBadOutput
		}
		if outputs[o.Commit] || inputs[o.Commit] || c.store.HasOutput(o.Commit) || c.store.HasUTXO(o.Commit) {
			return errors.New("chain: duplicate or existing output")
		}
		outputs[o.Commit] = true
		if o.LegacyAddress != "" || o.LegacyAmount != 0 || o.GVTNumber != 0 {
			return ErrBadOutput
		}
		switch o.Features {
		case types.OutputFeaturesPlain:
			if len(o.RangeProof) == 0 {
				return ErrBadOutput
			}
		case types.OutputFeaturesCoinbase:
			if !block || len(o.RangeProof) != 0 {
				return ErrBadOutput
			}
			cbOuts++
			cb = o
		case types.OutputFeaturesDevFund:
			if !block || len(o.RangeProof) != 0 {
				return ErrBadOutput
			}
		default:
			return ErrBadOutput
		}
	}
	cbKernels := 0
	var cbK *types.Kernel
	seenK := map[types.Hash]bool{}
	var fees uint64
	for i := range b.Kernels {
		k := &b.Kernels[i]
		if !v2crypto.ValidPublicPoint(k.Excess) {
			return errors.New("chain: invalid excess point")
		}
		id := types.KernelID(k)
		if seenK[id] || c.store.HasKernel(id) {
			return errors.New("chain: duplicate kernel")
		}
		seenK[id] = true
		if k.Fee > math.MaxInt64-fees {
			return errors.New("chain: fee overflow")
		}
		fees += k.Fee
		switch k.Features {
		case types.KernelFeaturesCoinbase:
			if !block || k.Fee != 0 || b.Header.Height > math.MaxUint64-types.CoinbaseLock || k.LockHeight != b.Header.Height+types.CoinbaseLock {
				return errors.New("chain: invalid coinbase kernel")
			}
			cbKernels++
			cbK = k
		case types.KernelFeaturesLegacyClaim:
			if k.Fee != 0 || k.LockHeight != 0 || len(k.ExcessSig) != 65 {
				return errors.New("chain: invalid legacy claim kernel")
			}
		case types.KernelFeaturesPlain:
			if k.LockHeight > b.Header.Height || len(k.ExcessSig) != 65 {
				return errors.New("chain: invalid kernel authorization")
			}
		default:
			return errors.New("chain: unsupported kernel feature")
		}
	}
	if block {
		reward := types.BlockReward(b.Header.Height)
		if reward > 0 {
			if cbOuts != 1 || cbKernels != 1 || cb.Commit != cbK.Excess || !wallet.VerifyCoinbase(b.Header.Height, reward, cbK.Excess, cbK.ExcessSig) {
				return errors.New("chain: invalid or missing subsidy authorization")
			}
		} else if cbOuts != 0 || cbKernels != 0 {
			return errors.New("chain: subsidy after issuance ended")
		}
		if err := validateDevFund(b); err != nil {
			return err
		}
	}
	if err := c.validateLegacyClaims(b); err != nil {
		return fmt.Errorf("chain: legacy ownership procedure: %w", err)
	}
	for _, k := range b.Kernels {
		if k.Features == types.KernelFeaturesPlain {
			id := types.KernelID(&k)
			if !v2crypto.SchnorrVerify(k.Excess, id[:], k.ExcessSig) {
				return errors.New("chain: invalid kernel authorization")
			}
		}
	}
	for _, o := range b.Outputs {
		if o.Features == types.OutputFeaturesPlain && !v2crypto.VerifyRange(o.Commit, o.RangeProof) {
			return ErrBadOutput
		}
	}
	return c.validateBalance(b)
}
