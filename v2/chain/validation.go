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
	if b.Header.Height != 0 || !b.Header.PrevHash.IsZero() || len(b.Inputs) != 0 || len(b.Outputs) != 0 || len(b.Kernels) != 0 {
		return errors.New("chain: invalid trusted genesis")
	}
	return nil
}

func (c *Chain) verifyHistory(store Store, genesis *types.Block) error {
	if persistent, ok := store.(*BadgerStore); ok {
		return c.streamingVerifyHistory(persistent, genesis)
	}
	// Remaining case: the in-memory store, replayed into a fresh memStore.
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
		if err = check.validate(b, false); err != nil {
			return fmt.Errorf("chain: invalid persisted block %d: %w", h, err)
		}
		if err = staged.WriteBlock(b); err != nil {
			return err
		}
	}
	return nil
}

// ValidateTransaction checks admission against the next canonical block state.
// The coinbase (subsidy plus fees) is constructed separately by the miner.
//
// Cheapest checks first: bounds and shape, then state (inputs, maturity,
// duplicates) and the balance equation under the chain lock; the signatures
// and range proofs, which dominate the cost, run last and without the lock, so
// a transaction that cannot balance never reaches them.
func (c *Chain) ValidateTransaction(tx *types.Transaction) error {
	b, err := c.checkTransactionCheap(tx)
	if err != nil {
		return err
	}
	return verifyCrypto(b)
}

func (c *Chain) checkTransactionCheap(tx *types.Transaction) (*types.Block, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if tx == nil {
		return nil, errors.New("chain: nil transaction")
	}
	tip, ok := c.store.Tip()
	if !ok || tip.Height == math.MaxUint64 {
		return nil, errors.New("chain: unavailable tip")
	}
	b := &types.Block{Header: types.BlockHeader{Height: tip.Height + 1, NetworkMagic: tip.NetworkMagic}, Inputs: tx.Inputs, Outputs: tx.Outputs, Kernels: tx.Kernels}
	if len(b.Inputs) == 0 || len(b.Outputs) == 0 || len(b.Kernels) == 0 {
		return nil, errors.New("chain: empty transaction")
	}
	if err := bodyBounds(b); err != nil {
		return nil, err
	}
	// The block's one coinbase output and kernel are reserved whenever the block
	// will have to carry one: while the subsidy lasts, and afterwards whenever a
	// transaction pays a fee.
	reserveOutputs, reserveKernels, reserveBytes := CoinbaseReserve(b.Header.Height, TotalKernelFee(b))
	if len(b.Outputs)+reserveOutputs > types.MaxBlockOutputs || len(b.Kernels)+reserveKernels > types.MaxBlockKernels {
		return nil, errors.New("chain: transaction leaves no mandatory block capacity")
	}
	n, err := BodyResourceBytes(b)
	if err != nil {
		return nil, err
	}
	if n+reserveBytes > types.MaxBlockBodyBytes {
		return nil, ErrResourceBudget
	}
	if err := c.validateBody(b, false); err != nil {
		return nil, err
	}
	return b, nil
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
			return fmt.Errorf("%w: %w", ErrDoubleSpend, ErrTxState)
		}
		if in.Features != stored.Features {
			return errors.New("chain: input metadata mismatch")
		}
		switch stored.Features {
		case types.OutputFeaturesPlain, types.OutputFeaturesCoinbase:
		default:
			return errors.New("chain: unsupported input feature")
		}
		if stored.Features == types.OutputFeaturesCoinbase {
			// Mature once CoinbaseLock blocks have passed since creation. The
			// creation height is indexed with the output, so no block bodies
			// are read.
			created, ok := c.store.OutputHeight(in.Commit)
			if !ok {
				return errors.New("chain: coinbase creation height unavailable")
			}
			if created >= b.Header.Height || b.Header.Height-created < types.CoinbaseLock {
				return fmt.Errorf("%w: chain: immature coinbase input %d", ErrTxState, i)
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
		if outputs[o.Commit] || inputs[o.Commit] {
			return errors.New("chain: duplicate output")
		}
		if c.store.HasOutput(o.Commit) || c.store.HasUTXO(o.Commit) {
			return fmt.Errorf("%w: chain: output already exists", ErrTxState)
		}
		outputs[o.Commit] = true
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
		if seenK[id] {
			return errors.New("chain: duplicate kernel")
		}
		if c.store.HasKernel(id) {
			return fmt.Errorf("%w: chain: kernel already included", ErrTxState)
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
		case types.KernelFeaturesPlain:
			if k.LockHeight > b.Header.Height {
				return fmt.Errorf("%w: chain: kernel locked until height %d", ErrTxState, k.LockHeight)
			}
			if len(k.ExcessSig) != 65 {
				return errors.New("chain: invalid kernel authorization")
			}
		default:
			return errors.New("chain: unsupported kernel feature")
		}
	}
	if block {
		// The miner is paid reward + fees, no more and no less. A coinbase is
		// required exactly when that amount is positive, including after the
		// subsidy has ended, and is forbidden otherwise.
		amount, err := CoinbaseAmount(b)
		if err != nil {
			return err
		}
		if amount > 0 {
			if cbOuts != 1 || cbKernels != 1 || cb.Commit != cbK.Excess {
				return errors.New("chain: invalid or missing coinbase")
			}
		} else if cbOuts != 0 || cbKernels != 0 {
			return errors.New("chain: coinbase in a block that pays nothing")
		}
	}
	// Cheap state-dependent balance check before any expensive proof work.
	return c.validateBalance(b)
}

// verifyCrypto runs the signature and range-proof checks. They depend only on
// the block bytes (and the network magic), never on chain state, so callers run
// them outside the chain lock and after every cheaper check has passed.
func verifyCrypto(b *types.Block) error {
	amount, err := CoinbaseAmount(b)
	if err != nil {
		return err
	}
	for i := range b.Kernels {
		k := &b.Kernels[i]
		switch k.Features {
		case types.KernelFeaturesCoinbase:
			if amount <= 0 || !wallet.VerifyCoinbase(b.Header.NetworkMagic, b.Header.Height, amount, k.Excess, k.ExcessSig) {
				return errors.New("chain: invalid or missing coinbase authorization")
			}
		case types.KernelFeaturesPlain:
			if !v2crypto.SchnorrVerify(k.Excess, types.KernelSigningMessage(b.Header.NetworkMagic, k), k.ExcessSig) {
				return errors.New("chain: invalid kernel authorization")
			}
		}
	}
	for i := range b.Outputs {
		o := &b.Outputs[i]
		if o.Features == types.OutputFeaturesPlain && !v2crypto.VerifyRange(o.Commit, o.RangeProof) {
			return ErrBadOutput
		}
	}
	return nil
}

// TotalKernelFee sums public fees, saturating at MaxUint64 on overflow.
// Consensus separately rejects totals above MaxInt64 before using this helper.
func TotalKernelFee(b *types.Block) uint64 {
	var sum uint64
	for i := range b.Kernels {
		if b.Kernels[i].Fee > math.MaxUint64-sum {
			return math.MaxUint64
		}
		sum += b.Kernels[i].Fee
	}
	return sum
}

// errFeeOverflow reports kernel fees that cannot be summed in an int64.
var errFeeOverflow = errors.New("chain: fee overflow")

// PlainKernelFees is the total fee of the block's plain kernels: the fee the
// spends destroy and the coinbase re-creates. It is the single definition used
// by the balance equation (validateBalance) and the coinbase amount
// (CoinbaseAmount), so the two cannot disagree about which kernels carry value.
// Coinbase kernels never count; a coinbase kernel with a nonzero Fee is also
// rejected outright by validateBody. Totals above MaxInt64 are an error.
func PlainKernelFees(b *types.Block) (uint64, error) {
	var sum uint64
	for i := range b.Kernels {
		if b.Kernels[i].Features == types.KernelFeaturesCoinbase {
			continue
		}
		if b.Kernels[i].Fee > math.MaxInt64-sum {
			return 0, errFeeOverflow
		}
		sum += b.Kernels[i].Fee
	}
	return sum, nil
}

// CoinbaseReserve is the output, kernel and body-byte capacity a block must keep
// free for its mandatory coinbase when its selected transactions pay fees. A
// coinbase is required exactly when reward+fees > 0, so after the subsidy has
// ended nothing is reserved until a transaction pays a fee. The mempool
// admission check and the miner's transaction selection both use this.
func CoinbaseReserve(height uint64, fees uint64) (outputs, kernels int, bytes uint64) {
	if types.BlockReward(height) > 0 || fees > 0 {
		return 1, 1, 128 + (128 + 65)
	}
	return 0, 0, 0
}

// CoinbaseAmount is the exact value a block's coinbase must commit:
// BlockReward(height) plus the total of its plain kernel fees. Fees are not
// minted; the transactions destroy them (outputs + fee = inputs) and the
// coinbase collects them, so the unspent set always sums to the cumulative
// subsidy. The arithmetic is overflow-checked in int64.
func CoinbaseAmount(b *types.Block) (int64, error) {
	reward := types.BlockReward(b.Header.Height)
	fees, err := PlainKernelFees(b)
	if err != nil {
		return 0, err
	}
	if int64(fees) > math.MaxInt64-reward {
		return 0, errors.New("chain: coinbase amount overflow")
	}
	return reward + int64(fees), nil
}
