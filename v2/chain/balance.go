package chain

import (
	"errors"
	"fmt"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
)

// ErrBalance is returned when a block's Mimblewimble commitment sum does not
// balance — i.e. value was created from nothing (inflation) or destroyed.
var ErrBalance = errors.New("chain: block does not balance")

// validateBalance enforces the core MW no-inflation invariant for the regular
// (non-coinbase) value flow of a block:
//
//	Σ plain_outputs − Σ inputs + totalFee·H == Σ tx_kernel_excess
//
// The coinbase output is value-known and verified separately (VerifyCoinbase
// over reward + F), so it is excluded here. The fee term F·H stays: spends
// destroy F and the coinbase re-creates it for the miner. Genesis (height 0) is
// skipped: it is empty and has no spends.
//
// Rearranged for the curve check Σpos − Σneg == identity:
//
//	pos = {plain outputs} ∪ {totalFee·H}
//	neg = {inputs} ∪ {non-coinbase kernel excesses}
func (c *Chain) validateBalance(b *types.Block) error {
	if b.Header.Height == 0 {
		return nil // genesis is empty
	}

	var pos, neg [][33]byte
	for i := range b.Outputs {
		if b.Outputs[i].Features == types.OutputFeaturesPlain {
			pos = append(pos, b.Outputs[i].Commit)
		}
	}
	for i := range b.Inputs {
		neg = append(neg, b.Inputs[i].Commit)
	}
	for i := range b.Kernels {
		if b.Kernels[i].Features == types.KernelFeaturesCoinbase {
			continue // coinbase kernel excess is the value-known coinbase commit
		}
		neg = append(neg, b.Kernels[i].Excess)
	}
	// The same fee total CoinbaseAmount pays out to the miner.
	totalFee, err := PlainKernelFees(b)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBalance, err)
	}

	// Nothing to balance (e.g. a coinbase-only block): trivially valid.
	if len(pos) == 0 && len(neg) == 0 {
		return nil
	}

	if totalFee > 0 {
		feeH, err := v2crypto.PedersenCommit(int64(totalFee), make([]byte, 32)) // totalFee·H
		if err != nil {
			return err
		}
		pos = append(pos, feeH)
	}

	ok, err := v2crypto.PedersenSumZero(pos, neg, 0)
	if err != nil {
		// A decode error means a malformed commitment/excess point.
		return ErrBalance
	}
	if !ok {
		return ErrBalance
	}
	return nil
}
