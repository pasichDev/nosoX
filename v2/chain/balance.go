package chain

import (
	"errors"
	"math"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
)

// ErrBalance is returned when a block's Mimblewimble commitment sum does not
// balance — i.e. value was created from nothing (inflation) or destroyed.
var ErrBalance = errors.New("chain: block does not balance")

// validateBalance enforces the core MW no-inflation invariant for the regular
// (non-coinbase, non-dev) value flow of a block:
//
//	Σ plain_outputs − Σ inputs + totalFee·H == Σ tx_kernel_excess
//
// Coinbase and dev-fund outputs are value-known and verified separately
// (VerifyCoinbase over the subsidy, validateDevFund over F·H+DevFundPoint+t·G), so
// they cancel out of this equation and are excluded here. Genesis (height 0) is
// skipped: it mints value-known legacy/coinbase outputs with no spends.
//
// Rearranged for the curve check Σpos − Σneg == identity:
//
//	pos = {plain outputs} ∪ {totalFee·H}
//	neg = {inputs} ∪ {non-coinbase kernel excesses}
func (c *Chain) validateBalance(b *types.Block) error {
	if b.Header.Height == 0 {
		return nil // genesis carries value-known outputs only
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
	var totalFee uint64
	for i := range b.Kernels {
		if b.Kernels[i].Features == types.KernelFeaturesCoinbase {
			continue // coinbase kernel excess is the value-known coinbase commit
		}
		neg = append(neg, b.Kernels[i].Excess)
		if b.Kernels[i].Fee > math.MaxInt64-totalFee {
			return ErrBalance
		}
		totalFee += b.Kernels[i].Fee
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
