package chain

import (
	"errors"
	"fmt"

	v2crypto "github.com/noso-project/noso-go/v2/crypto"
	"github.com/noso-project/noso-go/v2/types"
)

// ErrDevFund is returned when a block violates the transparent dev-fee rule.
var ErrDevFund = errors.New("chain: invalid dev-fund output")

func errDevFund(msg string) error { return fmt.Errorf("%w: %s", ErrDevFund, msg) }

// TotalKernelFee sums the public fee field across every kernel in a block.
func TotalKernelFee(b *types.Block) uint64 {
	var sum uint64
	for i := range b.Kernels {
		sum += b.Kernels[i].Fee
	}
	return sum
}

// ExpectedDevFundCommit returns the value-known commitment the transparent
// dev-fund output MUST carry for a block whose total kernel fee is totalFee:
//
//	C = totalFee·H + DevFundPoint
//
// Anyone can recompute it from public data, so the fee destination is fixed and
// auditable. Only the off-repo dev scalar can later spend the output.
func ExpectedDevFundCommit(totalFee uint64) (types.Commitment, error) {
	feeH, err := v2crypto.PedersenCommit(int64(totalFee), make([]byte, 32)) // totalFee·H
	if err != nil {
		return types.Commitment{}, err
	}
	sum, err := v2crypto.PointAdd(feeH, types.DevFundPoint())
	if err != nil {
		return types.Commitment{}, err
	}
	return types.Commitment(sum), nil
}

// validateDevFund enforces the transparent dev-fee rule:
//   - if the block's total kernel fee F > 0, there must be exactly ONE output
//     with Features == OutputFeaturesDevFund whose commit == F·H + DevFundPoint;
//   - if F == 0, there must be NO dev-fund output.
func validateDevFund(b *types.Block) error {
	fee := TotalKernelFee(b)
	var devOuts []types.Commitment
	for i := range b.Outputs {
		if b.Outputs[i].Features == types.OutputFeaturesDevFund {
			devOuts = append(devOuts, b.Outputs[i].Commit)
		}
	}
	if fee == 0 {
		if len(devOuts) != 0 {
			return errDevFund("dev-fund output present but block has no fees")
		}
		return nil
	}
	if len(devOuts) != 1 {
		return errDevFund("block with fees must have exactly one dev-fund output")
	}
	want, err := ExpectedDevFundCommit(fee)
	if err != nil {
		return err
	}
	if devOuts[0] != want {
		return errDevFund("dev-fund output does not commit the total fee to the dev address")
	}
	return nil
}
