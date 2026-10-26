package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
)

// ErrDevFund is returned when a block violates the transparent dev-fee rule.
var ErrDevFund = errors.New("chain: invalid dev-fund output")

func errDevFund(msg string) error { return fmt.Errorf("%w: %s", ErrDevFund, msg) }

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

// DevFundBlindingTweak returns the canonical public version-3 scalar t:
//
//	t = SHA256("NosoX/devfund-blind/v3" || BE32(network) || BE64(height) || parentHash[32] || BE64(totalFee)) mod n.
//
// The developer spends with (d_dev+t) mod n, retaining the original recipient.
// Parent ancestry binds genesis as well as the explicit network domain. Body
// roots, nonce and timestamp are excluded to avoid circular mining templates.
// All inputs are public; this helper performs no secret scalar operations.
func DevFundBlindingTweak(header *types.BlockHeader, totalFee uint64) ([32]byte, error) {
	if header == nil || header.Version != types.BlockVersion {
		return [32]byte{}, errDevFund("version-3 header required")
	}
	if totalFee > math.MaxInt64 {
		return [32]byte{}, errDevFund("fee overflow")
	}
	preimage := []byte("NosoX/devfund-blind/v3")
	preimage = binary.BigEndian.AppendUint32(preimage, header.NetworkMagic)
	preimage = binary.BigEndian.AppendUint64(preimage, header.Height)
	preimage = append(preimage, header.PrevHash[:]...)
	preimage = binary.BigEndian.AppendUint64(preimage, totalFee)
	digest := sha256.Sum256(preimage)
	scalar := new(big.Int).SetBytes(digest[:])
	scalar.Mod(scalar, v2crypto.Curve().Params().N)
	var out [32]byte
	scalar.FillBytes(out[:])
	return out, nil
}

// ExpectedDevFundCommit returns C = F·H + P_dev + t·G for this block context.
// The value remains exactly F; only its public blinding is context-specific.
// Only the holder of d_dev can derive the spending scalar d_dev+t. The fixed
// recipient cannot be substituted by a caller. No identity commitment or
// noncanonical point is accepted, including in the negligible cancellation case.
func ExpectedDevFundCommit(header *types.BlockHeader, totalFee uint64) (types.Commitment, error) {
	tweak, err := DevFundBlindingTweak(header, totalFee)
	if err != nil {
		return types.Commitment{}, err
	}
	// Explicitly reject an identity adjusted recipient: that would erase the
	// developer's secret from the output even if the final value point is valid.
	// The canonical internal zero from t=0 is accepted only as an addend by the
	// existing point operation; its nonidentity result is still checked below.
	tweakPoint, err := v2crypto.PedersenCommit(0, tweak[:])
	if err != nil {
		return types.Commitment{}, err
	}
	recipient, err := v2crypto.PointAdd(types.DevFundPoint(), tweakPoint)
	if err != nil {
		return types.Commitment{}, errDevFund("identity adjusted recipient")
	}
	if !v2crypto.ValidPublicPoint(recipient) {
		return types.Commitment{}, errDevFund("noncanonical adjusted recipient")
	}
	feeH, err := v2crypto.PedersenCommit(int64(totalFee), make([]byte, 32))
	if err != nil {
		return types.Commitment{}, err
	}
	sum, err := v2crypto.PointAdd(feeH, recipient)
	if err != nil {
		return types.Commitment{}, errDevFund("identity dev-fund commitment")
	}
	if !v2crypto.ValidPublicPoint(sum) {
		return types.Commitment{}, errDevFund("noncanonical dev-fund point")
	}
	return types.Commitment(sum), nil
}

// validateDevFund enforces the transparent dev-fee rule:
//   - if the block's total kernel fee F > 0, there must be exactly ONE output
//     with Features == OutputFeaturesDevFund whose commit == F·H + DevFundPoint + t·G;
//   - if F == 0, there must be NO dev-fund output.
func validateDevFund(b *types.Block) error {
	var fee uint64
	for _, k := range b.Kernels {
		if k.Fee > math.MaxInt64-fee {
			return errDevFund("fee overflow")
		}
		fee += k.Fee
	}
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
	want, err := ExpectedDevFundCommit(&b.Header, fee)
	if err != nil {
		return err
	}
	if devOuts[0] != want {
		return errDevFund("dev-fund output does not commit the total fee to the dev address")
	}
	return nil
}
