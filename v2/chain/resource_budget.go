package chain

import (
	"errors"
	"fmt"

	"github.com/pasichDev/noso-go/v2/types"
)

// Consensus limits. Every legal suffix of MaxReorgBlocks fits the aggregate
// body budget; this is not a smaller, node-local fork policy. Genesis is empty
// and has no separate envelope.
const (
	MaxBlockInputs     = types.MaxBlockInputs
	MaxBlockOutputs    = types.MaxBlockOutputs
	MaxBlockKernels    = types.MaxBlockKernels
	MaxBlockBodyBytes  = types.MaxBlockBodyBytes
	MaxRangeProofBytes = types.MaxRangeProofBytes
	MaxReorgBlocks     = types.MaxReorgBlocks
	MaxReorgBodyBytes  = types.MaxReorgBodyBytes
	MaxUndoRecordBytes = MaxBlockInputs * (128 + MaxRangeProofBytes)
	// Gob includes field/type descriptors and length prefixes. This loose bound
	// exceeds twice the complete charge plus 4 KiB for the fixed output schema.
	MaxEncodedUndoBytes = 2*MaxUndoRecordBytes + 4096
)

var ErrResourceBudget = errors.New("chain: resource budget exceeded")

// BodyResourceBytes checks the consensus envelope without copying any fields.
// The 128-byte charge per item is the existing protocol accounting unit, not
// a claim about Go heap usage or the transport encoding size.
func BodyResourceBytes(b *types.Block) (uint64, error) {
	if b == nil {
		return 0, errors.New("chain: nil block")
	}
	if len(b.Inputs) > MaxBlockInputs || len(b.Outputs) > MaxBlockOutputs || len(b.Kernels) > MaxBlockKernels {
		return 0, errors.New("chain: body item limit")
	}
	var size uint64
	size += uint64(len(b.Inputs)) * 192
	for _, out := range b.Outputs {
		if len(out.RangeProof) > MaxRangeProofBytes {
			return 0, errors.New("chain: output field limit")
		}
		size += uint64(128 + len(out.RangeProof))
	}
	for _, kernel := range b.Kernels {
		if len(kernel.ExcessSig) > 65 {
			return 0, errors.New("chain: kernel field limit")
		}
		size += uint64(128 + len(kernel.ExcessSig))
	}
	if size > uint64(MaxBlockBodyBytes) {
		return 0, errors.New("chain: body size limit")
	}
	return size, nil
}

// CheckReorgResourceBudget runs before rollback allocations. It accepts every
// suffix allowed by the per-block and depth limits, including the maximum.
func CheckReorgResourceBudget(incoming []*types.Block) error {
	if len(incoming) > MaxReorgBlocks {
		return ErrTooDeep
	}
	var size uint64
	for _, b := range incoming {
		if b == nil || b.Header.Height == 0 {
			return errors.New("chain: invalid incoming suffix")
		}
		n, err := BodyResourceBytes(b)
		if err != nil {
			return err
		}
		if n > MaxReorgBodyBytes-size {
			return fmt.Errorf("%w: incoming bodies", ErrResourceBudget)
		}
		size += n
	}
	return nil
}

func undoResourceBytes(outputs []types.Output) (uint64, error) {
	if len(outputs) > MaxBlockInputs {
		return 0, fmt.Errorf("%w: undo item count", ErrResourceBudget)
	}
	var size uint64
	for _, out := range outputs {
		if len(out.RangeProof) > MaxRangeProofBytes {
			return 0, fmt.Errorf("%w: undo output fields", ErrResourceBudget)
		}
		size += uint64(128 + len(out.RangeProof))
	}
	return size, nil
}
