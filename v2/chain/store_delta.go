package chain

import (
	"errors"

	"github.com/pasichDev/noso-go/v2/types"
)

type deltaReader struct {
	output     func(types.Commitment) (*types.Output, bool, error)
	seenOutput func(types.Commitment) (bool, error)
	seenKernel func(types.Hash) (bool, error)
}

// checkStoreDelta protects storage/index consistency before mutation. Its
// callbacks must read the same snapshot that will be changed. It deliberately
// does not authorize signatures, proofs, subsidy, fees, features or PoW: callers
// still obtain full consensus authorization through Chain.AddBlock/ReorgTo.
func checkStoreDelta(b *types.Block, read deltaReader) ([]types.Output, error) {
	inputs := make(map[types.Commitment]bool, len(b.Inputs))
	spent := make([]types.Output, 0, len(b.Inputs))
	for _, in := range b.Inputs {
		if inputs[in.Commit] {
			return nil, errors.New("store: duplicate input")
		}
		inputs[in.Commit] = true
		out, ok, err := read.output(in.Commit)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrDoubleSpend
		}
		if out.Commit != in.Commit || out.Features != in.Features {
			return nil, errors.New("store: input metadata mismatch")
		}
		spent = append(spent, *out)
	}
	outputs := make(map[types.Commitment]bool, len(b.Outputs))
	for _, out := range b.Outputs {
		if outputs[out.Commit] || inputs[out.Commit] {
			return nil, errors.New("store: duplicate output")
		}
		outputs[out.Commit] = true
		seen, err := read.seenOutput(out.Commit)
		if err != nil {
			return nil, err
		}
		if seen {
			return nil, errors.New("store: historical output already exists")
		}
		_, exists, err := read.output(out.Commit)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, errors.New("store: output already unspent")
		}
	}
	kernels := make(map[types.Hash]bool, len(b.Kernels))
	for _, k := range b.Kernels {
		id := types.KernelID(&k)
		if kernels[id] {
			return nil, errors.New("store: duplicate kernel")
		}
		kernels[id] = true
		seen, err := read.seenKernel(id)
		if err != nil {
			return nil, err
		}
		if seen {
			return nil, errors.New("store: historical kernel already exists")
		}
	}
	return spent, nil
}
