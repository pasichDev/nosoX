package chain

import (
	"errors"
	"fmt"
	"github.com/pasichDev/noso-go/v2/types"
	"math"
)

// suffixDelta contains only touched keys. Nil pointers and false booleans are
// tombstones; a nonnil empty Undo records a block which spent no outputs.
type suffixDelta struct {
	Blocks  map[uint64]*types.Block
	Undo    map[uint64][]types.Output
	Hashes  map[types.Hash]*uint64
	UTXOs   map[types.Commitment]*types.Output
	Outputs map[types.Commitment]bool
	Kernels map[types.Hash]bool
	Legacy  map[string]*types.Commitment
	Tip     types.BlockHeader
}
type forkStore struct {
	base    Store
	changes suffixDelta
}

func cloneOutputs(in []types.Output) []types.Output {
	out := make([]types.Output, len(in))
	copy(out, in)
	for i := range out {
		out[i].RangeProof = append([]byte(nil), out[i].RangeProof...)
	}
	return out
}
func newForkStore(base Store, ancestor uint64) (*forkStore, error) {
	tip, ok := base.Tip()
	if !ok || ancestor > tip.Height {
		return nil, ErrUnknownAnc
	}
	if tip.Height-ancestor > MaxReorgBlocks {
		return nil, ErrTooDeep
	}
	f := &forkStore{base: base, changes: suffixDelta{
		Blocks: map[uint64]*types.Block{}, Undo: map[uint64][]types.Output{}, Hashes: map[types.Hash]*uint64{},
		UTXOs: map[types.Commitment]*types.Output{}, Outputs: map[types.Commitment]bool{}, Kernels: map[types.Hash]bool{}, Legacy: map[string]*types.Commitment{}, Tip: tip,
	}}
	for h := tip.Height; h > ancestor; h-- {
		b, err := base.BlockAt(h)
		if err != nil {
			return nil, err
		}
		if err := bodyBounds(b); err != nil {
			return nil, err
		}
		undo, err := base.UndoAtBudget(h, MaxUndoRecordBytes)
		if err != nil {
			return nil, err
		}
		if len(undo) != len(b.Inputs) {
			return nil, errors.New("store: incomplete undo")
		}
		for i, in := range b.Inputs {
			o := undo[i]
			if o.Commit != in.Commit || o.Features != in.Features || o.LegacyAddress != in.LegacyAddr || o.LegacyAmount != in.LegacyAmount {
				return nil, errors.New("store: undo metadata mismatch")
			}
		}
		f.changes.Blocks[h] = nil
		f.changes.Undo[h] = nil
		f.changes.Hashes[types.HeaderID(&b.Header)] = nil
		for _, o := range b.Outputs {
			f.changes.UTXOs[o.Commit] = nil
			f.changes.Outputs[o.Commit] = false
			if o.Features == types.OutputFeaturesLegacy {
				f.changes.Legacy[o.LegacyAddress] = nil
			}
		}
		for _, k := range b.Kernels {
			f.changes.Kernels[types.KernelID(&k)] = false
		}
		// UndoAtBudget already returned isolated, owned proof slices.
		for _, o := range undo {
			o := o
			f.changes.UTXOs[o.Commit] = &o
			if o.Features == types.OutputFeaturesLegacy {
				v := o.Commit
				f.changes.Legacy[o.LegacyAddress] = &v
			}
		}
	}
	b, err := base.BlockAt(ancestor)
	if err != nil {
		return nil, err
	}
	f.changes.Tip = b.Header
	return f, nil
}
func (f *forkStore) delta() *suffixDelta            { return &f.changes }
func (f *forkStore) Tip() (types.BlockHeader, bool) { return f.changes.Tip, true }
func (f *forkStore) HeightOf(h types.Hash) (uint64, bool) {
	if v, ok := f.changes.Hashes[h]; ok {
		if v == nil {
			return 0, false
		}
		return *v, true
	}
	return f.base.HeightOf(h)
}
func (f *forkStore) BlockAt(h uint64) (*types.Block, error) {
	if b, ok := f.changes.Blocks[h]; ok {
		if b == nil {
			return nil, errors.New("store: height out of range")
		}
		return cloneBlock(b), nil
	}
	if h > f.changes.Tip.Height {
		return nil, errors.New("store: height out of range")
	}
	return f.base.BlockAt(h)
}
func (f *forkStore) BlockByHash(h types.Hash) (*types.Block, error) {
	v, ok := f.HeightOf(h)
	if !ok {
		return nil, errors.New("store: unknown hash")
	}
	return f.BlockAt(v)
}
func (f *forkStore) UndoAt(h uint64) ([]types.Output, error) {
	return f.UndoAtBudget(h, MaxUndoRecordBytes)
}
func (f *forkStore) UndoAtBudget(h uint64, maxBytes uint64) ([]types.Output, error) {
	if v, ok := f.changes.Undo[h]; ok {
		if v == nil {
			return nil, errors.New("store: unknown undo")
		}
		n, err := undoResourceBytes(v)
		if err != nil {
			return nil, err
		}
		if n > maxBytes {
			return nil, ErrResourceBudget
		}
		return cloneOutputs(v), nil
	}
	return f.base.UndoAtBudget(h, maxBytes)
}
func (f *forkStore) UTXOByCommit(c types.Commitment) (*types.Output, bool) {
	if o, ok := f.changes.UTXOs[c]; ok {
		if o == nil {
			return nil, false
		}
		out := cloneOutputs([]types.Output{*o})
		return &out[0], true
	}
	return f.base.UTXOByCommit(c)
}
func (f *forkStore) HasUTXO(c types.Commitment) bool { _, ok := f.UTXOByCommit(c); return ok }
func (f *forkStore) HasOutput(c types.Commitment) bool {
	if v, ok := f.changes.Outputs[c]; ok {
		return v
	}
	return f.base.HasOutput(c)
}
func (f *forkStore) HasKernel(h types.Hash) bool {
	if v, ok := f.changes.Kernels[h]; ok {
		return v
	}
	return f.base.HasKernel(h)
}
func (f *forkStore) UTXOByLegacyAddress(addr string) (*types.Output, bool) {
	if c, ok := f.changes.Legacy[addr]; ok {
		if c == nil {
			return nil, false
		}
		return f.UTXOByCommit(*c)
	}
	o, ok := f.base.UTXOByLegacyAddress(addr)
	if !ok {
		return nil, false
	}
	return f.UTXOByCommit(o.Commit)
}
func (f *forkStore) WriteBlock(b *types.Block) error {
	if b == nil {
		return errors.New("store: nil block")
	}
	if err := bodyBounds(b); err != nil {
		return err
	}
	tip := f.changes.Tip
	if tip.Height == math.MaxUint64 || b.Header.Height != tip.Height+1 {
		return errors.New("store: noncontiguous height")
	}
	if b.Header.PrevHash != types.HeaderID(&tip) {
		return ErrStale
	}
	id := types.HeaderID(&b.Header)
	if _, ok := f.HeightOf(id); ok {
		return errors.New("store: block hash already exists")
	}
	spent, err := checkStoreDelta(b, f.storeDeltaReader())
	if err != nil {
		return err
	}
	if _, err := undoResourceBytes(spent); err != nil {
		return err
	}
	b = cloneBlock(b)
	for _, o := range spent {
		f.changes.UTXOs[o.Commit] = nil
		if o.Features == types.OutputFeaturesLegacy {
			f.changes.Legacy[o.LegacyAddress] = nil
		}
	}
	for _, o := range b.Outputs {
		o := o
		f.changes.UTXOs[o.Commit] = &o
		f.changes.Outputs[o.Commit] = true
		if o.Features == types.OutputFeaturesLegacy {
			v := o.Commit
			f.changes.Legacy[o.LegacyAddress] = &v
		}
	}
	for _, k := range b.Kernels {
		f.changes.Kernels[types.KernelID(&k)] = true
	}
	h := b.Header.Height
	f.changes.Blocks[h] = b
	// checkStoreDelta's readers return isolated copies; transfer their ownership.
	f.changes.Undo[h] = spent
	f.changes.Hashes[id] = &h
	f.changes.Tip = b.Header
	return nil
}
func (f *forkStore) UndoBlock() error { return errors.New("store: fork undo unsupported") }
func (f *forkStore) ReplaceChain([]*types.Block) error {
	return errors.New("store: fork replacement unsupported")
}
func (f *forkStore) ReplaceSuffix(uint64, []*types.Block) error {
	return errors.New("store: nested suffix unsupported")
}
func (f *forkStore) Save() error  { return errors.New("store: fork is ephemeral") }
func (f *forkStore) Close() error { return nil }

func (s *memStore) orderedBlocks() []*types.Block {
	out := make([]*types.Block, len(s.blocks))
	for i := range out {
		out[i] = s.blocks[uint64(i)]
	}
	return out
}
func (s *memStore) UndoAt(h uint64) ([]types.Output, error) {
	return s.UndoAtBudget(h, MaxUndoRecordBytes)
}
func (s *memStore) UndoAtBudget(h uint64, maxBytes uint64) ([]types.Output, error) {
	v, ok := s.undo[h]
	if !ok {
		return nil, errors.New("store: missing undo")
	}
	n, err := undoResourceBytes(v)
	if err != nil {
		return nil, err
	}
	if n > maxBytes {
		return nil, ErrResourceBudget
	}
	return cloneOutputs(v), nil
}
func (s *memStore) ReplaceSuffix(ancestor uint64, incoming []*types.Block) error {
	if err := CheckReorgResourceBudget(incoming); err != nil {
		return err
	}
	f, err := newForkStore(s, ancestor)
	if err != nil {
		return err
	}
	for i, b := range incoming {
		if err := f.WriteBlock(b); err != nil {
			return fmt.Errorf("store: suffix %d: %w", i, err)
		}
	}
	// All reads, allocations of owned block/proof bytes and raw consistency checks
	// completed above. Apply only touched keys; the canonical prefix is never copied.
	d := f.delta()
	for h, b := range d.Blocks {
		if b == nil {
			delete(s.blocks, h)
		} else {
			s.blocks[h] = b
		}
	}
	for h, u := range d.Undo {
		if u == nil {
			delete(s.undo, h)
		} else {
			s.undo[h] = u
		}
	}
	for h, v := range d.Hashes {
		if v == nil {
			delete(s.heightOf, h)
		} else {
			s.heightOf[h] = *v
		}
	}
	for c, o := range d.UTXOs {
		if o == nil {
			delete(s.utxo, c)
		} else {
			s.utxo[c] = *o
		}
	}
	for c, v := range d.Outputs {
		if !v {
			delete(s.outputSeen, c)
		} else {
			s.outputSeen[c] = true
		}
	}
	for h, v := range d.Kernels {
		if !v {
			delete(s.kernelSeen, h)
		} else {
			s.kernelSeen[h] = true
		}
	}
	for a, v := range d.Legacy {
		if v == nil {
			delete(s.legacyIdx, a)
		} else {
			s.legacyIdx[a] = *v
		}
	}
	return nil
}

// Backends can preserve error causes for raw consistency checks even though the
// public historical lookup API still returns booleans. Touched keys are already
// owned and checked by this overlay; untouched keys retain backend read errors.
type deltaReadStore interface{ storeDeltaReader() deltaReader }

func (f *forkStore) storeDeltaReader() deltaReader {
	base := deltaReader{
		output: func(c types.Commitment) (*types.Output, bool, error) {
			o, ok := f.base.UTXOByCommit(c)
			return o, ok, nil
		},
		seenOutput: func(c types.Commitment) (bool, error) { return f.base.HasOutput(c), nil },
		seenKernel: func(h types.Hash) (bool, error) { return f.base.HasKernel(h), nil },
	}
	if s, ok := f.base.(deltaReadStore); ok {
		base = s.storeDeltaReader()
	}
	return deltaReader{
		output: func(c types.Commitment) (*types.Output, bool, error) {
			if _, ok := f.changes.UTXOs[c]; ok {
				o, exists := f.UTXOByCommit(c)
				return o, exists, nil
			}
			return base.output(c)
		},
		seenOutput: func(c types.Commitment) (bool, error) {
			if v, ok := f.changes.Outputs[c]; ok {
				return v, nil
			}
			return base.seenOutput(c)
		},
		seenKernel: func(h types.Hash) (bool, error) {
			if v, ok := f.changes.Kernels[h]; ok {
				return v, nil
			}
			return base.seenKernel(h)
		},
	}
}
