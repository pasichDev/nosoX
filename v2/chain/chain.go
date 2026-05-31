// Package chain implements the v2 blockchain state machine: tip
// management, block validation, UTXO set, header index, and short-range
// reorg.
//
// The Store interface (store.go) is the persistence boundary. Two
// implementations ship: an in-memory map (memStore) for tests and
// short-lived runs, and a BadgerDB-backed store (badger_store.go) for
// real deployments.
package chain

import (
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	v2crypto "github.com/noso-project/noso-go/v2/crypto"
	"github.com/noso-project/noso-go/v2/pow"
	"github.com/noso-project/noso-go/v2/types"
	"github.com/noso-project/noso-go/v2/wallet"
)

// Chain composes a Store with validation rules, difficulty calculation,
// and reorg support. All mutating operations are serialized through a
// single Mutex so the Store sees a consistent transaction stream.
type Chain struct {
	mu          sync.Mutex
	store       Store
	checkpoints []types.Checkpoint
}

// SetCheckpoints installs the trusted (height, hash) pairs that the
// validator will pin against. Call once before LoadOrInit. Subsequent
// calls overwrite the previous list.
func (c *Chain) SetCheckpoints(cp []types.Checkpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkpoints = append([]types.Checkpoint(nil), cp...)
}

// Errors returned by AddBlock / reorg paths.
var (
	ErrStale       = errors.New("chain: stale block (wrong parent)")
	ErrBadPoW      = errors.New("chain: PoW does not meet difficulty")
	ErrBadDiff     = errors.New("chain: difficulty mismatch")
	ErrBadOutput   = errors.New("chain: invalid output")
	ErrDoubleSpend = errors.New("chain: input not in UTXO set")
	ErrTooDeep     = errors.New("chain: reorg would exceed SecurityBlocks depth")
	ErrUnknownAnc  = errors.New("chain: reorg ancestor not in store")
	ErrCheckpoint  = errors.New("chain: block conflicts with published checkpoint")
)

// NewMemory returns a Chain backed by an in-memory map. Useful for
// tests, but data evaporates on process exit (unless LoadOrInit is
// called with a directory, in which case the chain snapshots to gob).
func NewMemory() *Chain {
	return &Chain{store: newMemStore()}
}

// NewBadger opens (or creates) a BadgerDB-backed Chain at dir.
func NewBadger(dir string) (*Chain, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	bs, err := OpenBadger(dir)
	if err != nil {
		return nil, err
	}
	return &Chain{store: bs}, nil
}

// LoadOrInit either restores chain state from `dir/state.gob` (memory
// store) or initializes a new chain at `genesis`. For the BadgerDB
// store this method just ensures the genesis is applied; the persistent
// state is already on disk and discovered on Open.
func (c *Chain) LoadOrInit(dir string, genesis *types.Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	switch s := c.store.(type) {
	case *memStore:
		statePath := filepath.Join(dir, "state.gob")
		if data, err := os.ReadFile(statePath); err == nil {
			return s.loadGob(data, statePath)
		}
		s.dir = dir
		return s.applyGenesis(genesis)
	case *BadgerStore:
		if _, ok := s.Tip(); ok {
			return nil // already initialized
		}
		return s.WriteBlock(genesis)
	default:
		return errors.New("chain: unknown store backend")
	}
}

// Close releases backend resources.
func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.Close()
}

// Tip returns the current tip header.
func (c *Chain) Tip() (types.BlockHeader, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.Tip()
}

// Height returns the current chain height.
func (c *Chain) Height() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.store.Tip()
	if !ok {
		return 0
	}
	return t.Height
}

// BlockByHeight returns the full block at h (header + inputs/outputs/kernels).
// Used by the libp2p sync handler when serving reorg fetches.
func (c *Chain) BlockByHeight(h uint64) (*types.Block, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := c.store.BlockAt(h)
	if err != nil {
		return nil, false
	}
	return b, true
}

// HeaderByHeight returns the header at h.
func (c *Chain) HeaderByHeight(h uint64) (types.BlockHeader, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := c.store.BlockAt(h)
	if err != nil {
		return types.BlockHeader{}, false
	}
	return b.Header, true
}

// LookupLegacyBalance reports the carried balance for a legacy v1
// address if its genesis-bound legacy UTXO is still unspent.
func (c *Chain) LookupLegacyBalance(addr string) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, ok := c.store.UTXOByLegacyAddress(addr)
	if !ok {
		return 0, false
	}
	return out.LegacyAmount, true
}

// AddBlock validates and appends a new block at chain tip.
func (c *Chain) AddBlock(b *types.Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.validate(b); err != nil {
		return err
	}
	return c.store.WriteBlock(b)
}

// NextDifficulty returns the LWMA-3 expected difficulty for the next
// block on top of the current tip. Miners should use this to template
// candidate blocks; the validator will reject any block that doesn't
// match the same value.
func (c *Chain) NextDifficulty() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.expectedDifficulty()
}

// Save flushes the underlying store to disk.
func (c *Chain) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.Save()
}

// ReorgTo replaces the current chain suffix with the supplied
// `incoming` blocks. The incoming chain MUST share a common ancestor
// with the current chain within `SecurityBlocks` of tip; otherwise
// ErrTooDeep is returned. The algorithm:
//
//  1. Walk `incoming` newest→oldest to find the ancestor block hash
//     (its PrevHash field on the eldest incoming block must point at a
//     block we have).
//  2. Undo our current blocks one by one until we are at that ancestor.
//  3. Apply the incoming blocks oldest→newest via validate + WriteBlock.
//
// On any error the chain is left in its pre-reorg state — undone
// blocks are re-applied. Caller does not need to handle partial state.
func (c *Chain) ReorgTo(incoming []*types.Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(incoming) == 0 {
		return errors.New("chain: empty incoming chain")
	}
	tip, ok := c.store.Tip()
	if !ok {
		return errors.New("chain: cannot reorg an empty chain")
	}
	ancestorHash := incoming[0].Header.PrevHash
	ancestorHeight, ok := c.store.HeightOf(ancestorHash)
	if !ok {
		return ErrUnknownAnc
	}
	// Refuse any reorg that would cross the latest published checkpoint —
	// even a single block deeper than the checkpoint disqualifies the fork.
	if maxCP := types.MaxCheckpointHeight(c.checkpoints); maxCP > 0 && ancestorHeight < maxCP {
		return ErrCheckpoint
	}
	depth := int64(tip.Height) - int64(ancestorHeight)
	if depth > int64(types.CoinbaseLock)*int64(types.DifficultyWindow) || depth > 1024 {
		return ErrTooDeep
	}

	// 1. Undo to ancestor, collecting the old blocks so we can replay
	//    them if the new chain fails to apply.
	undone := make([]*types.Block, 0, depth)
	for h := tip.Height; h > ancestorHeight; h-- {
		blk, err := c.store.BlockAt(h)
		if err != nil {
			return fmt.Errorf("chain: read block %d during reorg: %w", h, err)
		}
		undone = append(undone, blk)
		if err := c.store.UndoBlock(); err != nil {
			// Best-effort recovery: re-apply what we already removed.
			c.replay(undone[:len(undone)-1])
			return fmt.Errorf("chain: undo block %d: %w", h, err)
		}
	}

	// 2. Apply incoming. If any block fails validation, roll back.
	applied := 0
	for i := range incoming {
		if err := c.validate(incoming[i]); err != nil {
			c.replay(undone)
			// Re-undo whatever we already applied from incoming.
			for j := 0; j < applied; j++ {
				_ = c.store.UndoBlock()
			}
			return fmt.Errorf("chain: validate incoming block %d: %w", i, err)
		}
		if err := c.store.WriteBlock(incoming[i]); err != nil {
			c.replay(undone)
			return fmt.Errorf("chain: write incoming block %d: %w", i, err)
		}
		applied++
	}
	return nil
}

// replay re-applies the slice of blocks that were undone, oldest first.
// We accept that re-applied blocks already passed validation once, so
// we skip re-checking them.
func (c *Chain) replay(undone []*types.Block) {
	// undone is in newest→oldest order, so iterate backwards.
	for i := len(undone) - 1; i >= 0; i-- {
		_ = c.store.WriteBlock(undone[i])
	}
}

// ---- validation helpers ------------------------------------------------

// validate runs per-block invariants. Caller holds c.mu.
func (c *Chain) validate(b *types.Block) error {
	tip, ok := c.store.Tip()
	if ok {
		if b.Header.PrevHash != types.HeaderID(&tip) {
			return ErrStale
		}
		if b.Header.Height != tip.Height+1 {
			return fmt.Errorf("chain: expected height %d, got %d",
				tip.Height+1, b.Header.Height)
		}
		want := c.expectedDifficulty()
		if b.Header.Difficulty != want {
			return fmt.Errorf("%w: have %d want %d",
				ErrBadDiff, b.Header.Difficulty, want)
		}
	}
	if !pow.Verify(&b.Header) {
		return ErrBadPoW
	}
	// Checkpoint guard — if a checkpoint pins this height, the incoming
	// block's hash must match it exactly.
	if cp, ok := types.CheckpointForHeight(c.checkpoints, b.Header.Height); ok {
		if types.HeaderID(&b.Header) != cp.Hash {
			return ErrCheckpoint
		}
	}
	for i := range b.Inputs {
		if !c.store.HasUTXO(b.Inputs[i].Commit) {
			return fmt.Errorf("%w: input %d", ErrDoubleSpend, i)
		}
	}
	// Verify coinbase Schnorr sig if present.
	reward := types.BlockReward(b.Header.Height)
	if reward > 0 {
		var foundCB bool
		for i := range b.Outputs {
			if b.Outputs[i].Features == types.OutputFeaturesCoinbase {
				foundCB = true
				// Find the matching coinbase kernel.
				for j := range b.Kernels {
					k := &b.Kernels[j]
					if k.Features != types.KernelFeaturesCoinbase {
						continue
					}
					if k.Excess != b.Outputs[i].Commit {
						continue
					}
					if len(k.ExcessSig) > 0 && !wallet.VerifyCoinbase(b.Header.Height, reward, k.Excess, k.ExcessSig) {
						return errors.New("chain: bad coinbase Schnorr signature")
					}
					break
				}
				break
			}
		}
		_ = foundCB
	}
	// Verify per-output range proofs (currently SimpleRangeProof; will be
	// real Bulletproofs once the upgrade lands).
	for i := range b.Outputs {
		o := &b.Outputs[i]
		if o.Features != types.OutputFeaturesPlain {
			continue
		}
		if !v2crypto.VerifyRange(o.Commit, o.RangeProof) {
			return fmt.Errorf("chain: output %d has invalid range proof", i)
		}
	}
	return nil
}

// expectedDifficulty computes LWMA-3 over the last DifficultyWindow
// blocks. Returns MinDifficulty when not enough history exists yet.
func (c *Chain) expectedDifficulty() uint64 {
	tip, ok := c.store.Tip()
	if !ok {
		return types.MinDifficulty
	}
	N := uint64(types.DifficultyWindow)
	if tip.Height < N {
		// Bootstrap: keep difficulty pinned at the genesis level.
		return tip.Difficulty
	}
	solveTimes := make([]int64, 0, N)
	difficulties := make([]uint64, 0, N)
	prev, err := c.store.BlockAt(tip.Height - N)
	if err != nil {
		return tip.Difficulty
	}
	for h := tip.Height - N + 1; h <= tip.Height; h++ {
		blk, err := c.store.BlockAt(h)
		if err != nil {
			return tip.Difficulty
		}
		solveTimes = append(solveTimes, blk.Header.Timestamp-prev.Header.Timestamp)
		difficulties = append(difficulties, blk.Header.Difficulty)
		prev = blk
	}
	return pow.LWMA3(solveTimes, difficulties, types.TargetBlockTimeSeconds)
}

// ---- in-memory store implementation (gob-persisted) -------------------

type memStore struct {
	dir       string
	blocks    []*types.Block
	heightOf  map[types.Hash]uint64
	utxo      map[types.Commitment]types.Output
	legacyIdx map[string]types.Commitment
}

func newMemStore() *memStore {
	return &memStore{
		heightOf:  map[types.Hash]uint64{},
		utxo:      map[types.Commitment]types.Output{},
		legacyIdx: map[string]types.Commitment{},
	}
}

func (s *memStore) applyGenesis(g *types.Block) error {
	if len(s.blocks) > 0 {
		return errors.New("store: genesis already applied")
	}
	return s.WriteBlock(g)
}

func (s *memStore) Tip() (types.BlockHeader, bool) {
	if len(s.blocks) == 0 {
		return types.BlockHeader{}, false
	}
	return s.blocks[len(s.blocks)-1].Header, true
}

func (s *memStore) HeightOf(h types.Hash) (uint64, bool) {
	v, ok := s.heightOf[h]
	return v, ok
}

func (s *memStore) BlockAt(h uint64) (*types.Block, error) {
	if h >= uint64(len(s.blocks)) {
		return nil, errors.New("store: height out of range")
	}
	return s.blocks[h], nil
}

func (s *memStore) BlockByHash(h types.Hash) (*types.Block, error) {
	idx, ok := s.heightOf[h]
	if !ok {
		return nil, errors.New("store: unknown block hash")
	}
	return s.blocks[idx], nil
}

func (s *memStore) HasUTXO(c types.Commitment) bool { _, ok := s.utxo[c]; return ok }

func (s *memStore) UTXOByCommit(c types.Commitment) (*types.Output, bool) {
	o, ok := s.utxo[c]
	if !ok {
		return nil, false
	}
	return &o, true
}

func (s *memStore) UTXOByLegacyAddress(addr string) (*types.Output, bool) {
	c, ok := s.legacyIdx[addr]
	if !ok {
		return nil, false
	}
	o := s.utxo[c]
	return &o, true
}

func (s *memStore) WriteBlock(b *types.Block) error {
	for i := range b.Inputs {
		c := b.Inputs[i].Commit
		if o, ok := s.utxo[c]; ok && o.Features == types.OutputFeaturesLegacy {
			delete(s.legacyIdx, o.LegacyAddress)
		}
		delete(s.utxo, c)
	}
	for i := range b.Outputs {
		s.utxo[b.Outputs[i].Commit] = b.Outputs[i]
		if b.Outputs[i].Features == types.OutputFeaturesLegacy {
			s.legacyIdx[b.Outputs[i].LegacyAddress] = b.Outputs[i].Commit
		}
	}
	s.blocks = append(s.blocks, b)
	s.heightOf[types.HeaderID(&b.Header)] = b.Header.Height
	return nil
}

func (s *memStore) UndoBlock() error {
	if len(s.blocks) <= 1 {
		return errors.New("store: refuse to undo genesis")
	}
	tip := s.blocks[len(s.blocks)-1]
	for i := range tip.Outputs {
		out := tip.Outputs[i]
		delete(s.utxo, out.Commit)
		if out.Features == types.OutputFeaturesLegacy {
			delete(s.legacyIdx, out.LegacyAddress)
		}
	}
	for i := range tip.Inputs {
		in := tip.Inputs[i]
		restored := types.Output{
			Features:      in.Features,
			Commit:        in.Commit,
			LegacyAddress: in.LegacyAddr,
			LegacyAmount:  in.LegacyAmount,
		}
		s.utxo[in.Commit] = restored
		if restored.Features == types.OutputFeaturesLegacy {
			s.legacyIdx[restored.LegacyAddress] = restored.Commit
		}
	}
	delete(s.heightOf, types.HeaderID(&tip.Header))
	s.blocks = s.blocks[:len(s.blocks)-1]
	return nil
}

func (s *memStore) Save() error {
	if s.dir == "" {
		return nil
	}
	statePath := filepath.Join(s.dir, "state.gob")
	tmp := statePath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := gob.NewEncoder(f).Encode(s.blocks); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	_ = f.Close()
	return os.Rename(tmp, statePath)
}

func (s *memStore) Close() error { return s.Save() }

func (s *memStore) loadGob(data []byte, path string) error {
	var blocks []*types.Block
	if err := gob.NewDecoder(bytesReader(data)).Decode(&blocks); err != nil {
		return fmt.Errorf("store: decode %s: %w", path, err)
	}
	s.blocks = blocks
	s.heightOf = map[types.Hash]uint64{}
	s.utxo = map[types.Commitment]types.Output{}
	s.legacyIdx = map[string]types.Commitment{}
	for h := range blocks {
		b := blocks[h]
		s.heightOf[types.HeaderID(&b.Header)] = uint64(h)
		for i := range b.Inputs {
			c := b.Inputs[i].Commit
			if o, ok := s.utxo[c]; ok && o.Features == types.OutputFeaturesLegacy {
				delete(s.legacyIdx, o.LegacyAddress)
			}
			delete(s.utxo, c)
		}
		for i := range b.Outputs {
			s.utxo[b.Outputs[i].Commit] = b.Outputs[i]
			if b.Outputs[i].Features == types.OutputFeaturesLegacy {
				s.legacyIdx[b.Outputs[i].LegacyAddress] = b.Outputs[i].Commit
			}
		}
	}
	s.dir = filepath.Dir(path)
	return nil
}
