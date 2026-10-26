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
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pasichDev/noso-go/v2/pow"
	"github.com/pasichDev/noso-go/v2/types"
)

// Chain composes a Store with validation rules, difficulty calculation,
// and reorg support. All mutating operations are serialized through a
// single Mutex so the Store sees a consistent transaction stream.
type Chain struct {
	mu          sync.Mutex
	store       Store
	checkpoints []types.Checkpoint
	now         func() time.Time
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
	if err := validateGenesis(genesis); err != nil {
		return err
	}
	if cp, ok := types.CheckpointForHeight(c.checkpoints, 0); ok && types.HeaderID(&genesis.Header) != cp.Hash {
		return ErrCheckpoint
	}
	switch s := c.store.(type) {
	case *memStore:
		statePath := filepath.Join(dir, "state.gob")
		if data, err := os.ReadFile(statePath); err == nil {
			restored := newMemStore()
			if err := restored.loadGob(data, statePath); err != nil {
				return err
			}
			if err := c.verifyHistory(restored, genesis); err != nil {
				return err
			}
			c.store = restored
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		if _, ok := s.Tip(); ok {
			return c.verifyHistory(s, genesis)
		}
		s.dir = dir
		return s.applyGenesis(genesis)
	case *BadgerStore:
		if _, ok := s.Tip(); ok {
			return c.verifyHistory(s, genesis)
		}
		empty, err := s.isEmpty()
		if err != nil {
			return err
		}
		if !empty {
			return errors.New("chain: missing or corrupt persisted tip")
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

// ValidateBlock checks a candidate extending the current tip without changing
// canonical or persistent state. Fork blocks require staged ReorgTo validation.
func (c *Chain) ValidateBlock(b *types.Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.validate(b)
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

// ReorgTo validates an oldest-first incoming suffix against an isolated state.
// The common ancestor must be within 1024 blocks and preserve checkpoints.
// Only strictly greater valid accumulated work replaces the canonical chain,
// committed atomically by the backend after every candidate block succeeds.
func (c *Chain) ReorgTo(incoming []*types.Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(incoming) == 0 || len(incoming) > 1024 || incoming[0] == nil {
		return errors.New("chain: invalid incoming suffix")
	}
	tip, ok := c.store.Tip()
	if !ok {
		return errors.New("chain: empty chain")
	}
	ancestorHeight, ok := c.store.HeightOf(incoming[0].Header.PrevHash)
	if !ok {
		return ErrUnknownAnc
	}
	if ancestorHeight > tip.Height {
		return ErrUnknownAnc
	}
	if maxCP := types.MaxCheckpointHeight(c.checkpoints); maxCP > 0 && ancestorHeight < maxCP {
		return ErrCheckpoint
	}
	if tip.Height-ancestorHeight > 1024 {
		return ErrTooDeep
	}
	// Reject malformed suffixes before copying any retained history.
	parent := incoming[0].Header.PrevHash
	height := ancestorHeight
	for _, b := range incoming {
		if err := validateStructure(b); err != nil {
			return err
		}
		if height == math.MaxUint64 || b.Header.Height != height+1 || b.Header.PrevHash != parent {
			return ErrStale
		}
		parent = types.HeaderID(&b.Header)
		height++
	}
	// Validate against an isolated copy. No live or durable mutation occurs until
	// every incoming block is validated and its accumulated work strictly wins.
	staged := newMemStore()
	for h := uint64(0); h <= ancestorHeight; h++ {
		b, err := c.store.BlockAt(h)
		if err != nil {
			return err
		}
		if err = staged.WriteBlock(b); err != nil {
			return err
		}
	}
	candidate := &Chain{store: staged, checkpoints: c.checkpoints, now: c.now}
	newWork, oldWork := new(big.Int), new(big.Int)
	for h := ancestorHeight + 1; h <= tip.Height; h++ {
		b, err := c.store.BlockAt(h)
		if err != nil {
			return err
		}
		oldWork.Add(oldWork, blockWork(b.Header.Difficulty))
	}
	for i, b := range incoming {
		if err := candidate.validate(b); err != nil {
			return fmt.Errorf("chain: incoming %d: %w", i, err)
		}
		if err := staged.WriteBlock(b); err != nil {
			return err
		}
		newWork.Add(newWork, blockWork(b.Header.Difficulty))
	}
	if newWork.Cmp(oldWork) <= 0 {
		return errors.New("chain: fork does not have strictly greater work")
	}
	return c.store.ReplaceChain(staged.blocks)
}

// blockWork is floor(2^256/(target+1)), using exactly the target accepted by PoW.
func blockWork(difficulty uint64) *big.Int {
	denominator := new(big.Int).Add(pow.Target(difficulty), big.NewInt(1))
	return new(big.Int).Div(new(big.Int).Lsh(big.NewInt(1), 256), denominator)
}

// ---- validation helpers ------------------------------------------------

// validate runs per-block invariants. Caller holds c.mu.
func (c *Chain) validate(b *types.Block) error {
	if err := validateStructure(b); err != nil {
		return err
	}
	tip, ok := c.store.Tip()
	if !ok {
		return errors.New("chain: initialize trusted genesis first")
	}
	if tip.Height == math.MaxUint64 || b.Header.PrevHash != types.HeaderID(&tip) {
		return ErrStale
	}
	if b.Header.Height != tip.Height+1 {
		return errors.New("chain: wrong height")
	}
	if b.Header.NetworkMagic != tip.NetworkMagic {
		return errors.New("chain: network mismatch")
	}
	if b.Header.Timestamp <= tip.Timestamp {
		return errors.New("chain: timestamp must advance")
	}
	// Consensus accepts at most two hours of future drift relative to the
	// validator's UTC Unix clock. Big integers avoid overflow on hostile timestamps.
	clockNow := time.Now()
	if c.now != nil {
		clockNow = c.now()
	}
	ahead := new(big.Int).Sub(big.NewInt(b.Header.Timestamp), big.NewInt(clockNow.Unix()))
	if ahead.Cmp(big.NewInt(2*60*60)) > 0 {
		return errors.New("chain: timestamp exceeds future drift")
	}

	if b.Header.Difficulty != c.expectedDifficulty() {
		return ErrBadDiff
	}
	if cp, ok := types.CheckpointForHeight(c.checkpoints, b.Header.Height); ok && types.HeaderID(&b.Header) != cp.Hash {
		return ErrCheckpoint
	}
	if !pow.Verify(&b.Header) {
		return ErrBadPoW
	}
	if err := c.validateBody(b, true); err != nil {
		return err
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
		return 0
	} // missing history must stop validation/mining
	for h := tip.Height - N + 1; h <= tip.Height; h++ {
		blk, err := c.store.BlockAt(h)
		if err != nil {
			return 0
		}
		delta := new(big.Int).Sub(big.NewInt(blk.Header.Timestamp), big.NewInt(prev.Header.Timestamp))
		if !delta.IsInt64() {
			solveTimes = append(solveTimes, math.MaxInt64)
		} else {
			solveTimes = append(solveTimes, delta.Int64())
		}
		difficulties = append(difficulties, blk.Header.Difficulty)
		prev = blk
	}
	return pow.LWMA3(solveTimes, difficulties, types.TargetBlockTimeSeconds)
}

// ---- in-memory store implementation (gob-persisted) -------------------

type memStore struct {
	dir        string
	blocks     []*types.Block
	heightOf   map[types.Hash]uint64
	utxo       map[types.Commitment]types.Output
	legacyIdx  map[string]types.Commitment
	outputSeen map[types.Commitment]bool
	kernelSeen map[types.Hash]bool
}

func newMemStore() *memStore {
	return &memStore{
		heightOf:   map[types.Hash]uint64{},
		utxo:       map[types.Commitment]types.Output{},
		legacyIdx:  map[string]types.Commitment{},
		outputSeen: map[types.Commitment]bool{},
		kernelSeen: map[types.Hash]bool{},
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
	return cloneBlock(s.blocks[h]), nil
}

func (s *memStore) BlockByHash(h types.Hash) (*types.Block, error) {
	idx, ok := s.heightOf[h]
	if !ok {
		return nil, errors.New("store: unknown block hash")
	}
	return cloneBlock(s.blocks[idx]), nil
}

func (s *memStore) HasUTXO(c types.Commitment) bool { _, ok := s.utxo[c]; return ok }

func (s *memStore) HasOutput(c types.Commitment) bool { return s.outputSeen[c] }
func (s *memStore) HasKernel(h types.Hash) bool       { return s.kernelSeen[h] }

func (s *memStore) UTXOByCommit(c types.Commitment) (*types.Output, bool) {
	o, ok := s.utxo[c]
	if !ok {
		return nil, false
	}
	o.RangeProof = append([]byte(nil), o.RangeProof...)
	return &o, true
}

func (s *memStore) UTXOByLegacyAddress(addr string) (*types.Output, bool) {
	c, ok := s.legacyIdx[addr]
	if !ok {
		return nil, false
	}
	o := s.utxo[c]
	o.RangeProof = append([]byte(nil), o.RangeProof...)
	return &o, true
}

func (s *memStore) WriteBlock(b *types.Block) error {
	if b == nil {
		return errors.New("store: nil block")
	}
	if b.Header.Height != uint64(len(s.blocks)) {
		return errors.New("store: noncontiguous height")
	}
	if len(s.blocks) > 0 && b.Header.PrevHash != types.HeaderID(&s.blocks[len(s.blocks)-1].Header) {
		return ErrStale
	}
	if len(s.blocks) == 0 && !b.Header.PrevHash.IsZero() {
		return ErrStale
	}
	if _, ok := s.heightOf[types.HeaderID(&b.Header)]; ok {
		return errors.New("store: block hash already exists")
	}
	_, err := checkStoreDelta(b, deltaReader{
		output: func(c types.Commitment) (*types.Output, bool, error) {
			out, ok := s.UTXOByCommit(c)
			return out, ok, nil
		},
		seenOutput: func(c types.Commitment) (bool, error) { return s.HasOutput(c), nil },
		seenKernel: func(id types.Hash) (bool, error) { return s.HasKernel(id), nil },
	})
	if err != nil {
		return err
	}
	b = cloneBlock(b)
	for i := range b.Inputs {
		c := b.Inputs[i].Commit
		if o, ok := s.utxo[c]; ok && o.Features == types.OutputFeaturesLegacy {
			delete(s.legacyIdx, o.LegacyAddress)
		}
		delete(s.utxo, c)
	}
	for i := range b.Outputs {
		s.utxo[b.Outputs[i].Commit] = b.Outputs[i]
		s.outputSeen[b.Outputs[i].Commit] = true
		if b.Outputs[i].Features == types.OutputFeaturesLegacy {
			s.legacyIdx[b.Outputs[i].LegacyAddress] = b.Outputs[i].Commit
		}
	}
	for _, k := range b.Kernels {
		s.kernelSeen[types.KernelID(&k)] = true
	}
	s.blocks = append(s.blocks, b)
	s.heightOf[types.HeaderID(&b.Header)] = b.Header.Height
	return nil
}

func (s *memStore) UndoBlock() error {
	if len(s.blocks) <= 1 {
		return errors.New("store: refuse to undo genesis")
	}
	return s.ReplaceChain(s.blocks[:len(s.blocks)-1])
}

func (s *memStore) ReplaceChain(blocks []*types.Block) error {
	next := newMemStore()
	next.dir = s.dir
	for _, b := range blocks {
		if b == nil {
			return errors.New("store: nil block")
		}
		if err := next.WriteBlock(b); err != nil {
			return err
		}
	}
	*s = *next
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
	if err := os.Rename(tmp, statePath); err != nil {
		return err
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *memStore) Close() error { return s.Save() }

func (s *memStore) loadGob(data []byte, path string) error {
	var blocks []*types.Block
	if err := gob.NewDecoder(bytesReader(data)).Decode(&blocks); err != nil {
		return fmt.Errorf("store: decode %s: %w", path, err)
	}
	if len(blocks) == 0 {
		return errors.New("store: empty snapshot")
	}
	if err := s.ReplaceChain(blocks); err != nil {
		return err
	}
	s.dir = filepath.Dir(path)
	return nil
}
