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
	"bytes"
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
// and reorg support.
//
// Two locks. writeMu serializes everything that changes canonical state
// (AddBlock, ReorgTo, LoadOrInit) from start to finish, including the slow
// Argon2 and proof work, so one writer can run that work without holding mu.
// mu protects the Store and is held only for short, bounded sections; readers
// (Tip, Height, RPC, mining) therefore never wait on proof-of-work or
// range-proof verification.
type Chain struct {
	writeMu     sync.Mutex
	mu          sync.Mutex
	store       Store
	checkpoints []types.Checkpoint
	now         func() time.Time
	work        workCache

	rejected rejectedForks

	listenMu  sync.RWMutex
	listeners []func(Change)

	// Verified-history marker (see verified_marker.go).
	fullVerify  bool
	markerDir   string
	sinceMarker uint64
}

// Change describes a canonical-chain transition: Disconnected blocks (newest
// first) were removed and Connected blocks (oldest first) were applied.
type Change struct {
	Disconnected []*types.Block
	Connected    []*types.Block
}

// Subscribe registers fn to be called after every accepted block or reorg, in
// commit order. fn runs outside mu (the state lock) but INSIDE writeMu: it may
// call the Chain's read and validation methods, but must not call AddBlock,
// ReorgTo, LoadOrInit or Close (they take writeMu and would deadlock), and a slow
// fn delays every later write.
func (c *Chain) Subscribe(fn func(Change)) {
	c.listenMu.Lock()
	c.listeners = append(c.listeners, fn)
	c.listenMu.Unlock()
}

func (c *Chain) notify(ch Change) {
	c.listenMu.RLock()
	ls := append([]func(Change){}, c.listeners...)
	c.listenMu.RUnlock()
	for _, fn := range ls {
		fn(ch)
	}
}

// SetCheckpoints installs the trusted (height, hash) pairs that the
// validator will pin against. Call once before LoadOrInit. Subsequent
// calls overwrite the previous list.
func (c *Chain) SetCheckpoints(cp []types.Checkpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkpoints = append([]types.Checkpoint(nil), cp...)
}

// SetFullVerify forces a complete consensus replay at the next LoadOrInit even
// when a verified-history marker is present.
func (c *Chain) SetFullVerify(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fullVerify = on
}

// Errors returned by AddBlock / reorg paths.
var (
	ErrStale           = errors.New("chain: stale block (wrong parent)")
	ErrBadPoW          = errors.New("chain: PoW does not meet difficulty")
	ErrBadDiff         = errors.New("chain: difficulty mismatch")
	ErrBadOutput       = errors.New("chain: invalid output")
	ErrDoubleSpend     = errors.New("chain: input not in UTXO set")
	ErrTooDeep         = errors.New("chain: reorg would exceed MaxReorgBlocks depth")
	ErrUnknownAnc      = errors.New("chain: reorg ancestor not in store")
	ErrCheckpoint      = errors.New("chain: block conflicts with published checkpoint")
	ErrFutureTimestamp = errors.New("chain: timestamp exceeds future drift")
	ErrLowWork         = errors.New("chain: fork does not have strictly greater work")

	// ErrInvalidBlock wraps every rejection that follows from the block (or the
	// peer's own batch) and the parent chain it names, and from nothing else: a
	// peer that sent it can be penalized. Rejections that depend on our clock, our
	// tip moving, our limits or our disk never carry it (see IsPeerFault).
	ErrInvalidBlock = errors.New("chain: invalid block")
	// ErrNotLinked: a fork suffix whose blocks do not hash-link to each other.
	// Provable from the batch alone, but it says nothing about any block's own
	// header hash (so a caller must not blame an ID for it).
	ErrNotLinked = errors.New("chain: suffix does not link")
	// ErrTxState marks a rejection that depends on chain state the sender may
	// legitimately know better than we do (missing input, immature coinbase, lock
	// height, already-seen output or kernel). For a gossiped transaction it is
	// never the relay's fault; for a block on our tip it is still invalid.
	ErrTxState = errors.New("chain: transaction depends on state")
	// ErrStorage marks a rejection observed while the store reported read errors.
	ErrStorage = errors.New("chain: storage fault")
)

// IsPeerFault reports whether err proves the block or fork was invalid, so the
// peer that served it may be penalized. It is an allowlist: ErrStale,
// ErrLowWork, ErrFutureTimestamp, ErrResourceBudget, ErrTooDeep, ErrCheckpoint,
// store errors and anything unclassified are never a peer's fault.
func IsPeerFault(err error) bool {
	return errors.Is(err, ErrInvalidBlock) && !errors.Is(err, ErrStorage)
}

// storeFaults is implemented by stores that can report swallowed read errors.
type storeFaults interface{ Faults() uint64 }

func (c *Chain) faults() uint64 {
	if f, ok := c.store.(storeFaults); ok {
		return f.Faults()
	}
	return 0
}

// classify marks a validation error as invalid-block unless it is one of the
// conditions that depend on local state, or the store misbehaved meanwhile.
func (c *Chain) classify(err error, faults0 uint64) error {
	switch {
	case err == nil:
		return nil
	case c.faults() != faults0:
		return fmt.Errorf("%w: %w", ErrStorage, err)
	}
	for _, local := range []error{ErrStale, ErrLowWork, ErrFutureTimestamp, ErrResourceBudget, ErrTooDeep, ErrUnknownAnc, ErrCheckpoint, ErrStorage, ErrInvalidBlock} {
		if errors.Is(err, local) {
			return err
		}
	}
	return fmt.Errorf("%w: %w", ErrInvalidBlock, err)
}

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
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
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
			c.work = workCache{} // computed lazily for the in-memory store
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
		// markerDir stays unset until the stored chain has been verified, so a
		// failed load followed by Close can never record an unverified tip.
		if _, ok := s.Tip(); ok {
			return c.openVerifiedBadger(s, dir, genesis)
		}
		empty, err := s.isEmpty()
		if err != nil {
			return err
		}
		if !empty {
			return errors.New("chain: missing or corrupt persisted tip")
		}
		if err := s.WriteBlock(genesis); err != nil {
			return err
		}
		c.seedWorkLocked(blockWork(genesis.Header.Difficulty))
		c.markerDir = dir
		return c.writeMarkerLocked()
	default:
		return errors.New("chain: unknown store backend")
	}

}

// Close releases backend resources.
func (c *Chain) Close() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.markerDir != "" {
		// Everything in the store was validated on the way in; record that so
		// the next start does not repeat it. Best effort: a missing marker only
		// costs a full replay.
		_ = c.writeMarkerLocked()
	}
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

// AddBlock validates and appends a new block at chain tip.
//
// Order: cheap header checks (parent, height, time, difficulty, checkpoint)
// under mu; then proof-of-work and signatures/range proofs with no lock held
// (a cache makes a block already checked by ValidateBlock free); then the
// state-dependent body checks and the write under mu again. writeMu keeps the
// tip from changing in between.
func (c *Chain) AddBlock(b *types.Block) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	f0 := c.faults()
	if _, err := c.validateUnlockedPoW(b, true); err != nil {
		return c.classify(err, f0)
	}
	c.mu.Lock()
	if err := c.validateBody(b, true); err != nil {
		c.mu.Unlock()
		return c.classify(err, f0)
	}
	if err := c.store.WriteBlock(b); err != nil {
		c.mu.Unlock()
		return err
	}
	c.noteAppendedLocked(1)
	c.mu.Unlock()
	c.notify(Change{Connected: []*types.Block{cloneBlock(b)}})
	return nil
}

// ValidateBlock checks a candidate extending the current tip without changing
// canonical or persistent state. Fork blocks require staged ReorgTo validation.
// It does not take writeMu, so gossip validation never delays an accepted write.
func (c *Chain) ValidateBlock(b *types.Block) error {
	f0 := c.faults()
	tipID, err := c.validateUnlockedPoW(b, true)
	if err != nil {
		return c.classify(err, f0)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Without writeMu the tip may have moved while proofs were checked.
	if tip, ok := c.store.Tip(); !ok || types.HeaderID(&tip) != tipID {
		return ErrStale
	}
	return c.classify(c.validateBody(b, true), f0)
}

// validateUnlockedPoW runs the header checks under mu and the expensive
// stateless verification without it. clock selects the wall-clock future rule.
func (c *Chain) validateUnlockedPoW(b *types.Block, clock bool) (types.Hash, error) {
	if b == nil {
		return types.Hash{}, errors.New("chain: nil block")
	}
	c.mu.Lock()
	err := c.checkHeader(b, clock)
	c.mu.Unlock()
	if err != nil {
		return types.Hash{}, err
	}
	tipID := b.Header.PrevHash // checkHeader verified it equals the tip hash
	return tipID, verifyStateless(b)
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

// permanentForkError reports errors that are a property of the fork alone, so
// remembering the fork's head hash is sound. Errors that depend on the local
// clock, on what we currently hold (ErrLowWork included) or on the disk must
// never be remembered as "this fork is invalid".
func permanentForkError(err error) bool {
	if errors.Is(err, ErrStorage) {
		return false
	}
	for _, e := range []error{ErrBadPoW, ErrBadDiff, ErrBadOutput, ErrDoubleSpend, ErrCheckpoint} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// ReorgTo validates an oldest-first incoming suffix against an isolated state.
// The common ancestor must be within MaxReorgBlocks and preserve checkpoints.
// Only strictly greater valid accumulated work replaces the canonical chain,
// committed atomically by the backend after every candidate block succeeds.
//
// Cost control, cheapest first: blocks identical to canonical are trimmed; the
// declared work of the suffix must exceed ours before anything is validated;
// header and state-dependent checks run against an isolated fork state; only
// then are proof-of-work (head first) and proofs verified, outside mu. A fork
// that failed for a permanent reason is remembered by head hash.
func (c *Chain) ReorgTo(incoming []*types.Block) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(incoming) == 0 || len(incoming) > MaxReorgBlocks || incoming[0] == nil {
		return errors.New("chain: invalid incoming suffix")
	}
	head := incoming[len(incoming)-1]
	if head == nil {
		return errors.New("chain: invalid incoming suffix")
	}
	headID := types.HeaderID(&head.Header)
	if c.rejected.has(headID) {
		return ErrLowWork
	}
	removed, trimmed, ancestorHeight, oldWork, newWork, err := c.stageFork(incoming, func(trimmed []*types.Block) error {
		// Proof of work, head backwards, with no lock held, once the cheap checks
		// (shape, declared work above ours) passed and before any state is staged: a
		// forged fork has to pay for hashes before it can make us read history.
		for i := len(trimmed) - 1; i >= 0; i-- {
			if err := verifyPoW(&trimmed[i].Header); err != nil {
				c.rejected.add(headID)
				return fmt.Errorf("%w: incoming %d: %w", ErrInvalidBlock, i, err)
			}
		}
		return nil
	})
	if err != nil {
		if permanentForkError(err) {
			c.rejected.add(headID)
		}
		return err
	}
	// Expensive, state-independent verification with no lock held.
	for _, b := range trimmed {
		if err := verifyStateless(b); err != nil {
			c.rejected.add(headID)
			return fmt.Errorf("%w: chain: incoming %d: %w", ErrInvalidBlock, b.Header.Height-ancestorHeight-1, err)
		}
	}
	c.mu.Lock()
	tipBefore, _ := c.store.Tip()
	if err := c.store.ReplaceSuffix(ancestorHeight, trimmed); err != nil {
		c.mu.Unlock()
		return err
	}
	// Keep the work cache valid across the reorganisation so the next TotalWork
	// does not walk the whole chain under mu.
	newTip := trimmed[len(trimmed)-1].Header
	if c.work.total != nil && c.work.tip == types.HeaderID(&tipBefore) {
		total := new(big.Int).Sub(c.work.total, oldWork)
		total.Add(total, newWork)
		c.work = workCache{total: total, tip: types.HeaderID(&newTip), height: newTip.Height}
	} else {
		c.work = workCache{}
	}
	c.noteAppendedLocked(uint64(len(trimmed)))
	c.mu.Unlock()
	c.notify(Change{Disconnected: removed, Connected: cloneBlocks(trimmed)})
	return nil
}

func cloneBlocks(in []*types.Block) []*types.Block {
	out := make([]*types.Block, len(in))
	for i, b := range in {
		out[i] = cloneBlock(b)
	}
	return out
}

// stageFork performs every check that needs chain state, under mu, and
// returns the blocks the fork would disconnect (newest first), the suffix with
// the shared canonical prefix removed, and the ancestor height.
//
// It runs with writeMu held and WITHOUT mu: writeMu excludes every writer, the
// store is only read here (candidate state lives in an overlay), so readers keep
// running while a long fork is staged.
func (c *Chain) stageFork(incoming []*types.Block, powCheck func([]*types.Block) error) (removed, trimmed []*types.Block, ancestorHeight uint64, oldWork, newWork *big.Int, err error) {
	f0 := c.faults()
	fail := func(err error) ([]*types.Block, []*types.Block, uint64, *big.Int, *big.Int, error) {
		return nil, nil, 0, nil, nil, err
	}
	tip, ok := c.store.Tip()
	if !ok {
		return fail(errors.New("chain: empty chain"))
	}
	// Drop blocks identical to canonical ones; a peer that sends a window
	// starting below the fork point is not asking us to reorganize those.
	for len(incoming) > 0 && incoming[0] != nil && incoming[0].Header.Height <= tip.Height {
		canon, err := c.store.BlockAt(incoming[0].Header.Height)
		if err != nil || types.HeaderID(&canon.Header) != types.HeaderID(&incoming[0].Header) {
			break
		}
		incoming = incoming[1:]
	}
	if len(incoming) == 0 {
		return fail(ErrLowWork)
	}
	if incoming[0] == nil {
		return fail(errors.New("chain: invalid incoming suffix"))
	}
	ancestorHeight, ok = c.store.HeightOf(incoming[0].Header.PrevHash)
	if !ok || ancestorHeight > tip.Height {
		return fail(ErrUnknownAnc)
	}
	// A checkpoint pins history once the node holds it: refuse a fork that would
	// disconnect a checkpointed block. A canonical block at a checkpoint height
	// that does NOT match the checkpoint is exactly what a reorganisation should
	// replace, so it does not pin anything.
	for _, cp := range c.checkpoints {
		if cp.Height > ancestorHeight && cp.Height <= tip.Height {
			if canon, err := c.store.BlockAt(cp.Height); err == nil && types.HeaderID(&canon.Header) != cp.Hash {
				continue
			}
			return fail(ErrCheckpoint)
		}
	}
	if tip.Height-ancestorHeight > MaxReorgBlocks {
		return fail(ErrTooDeep)
	}
	if err := CheckReorgResourceBudget(incoming); err != nil {
		return fail(err)
	}
	// Reject malformed suffixes before reading history or staging rollback state.
	parent := incoming[0].Header.PrevHash
	height := ancestorHeight
	declared := new(big.Int)
	for i, b := range incoming {
		if b == nil {
			return fail(errors.New("chain: invalid incoming suffix"))
		}
		if err := validateStructure(b); err != nil {
			return fail(c.classify(err, f0))
		}
		if height == math.MaxUint64 || b.Header.Height != height+1 || b.Header.PrevHash != parent {
			// The suffix does not link to itself: provable from the peer's data.
			return fail(fmt.Errorf("%w: %w: incoming %d does not extend its predecessor", ErrInvalidBlock, ErrNotLinked, i))
		}
		parent = types.HeaderID(&b.Header)
		height++
		declared.Add(declared, blockWork(b.Header.Difficulty))
	}
	oldWork = new(big.Int)
	for h := tip.Height; h > ancestorHeight; h-- {
		b, err := c.store.BlockAt(h)
		if err != nil {
			return fail(fmt.Errorf("%w: %w", ErrStorage, err))
		}
		removed = append(removed, b)
		oldWork.Add(oldWork, blockWork(b.Header.Difficulty))
	}
	// Declared difficulties are only trusted after validation below, but a
	// fork whose declared work is not larger cannot win whatever it proves.
	if declared.Cmp(oldWork) <= 0 {
		return fail(ErrLowWork)
	}
	if powCheck != nil {
		if err := powCheck(incoming); err != nil {
			return fail(err)
		}
	}
	staged, err := newForkStore(c.store, ancestorHeight)
	if err != nil {
		return fail(fmt.Errorf("%w: %w", ErrStorage, err))
	}
	candidate := &Chain{store: staged, checkpoints: c.checkpoints, now: c.now}
	newWork = new(big.Int)
	for i, b := range incoming {
		// Same rules as AddBlock apart from the stateless proof work.
		if err := candidate.checkHeader(b, true); err != nil {
			return fail(fmt.Errorf("chain: incoming %d: %w", i, c.classify(err, f0)))
		}
		if err := candidate.validateBody(b, true); err != nil {
			return fail(fmt.Errorf("chain: incoming %d: %w", i, c.classify(err, f0)))
		}
		if err := staged.WriteBlock(b); err != nil {
			return fail(fmt.Errorf("%w: %w", ErrStorage, err))
		}
		newWork.Add(newWork, blockWork(b.Header.Difficulty))
	}
	if newWork.Cmp(oldWork) <= 0 {
		return fail(ErrLowWork)
	}
	return removed, incoming, ancestorHeight, oldWork, newWork, nil
}

// blockWork is floor(2^256/(target+1)), using exactly the target accepted by PoW.
func blockWork(difficulty uint64) *big.Int {
	denominator := new(big.Int).Add(pow.Target(difficulty), big.NewInt(1))
	return new(big.Int).Div(new(big.Int).Lsh(big.NewInt(1), 256), denominator)
}

// ---- validation helpers ------------------------------------------------

// checkHeader runs the cheap per-block checks that need chain state: format,
// parent, height, network, timestamp, difficulty, checkpoint. Caller holds
// c.mu. clock enables the wall-clock future-time rule; replay of persisted
// blocks passes false, since "too far in the future" is a relay-time rule and a
// stored block must stay valid after a clock step.
func (c *Chain) checkHeader(b *types.Block, clock bool) error {
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
	if clock {
		clockNow := time.Now()
		if c.now != nil {
			clockNow = c.now()
		}
		// Big integers avoid overflow on hostile timestamps.
		ahead := new(big.Int).Sub(big.NewInt(b.Header.Timestamp), big.NewInt(clockNow.Unix()))
		if ahead.Cmp(big.NewInt(types.MaxFutureDriftSeconds)) > 0 {
			return ErrFutureTimestamp
		}
	}
	if b.Header.Difficulty != c.expectedDifficulty() {
		return ErrBadDiff
	}
	if cp, ok := types.CheckpointForHeight(c.checkpoints, b.Header.Height); ok && types.HeaderID(&b.Header) != cp.Hash {
		return ErrCheckpoint
	}
	return nil
}

// validate runs every per-block rule while the caller holds c.mu: the path for
// startup replay and isolated checking, where nothing else contends for the
// lock. Live paths use the split form (header, stateless, body) instead.
func (c *Chain) validate(b *types.Block, clock bool) error {
	if err := c.checkHeader(b, clock); err != nil {
		return err
	}
	if err := verifyStateless(b); err != nil {
		return err
	}
	return c.validateBody(b, true)
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
	blocks     map[uint64]*types.Block
	undo       map[uint64][]types.Output
	heightOf   map[types.Hash]uint64
	utxo       map[types.Commitment]types.Output
	outputSeen map[types.Commitment]uint64
	kernelSeen map[types.Hash]bool
}

func newMemStore() *memStore {
	return &memStore{
		blocks:     map[uint64]*types.Block{},
		undo:       map[uint64][]types.Output{},
		heightOf:   map[types.Hash]uint64{},
		utxo:       map[types.Commitment]types.Output{},
		outputSeen: map[types.Commitment]uint64{},
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
	return s.blocks[uint64(len(s.blocks)-1)].Header, true
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

func (s *memStore) HasOutput(c types.Commitment) bool { _, ok := s.outputSeen[c]; return ok }
func (s *memStore) OutputHeight(c types.Commitment) (uint64, bool) {
	h, ok := s.outputSeen[c]
	return h, ok
}
func (s *memStore) HasKernel(h types.Hash) bool { return s.kernelSeen[h] }

func (s *memStore) UTXOByCommit(c types.Commitment) (*types.Output, bool) {
	o, ok := s.utxo[c]
	if !ok {
		return nil, false
	}
	o.RangeProof = append([]byte(nil), o.RangeProof...)
	return &o, true
}

func (s *memStore) WriteBlock(b *types.Block) error {
	if b == nil {
		return errors.New("store: nil block")
	}
	if err := bodyBounds(b); err != nil {
		return err
	}
	if b.Header.Height != uint64(len(s.blocks)) {
		return errors.New("store: noncontiguous height")
	}
	if len(s.blocks) > 0 && b.Header.PrevHash != types.HeaderID(&s.blocks[uint64(len(s.blocks)-1)].Header) {
		return ErrStale
	}
	if len(s.blocks) == 0 && !b.Header.PrevHash.IsZero() {
		return ErrStale
	}
	if _, ok := s.heightOf[types.HeaderID(&b.Header)]; ok {
		return errors.New("store: block hash already exists")
	}
	spent, err := checkStoreDelta(b, deltaReader{
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
	if _, err := undoResourceBytes(spent); err != nil {
		return err
	}
	b = cloneBlock(b)
	for i := range b.Inputs {
		c := b.Inputs[i].Commit
		delete(s.utxo, c)
	}
	for i := range b.Outputs {
		s.utxo[b.Outputs[i].Commit] = b.Outputs[i]
		s.outputSeen[b.Outputs[i].Commit] = b.Header.Height
	}
	for _, k := range b.Kernels {
		s.kernelSeen[types.KernelID(&k)] = true
	}
	s.blocks[b.Header.Height] = b
	s.undo[b.Header.Height] = cloneOutputs(spent)
	s.heightOf[types.HeaderID(&b.Header)] = b.Header.Height
	return nil
}

func (s *memStore) UndoBlock() error {
	if len(s.blocks) <= 1 {
		return errors.New("store: refuse to undo genesis")
	}
	return s.ReplaceSuffix(uint64(len(s.blocks)-2), nil)
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
	// Explicit snapshots intentionally traverse full history; reorgs never use Save.
	if err := gob.NewEncoder(f).Encode(s.orderedBlocks()); err != nil {
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
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&blocks); err != nil {
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
