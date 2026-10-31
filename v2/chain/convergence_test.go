package chain

import (
	"errors"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pasichDev/noso-go/v2/types"
)

// countingStore counts block reads.
type countingStore struct {
	Store
	reads atomic.Int64
}

func (s *countingStore) BlockAt(h uint64) (*types.Block, error) {
	s.reads.Add(1)
	return s.Store.BlockAt(h)
}

func sumWork(t *testing.T, c *Chain) *big.Int {
	t.Helper()
	tip, _ := c.Tip()
	sum := new(big.Int)
	for h := uint64(0); h <= tip.Height; h++ {
		b, err := c.store.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		sum.Add(sum, blockWork(b.Header.Difficulty))
	}
	return sum
}

// A reorganisation must update the cumulative-work cache from the work it
// already computed, not force a walk over the whole chain under the state lock.
func TestReorgUpdatesWorkCacheWithoutWalkingTheChain(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	blocks := appendBlocks(t, c, 1, 150)
	cs := &countingStore{Store: c.store}
	c.store = cs
	c.TotalWork() // warm
	anchor := blocks[146]
	a := mineEasy(types.HeaderID(&anchor.Header), 148)
	b := mineEasy(types.HeaderID(&a.Header), 149)
	d := mineEasy(types.HeaderID(&b.Header), 150)
	e := mineEasy(types.HeaderID(&d.Header), 151)
	if err := c.ReorgTo([]*types.Block{a, b, d, e}); err != nil {
		t.Fatal(err)
	}
	walks, reads := fullWorkWalks.Load(), cs.reads.Load()
	got := c.TotalWork()
	if fullWorkWalks.Load() != walks {
		t.Fatal("TotalWork after a reorg walked the whole chain (fullWorkLocked)")
	}
	if n := cs.reads.Load() - reads; n > 2 {
		t.Fatalf("TotalWork after a reorg read %d blocks", n)
	}
	if got.Cmp(sumWork(t, c)) != 0 {
		t.Fatalf("cached work %v != recomputed %v", got, sumWork(t, c))
	}
}

func TestCheckpointGuardComparesHashes(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	blocks := appendBlocks(t, c, 1, 6)
	anchor := blocks[1] // height 2
	fork := func() []*types.Block {
		a := mineEasy(types.HeaderID(&anchor.Header), 3)
		a.Header.Timestamp += 5 // differ from the canonical height-3 block (difficulty 1: any nonce)
		out := []*types.Block{a}
		for h := uint64(4); h <= 7; h++ {
			out = append(out, mineEasy(types.HeaderID(&out[len(out)-1].Header), h))
		}
		return out
	}
	// Checkpoint the canonical block at height 4: a fork below it is refused.
	canon4 := types.HeaderID(&blocks[3].Header)
	c.SetCheckpoints([]types.Checkpoint{{Height: 4, Hash: canon4}})
	if err := c.ReorgTo(fork()); err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("fork across a matching checkpoint: %v", err)
	}
	// A checkpoint the canonical block does NOT match must not pin it in place.
	c.SetCheckpoints([]types.Checkpoint{{Height: 4, Hash: types.Hash{9}}})
	f := fork()
	// The fork's own height-4 block does not match the checkpoint either, so the
	// fork is refused for that reason, never because the canonical block is pinned.
	err := c.ReorgTo(f)
	if err == nil {
		t.Fatal("fork violating the checkpoint accepted")
	}
	if strings.Contains(err.Error(), "checkpoint") && !strings.Contains(err.Error(), "incoming") {
		t.Fatalf("canonical block pinned although it conflicts with the checkpoint: %v", err)
	}
}

func tamperBadger(t *testing.T, dir string, entries map[string][]byte) {
	t.Helper()
	s, err := OpenBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleSet(t, s, entries)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func badgerWithBlocks(t *testing.T, n uint64) (string, *types.Block, []*types.Block) {
	t.Helper()
	dir := t.TempDir()
	c, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(dir, g); err != nil {
		t.Fatal(err)
	}
	blocks := appendBlocks(t, c, 1, n)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, g, blocks
}

func reopen(t *testing.T, dir string, g *types.Block, cps []types.Checkpoint) (*Chain, error) {
	t.Helper()
	c, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	c.SetCheckpoints(cps)
	if err := c.LoadOrInit(dir, g); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// A good marker must not let a stored block that conflicts with a (newly
// shipped) checkpoint through: only the full replay checked checkpoints.
func TestMarkerPathEnforcesCheckpoints(t *testing.T) {
	dir, g, blocks := badgerWithBlocks(t, 6)
	c, err := reopen(t, dir, g, []types.Checkpoint{{Height: 3, Hash: types.HeaderID(&blocks[2].Header)}})
	if err != nil {
		t.Fatalf("matching checkpoint rejected: %v", err)
	}
	c.Close()
	if c, err = reopen(t, dir, g, []types.Checkpoint{{Height: 3, Hash: types.Hash{7}}}); err == nil {
		c.Close()
		t.Fatal("stored block conflicting with a checkpoint was accepted through the marker")
	}
}

// The marker is bound to the checkpoint set and to the consensus rules version.
func TestMarkerBoundToCheckpointSetAndRules(t *testing.T) {
	dir, g, blocks := badgerWithBlocks(t, 4)
	m, ok := readMarker(dir)
	if !ok || m.Rules != consensusRulesVersion {
		t.Fatalf("marker rules: %+v ok=%v", m, ok)
	}
	s, err := OpenBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := &Chain{store: s}
	if okm, err := c.verifyFromMarker(s, dir, g); err != nil || !okm {
		t.Fatalf("baseline marker unusable: %v %v", okm, err)
	}
	c.checkpoints = []types.Checkpoint{{Height: 2, Hash: types.HeaderID(&blocks[1].Header)}}
	if okm, _ := c.verifyFromMarker(s, dir, g); okm {
		t.Fatal("marker accepted although the checkpoint set changed")
	}
	c.checkpoints = nil
	m.Rules--
	m.Check = m.checksum()
	writeMarkerFile(t, dir, m)
	if okm, _ := c.verifyFromMarker(s, dir, g); okm {
		t.Fatal("marker accepted although written under other consensus rules")
	}
}

// Damaged derived state (a lost UTXO key, a phantom kernel key) is caught on
// the marker path, as the full replay's state comparison used to.
func TestMarkerPathDetectsDamagedDerivedState(t *testing.T) {
	for name, mut := range map[string]func(blocks []*types.Block) map[string][]byte{
		"lost utxo": func(b []*types.Block) map[string][]byte {
			return map[string][]byte{string(append([]byte{kUTXO}, b[1].Outputs[0].Commit[:]...)): nil}
		},
		"phantom kernel": func([]*types.Block) map[string][]byte {
			return map[string][]byte{string(append([]byte{kKernelSeen}, make([]byte, 32)...)): {1}}
		},
		"lost output history": func(b []*types.Block) map[string][]byte {
			return map[string][]byte{string(append([]byte{kOutputSeen}, b[0].Outputs[0].Commit[:]...)): nil}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, g, blocks := badgerWithBlocks(t, 5)
			tamperBadger(t, dir, mut(blocks))
			if c, err := reopen(t, dir, g, nil); err == nil {
				c.Close()
				t.Fatal("damaged derived state accepted")
			}
		})
	}
}

// A marker write failure must not discard a successful verification.
func TestMarkerWriteFailureDoesNotFailLoad(t *testing.T) {
	dir, g, _ := badgerWithBlocks(t, 3)
	c, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// A directory squatting on the marker's temp pattern is not possible; make the
	// marker directory unwritable instead.
	makeUnwritable(t, dir)
	if err := c.LoadOrInit(dir, g); err != nil {
		t.Fatalf("verified chain refused because the marker could not be written: %v", err)
	}
}

type faultyStore struct {
	Store
	faults atomic.Uint64
}

func (s *faultyStore) Faults() uint64 { return s.faults.Load() }
func (s *faultyStore) UTXOByCommit(c types.Commitment) (*types.Output, bool) {
	if _, ok := s.Store.UTXOByCommit(c); ok {
		s.faults.Add(1) // a read error that the accessor reports as "absent"
	}
	return nil, false
}

// Only a rejection that follows from the block (or the peer's own batch) and
// its named parent may penalize the sender.
func TestIsPeerFaultIsAnAllowlist(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	blocks := appendBlocks(t, c, 1, 62)
	tip := blocks[len(blocks)-1]

	stale := mineEasy(types.HeaderID(&blocks[10].Header), 12)
	if err := c.AddBlock(stale); err == nil || IsPeerFault(err) {
		t.Fatalf("stale (wrong parent) block: err=%v peerFault=%v", err, IsPeerFault(err))
	}
	future := mineEasy(types.HeaderID(&tip.Header), 63)
	future.Header.Timestamp = 1 << 40
	if err := c.AddBlock(future); err == nil || IsPeerFault(err) {
		t.Fatalf("future timestamp must not be a peer fault: %v", err)
	}
	badDiff := mineEasy(types.HeaderID(&tip.Header), 63)
	badDiff.Header.Difficulty = 7
	if err := c.AddBlock(badDiff); !IsPeerFault(err) {
		t.Fatalf("wrong difficulty must be a peer fault: %v", err)
	}
	greedy := &types.Block{Header: easyHeader(types.HeaderID(&tip.Header), 63)}
	sealFixtureClaim(greedy, 1)
	if err := c.AddBlock(greedy); !IsPeerFault(err) {
		t.Fatalf("over-claiming coinbase must be a peer fault: %v", err)
	}
	// A fork that merely lost (equal/lower work) is local state, not misbehaviour.
	a := mineEasy(types.HeaderID(&blocks[58].Header), 60)
	a.Header.Timestamp++
	if err := c.ReorgTo([]*types.Block{a}); err == nil || IsPeerFault(err) {
		t.Fatalf("low-work fork must not be a peer fault: %v", err)
	}
	// A suffix that does not link to itself is provable from the batch alone.
	x := mineEasy(types.HeaderID(&blocks[57].Header), 59)
	x.Header.Timestamp++
	y := mineEasy(types.Hash{1}, 60)
	z := mineEasy(types.HeaderID(&y.Header), 61)
	w := mineEasy(types.HeaderID(&z.Header), 62)
	v := mineEasy(types.HeaderID(&w.Header), 63)
	if err := c.ReorgTo([]*types.Block{x, y, z, w, v}); !IsPeerFault(err) {
		t.Fatalf("non-linking suffix must be a peer fault: %v", err)
	}
	// nil must be an error, not a panic with the lock held.
	if err := c.AddBlock(nil); err == nil {
		t.Fatalf("nil block: %v", err)
	}
	if err := c.ValidateBlock(nil); err == nil {
		t.Fatal("nil block validated")
	}
	if _, ok := c.Tip(); !ok {
		t.Fatal("lock left held")
	}
}

// A validation that coincides with store read errors is a disk problem.
func TestStoreFaultIsNeverAPeerFault(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	blocks := appendBlocks(t, c, 1, 61)
	spend, _ := feeBlock(t, blocks[len(blocks)-1], blocks[0], 100, 0, false)
	c.store = &faultyStore{Store: c.store}
	err := c.AddBlock(spend)
	if err == nil || IsPeerFault(err) {
		t.Fatalf("read-fault double spend: err=%v peerFault=%v", err, IsPeerFault(err))
	}
	if !errors.Is(err, ErrStorage) {
		t.Fatalf("not marked as a storage fault: %v", err)
	}
}

// Proof of work is checked, head first, before any history is read or staged.
func TestForkPoWIsCheckedBeforeStaging(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	blocks := appendBlocks(t, c, 1, 20)
	cs := &countingStore{Store: c.store}
	c.store = cs
	a := mineEasy(types.HeaderID(&blocks[16].Header), 18)
	a.Header.Timestamp++
	b := mineEasy(types.HeaderID(&a.Header), 19)
	d := mineEasy(types.HeaderID(&b.Header), 20)
	d.Header.Difficulty = 1 << 50 // declares a lot of work, proves none
	// The first block is also invalid in its body: if state were staged before
	// the PoW check, that would be the error reported.
	a.Kernels[0].LockHeight++
	types.SetBlockRoots(a)
	b.Header.PrevHash = types.HeaderID(&a.Header)
	d.Header.PrevHash = types.HeaderID(&b.Header)
	before := cs.reads.Load()
	err := c.ReorgTo([]*types.Block{a, b, d})
	if !IsPeerFault(err) || !errors.Is(err, ErrBadPoW) {
		t.Fatalf("forged head: %v", err)
	}
	// Only the cheap declared-work comparison reads history (the blocks a fork
	// would replace); no fork state is staged.
	if n := cs.reads.Load() - before; n > 4 {
		t.Fatalf("%d block reads before the head's PoW was checked", n)
	}
}
