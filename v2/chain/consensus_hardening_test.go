package chain

import (
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pasichDev/nosoX/v2/pow"
	"github.com/pasichDev/nosoX/v2/types"
)

// mineFork builds a block on parent that differs from mineEasy's (timestamp
// shifted by delta seconds); difficulty 1 means any nonce satisfies the PoW.
func mineFork(parent types.Hash, height uint64, delta int64) *types.Block {
	h := easyHeader(parent, height)
	h.Timestamp += delta
	b := &types.Block{Header: h}
	sealFixture(b)
	for n := uint64(0); n < 1024; n++ {
		b.Header.Nonce = n
		if pow.Verify(&b.Header) {
			break
		}
	}
	return b
}

func resetVerificationCaches() {
	powChecked = newHashSet(256)
	statelessPassed = newHashSet(256)
}

func extendFork(parent types.Hash, from uint64, n int, delta int64) []*types.Block {
	var out []*types.Block
	for i := 0; i < n; i++ {
		b := mineFork(parent, from+uint64(i), delta)
		out = append(out, b)
		parent = types.HeaderID(&b.Header)
	}
	return out
}

// F3: a checkpoint above the tip must not block reorgs; a checkpointed block
// the node holds must still be protected; a window starting below a checkpoint
// is trimmed rather than refused.
func TestCheckpointAboveTipDoesNotFreezeReorg(t *testing.T) {
	setup := func(t *testing.T) (*Chain, *types.Block, []*types.Block) {
		c := NewMemory()
		g := easyGenesisBlock(t)
		if err := c.LoadOrInit(t.TempDir(), g); err != nil {
			t.Fatal(err)
		}
		return c, g, appendBlocks(t, c, 1, 3)
	}
	t.Run("checkpoint above tip", func(t *testing.T) {
		c, _, canon := setup(t)
		c.SetCheckpoints([]types.Checkpoint{{Height: 10, Hash: types.Hash{1}}})
		fork := extendFork(types.HeaderID(&canon[0].Header), 2, 3, 1)
		if err := c.ReorgTo(fork); err != nil {
			t.Fatalf("checkpoint the node has not reached blocked a heavier fork: %v", err)
		}
		if c.Height() != 4 {
			t.Fatalf("height %d", c.Height())
		}
	})
	t.Run("checkpointed block is protected", func(t *testing.T) {
		c, _, canon := setup(t)
		c.SetCheckpoints([]types.Checkpoint{{Height: 2, Hash: types.HeaderID(&canon[1].Header)}})
		fork := extendFork(types.HeaderID(&canon[0].Header), 2, 3, 1)
		if err := c.ReorgTo(fork); !errors.Is(err, ErrCheckpoint) {
			t.Fatalf("fork disconnecting a checkpointed block: %v", err)
		}
	})
	t.Run("window below checkpoint is trimmed", func(t *testing.T) {
		c, _, canon := setup(t)
		c.SetCheckpoints([]types.Checkpoint{{Height: 2, Hash: types.HeaderID(&canon[1].Header)}})
		fork := extendFork(types.HeaderID(&canon[1].Header), 3, 2, 1)
		window := append([]*types.Block{canon[0], canon[1]}, fork...)
		if err := c.ReorgTo(window); err != nil {
			t.Fatalf("fork above the checkpoint refused because the window began below it: %v", err)
		}
		if c.Height() != 4 {
			t.Fatalf("height %d", c.Height())
		}
	})
}

// F5: stored blocks must stay valid after the clock steps back.
func TestReplayDoesNotApplyWallClockRule(t *testing.T) {
	for _, backend := range []string{"memory", "badger"} {
		t.Run(backend, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "chain")
			open := func() *Chain {
				if backend == "badger" {
					c, err := NewBadger(dir)
					if err != nil {
						t.Fatal(err)
					}
					return c
				}
				return NewMemory()
			}
			g := easyGenesisBlock(t)
			c := open()
			if err := c.LoadOrInit(dir, g); err != nil {
				t.Fatal(err)
			}
			now := baseTime + 1000
			c.now = func() time.Time { return time.Unix(now, 0) }
			b := mineEasy(types.HeaderID(&g.Header), 1)
			b.Header.Timestamp = now + types.MaxFutureDriftSeconds
			if err := c.AddBlock(b); err != nil {
				t.Fatal(err)
			}
			if err := c.Save(); err != nil {
				t.Fatal(err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			c2 := open()
			defer c2.Close()
			c2.SetFullVerify(true) // replay must not depend on the marker
			c2.now = func() time.Time { return time.Unix(now-1, 0) }
			if err := c2.LoadOrInit(dir, g); err != nil {
				t.Fatalf("clock step stopped a node holding a valid block: %v", err)
			}
		})
	}
}

// N4/F4: proof-of-work runs with no chain lock held, cheap checks come first,
// and an accepted block is hashed once.
func TestBlockPoWRunsOutsideChainLock(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	resetVerificationCaches()
	// Occupy every Argon2 slot, as a flood of gossip blocks would.
	for i := 0; i < cap(powSlots); i++ {
		powSlots <- struct{}{}
	}
	released := false
	release := func() {
		if !released {
			released = true
			for i := 0; i < cap(powSlots); i++ {
				<-powSlots
			}
		}
	}
	defer release()
	b := mineEasy(types.HeaderID(&g.Header), 1)
	done := make(chan error, 1)
	go func() { done <- c.ValidateBlock(b) }()
	time.Sleep(100 * time.Millisecond) // validator now waits for a slot
	probe := make(chan struct{})
	go func() { c.Tip(); c.Height(); close(probe) }()
	select {
	case <-probe:
	case <-time.After(2 * time.Second):
		t.Fatal("Tip/Height blocked while a block waits for proof-of-work verification")
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAcceptedBlockHashedOnceAndCheapChecksFirst(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	resetVerificationCaches()
	b := mineEasy(types.HeaderID(&g.Header), 1)
	before := powEvaluations.Load()
	if err := c.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	if err := c.AddBlock(b); err != nil {
		t.Fatal(err)
	}
	if n := powEvaluations.Load() - before; n != 1 {
		t.Fatalf("accepted block hashed %d times, want 1", n)
	}
	// Wrong parent, wrong difficulty and wrong timestamp never reach Argon2.
	tip, _ := c.Tip()
	bad := mineEasy(types.HeaderID(&tip), 2)
	cases := map[string]func(*types.Block){
		"parent":     func(x *types.Block) { x.Header.PrevHash[0] ^= 1 },
		"difficulty": func(x *types.Block) { x.Header.Difficulty = 7 },
		"timestamp":  func(x *types.Block) { x.Header.Timestamp = tip.Timestamp },
	}
	for name, mutate := range cases {
		x := cloneBlock(bad)
		mutate(x)
		before = powEvaluations.Load()
		if err := c.ValidateBlock(x); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if n := powEvaluations.Load() - before; n != 0 {
			t.Fatalf("%s: %d Argon2 runs spent on a block failing a cheap check", name, n)
		}
	}
}

// N14/F9: low-work forks cost no hashing, and a failed fork is not re-verified.
func TestReorgChecksWorkBeforeValidationAndRemembersFailures(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	appendBlocks(t, c, 1, 3)
	resetVerificationCaches()
	before := powEvaluations.Load()
	short := extendFork(types.HeaderID(&g.Header), 1, 2, 5)
	if err := c.ReorgTo(short); !errors.Is(err, ErrLowWork) {
		t.Fatalf("lighter fork: %v", err)
	}
	if n := powEvaluations.Load() - before; n != 0 {
		t.Fatalf("lighter fork cost %d Argon2 runs", n)
	}

	// A heavier fork whose head cannot pay: one hash the first time, none after.
	hard := NewMemory()
	hg := easyGenesisBlock(t)
	hg.Header.Difficulty = 1 << 40
	types.SetBlockRoots(hg)
	if err := hard.LoadOrInit(t.TempDir(), hg); err != nil {
		t.Fatal(err)
	}
	f := mineFork(types.HeaderID(&hg.Header), 1, 0)
	f.Header.Difficulty = 1 << 40
	f.Header.Nonce = 3 // overwhelmingly unlikely to meet 2^-40
	resetVerificationCaches()
	before = powEvaluations.Load()
	if err := hard.ReorgTo([]*types.Block{f}); !errors.Is(err, ErrBadPoW) {
		t.Fatalf("unpaid head: %v", err)
	}
	if n := powEvaluations.Load() - before; n != 1 {
		t.Fatalf("unpaid head cost %d hashes, want 1", n)
	}
	before = powEvaluations.Load()
	if err := hard.ReorgTo([]*types.Block{f}); err == nil {
		t.Fatal("resent failed fork accepted")
	}
	if n := powEvaluations.Load() - before; n != 0 {
		t.Fatalf("resent failed fork cost %d hashes, want 0 (rejected-fork cache)", n)
	}
}

// N12: an unfunded transaction fails the balance check before range proofs.
func TestUnfundedTransactionRejectedBeforeRangeProofs(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	source := appendBlocks(t, c, 1, 1)[0]
	appendBlocks(t, c, 2, 61)
	spend, _ := fixtureSpend(t, source, 62)
	tx := &types.Transaction{Inputs: spend.Inputs, Outputs: spend.Outputs[:1], Kernels: spend.Kernels[:1]}
	if err := c.ValidateTransaction(tx); err != nil {
		t.Fatalf("control tx: %v", err)
	}
	bad := cloneTxForTest(tx)
	bad.Outputs[0].Commit = storePoint(t, 9) // no longer balances
	bad.Outputs[0].RangeProof[100] ^= 1      // and its proof is broken
	if err := c.ValidateTransaction(bad); !errors.Is(err, ErrBalance) {
		t.Fatalf("want ErrBalance before proof verification, got %v", err)
	}
}

func cloneTxForTest(tx *types.Transaction) *types.Transaction {
	b := cloneBlock(&types.Block{Inputs: tx.Inputs, Outputs: tx.Outputs, Kernels: tx.Kernels})
	return &types.Transaction{Inputs: b.Inputs, Outputs: b.Outputs, Kernels: b.Kernels}
}

type blockAtCounter struct {
	Store
	n int
}

func (s *blockAtCounter) BlockAt(h uint64) (*types.Block, error) { s.n++; return s.Store.BlockAt(h) }

// F10: coinbase maturity is answered from the output index, not block bodies.
func TestCoinbaseMaturityDoesNotDecodeBlocks(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		g := easyGenesisBlock(t)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		source := appendBlocks(t, c, 1, 1)[0]
		spend, _ := fixtureSpend(t, source, 62)
		tx := &types.Transaction{Inputs: spend.Inputs, Outputs: spend.Outputs[:1], Kernels: spend.Kernels[:1]}
		if err := c.ValidateTransaction(tx); err == nil {
			t.Fatal("immature coinbase accepted")
		}
		appendBlocks(t, c, 2, 60)
		counter := &blockAtCounter{Store: c.store}
		c.store = counter
		defer func() { c.store = counter.Store }()
		if err := c.ValidateTransaction(tx); err != nil {
			t.Fatalf("mature spend: %v", err)
		}
		if counter.n != 0 {
			t.Fatalf("maturity decoded %d blocks", counter.n)
		}
	})
}

// UTXOByCommit reports the creation height, also across a reorg.
func TestUTXOByCommitReportsCreationHeight(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		g := easyGenesisBlock(t)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		blocks := appendBlocks(t, c, 1, 3)
		for i, b := range blocks {
			out, h, ok := c.UTXOByCommit(b.Outputs[0].Commit)
			if !ok || h != uint64(i+1) || out.Commit != b.Outputs[0].Commit {
				t.Fatalf("block %d: ok=%v height=%d", i+1, ok, h)
			}
		}
		if _, _, ok := c.UTXOByCommit(storePoint(t, 77)); ok {
			t.Fatal("unknown commitment reported unspent")
		}
		fork := extendFork(types.HeaderID(&blocks[0].Header), 2, 3, 1)
		if err := c.ReorgTo(fork); err != nil {
			t.Fatal(err)
		}
		if _, _, ok := c.UTXOByCommit(blocks[2].Outputs[0].Commit); ok {
			t.Fatal("output of a disconnected block still reported")
		}
		if _, h, ok := c.UTXOByCommit(fork[1].Outputs[0].Commit); !ok || h != 3 {
			t.Fatalf("fork output: ok=%v height=%d", ok, h)
		}
	})
}

func TestTotalWorkAndLocator(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	unit := BlockWork(1)
	if c.TotalWork().Cmp(BlockWork(g.Header.Difficulty)) != 0 {
		t.Fatal("genesis work")
	}
	blocks := appendBlocks(t, c, 1, 30)
	want := new(bigInt).Mul(unit, bigFrom(31))
	if c.TotalWork().Cmp(want) != 0 {
		t.Fatalf("work %v want %v", c.TotalWork(), want)
	}
	// Reorg to a heavier fork: the cached sum must follow.
	fork := extendFork(types.HeaderID(&blocks[24].Header), 26, 7, 1)
	if err := c.ReorgTo(fork); err != nil {
		t.Fatal(err)
	}
	want = new(bigInt).Mul(unit, bigFrom(26+7))
	if c.TotalWork().Cmp(want) != 0 {
		t.Fatalf("work after reorg %v want %v", c.TotalWork(), want)
	}
	loc := c.BlockLocator()
	if len(loc) < 10 || len(loc) > 20 {
		t.Fatalf("locator length %d", len(loc))
	}
	tip, _ := c.Tip()
	if loc[0] != types.HeaderID(&tip) || loc[len(loc)-1] != types.HeaderID(&g.Header) {
		t.Fatal("locator must run from tip to genesis")
	}
	// A peer on the old branch finds the fork point.
	old := []types.Hash{types.HeaderID(&blocks[29].Header), types.HeaderID(&blocks[24].Header), types.HeaderID(&g.Header)}
	if h, ok := c.CommonAncestor(old); !ok || h != 25 {
		t.Fatalf("common ancestor %d %v", h, ok)
	}
}

func TestSubscribeDeliversConnectedAndDisconnected(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	var got []Change
	c.Subscribe(func(ch Change) {
		c.Height() // listeners may call back into the chain
		got = append(got, ch)
	})
	blocks := appendBlocks(t, c, 1, 3)
	if len(got) != 3 || len(got[2].Connected) != 1 || got[2].Connected[0].Header.Height != 3 {
		t.Fatalf("connect events: %+v", got)
	}
	fork := extendFork(types.HeaderID(&blocks[0].Header), 2, 3, 1)
	if err := c.ReorgTo(fork); err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if len(last.Disconnected) != 2 || last.Disconnected[0].Header.Height != 3 || len(last.Connected) != 3 {
		t.Fatalf("reorg event: disc=%d conn=%d", len(last.Disconnected), len(last.Connected))
	}
}

// F6: a verified marker avoids the full replay; anything unexpected falls back
// to it; stale replay scratch directories are removed.
func TestVerifiedMarkerSkipsReplay(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "chain")
	g := easyGenesisBlock(t)
	build := func() *Chain {
		c, err := NewBadger(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.LoadOrInit(root, g); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := build()
	appendBlocks(t, c, 1, 4)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := readMarker(root); !ok {
		t.Fatal("clean shutdown left no marker")
	}
	reopen := func(full bool) uint64 {
		resetVerificationCaches()
		before := powEvaluations.Load()
		c, err := NewBadger(dir)
		if err != nil {
			t.Fatal(err)
		}
		c.SetFullVerify(full)
		if err := c.LoadOrInit(root, g); err != nil {
			t.Fatal(err)
		}
		if c.Height() != 4 {
			t.Fatalf("height %d", c.Height())
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		return powEvaluations.Load() - before
	}
	if n := reopen(false); n != 0 {
		t.Fatalf("marker present but %d blocks re-hashed", n)
	}
	if n := reopen(true); n != 4 {
		t.Fatalf("-verify-full re-hashed %d blocks, want 4", n)
	}

	// Corrupt marker: full replay, not trust.
	raw, _ := os.ReadFile(filepath.Join(root, markerFile))
	raw[len(raw)/2] ^= 1
	if err := os.WriteFile(filepath.Join(root, markerFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if n := reopen(false); n != 4 {
		t.Fatalf("corrupt marker trusted: %d hashes", n)
	}
	// reopen rewrote a good marker. Stale scratch dirs are removed.
	scratch := filepath.Join(root, replayPrefix+"abandoned")
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scratch, "000001.sst"), make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	reopen(false)
	if _, err := os.Stat(scratch); !os.IsNotExist(err) {
		t.Fatalf("stale replay scratch not removed: %v", err)
	}
}

// Blocks accepted after the marker was written (crash before the next
// refresh) are fully re-validated on start.
func TestVerifiedMarkerReplaysTail(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "chain")
	g := easyGenesisBlock(t)
	c, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.LoadOrInit(root, g); err != nil { // marker at genesis
		t.Fatal(err)
	}
	appendBlocks(t, c, 1, 3)
	if err := c.store.Close(); err != nil { // "crash": no marker refresh
		t.Fatal(err)
	}
	resetVerificationCaches()
	before := powEvaluations.Load()
	c2, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := c2.LoadOrInit(root, g); err != nil {
		t.Fatal(err)
	}
	if n := powEvaluations.Load() - before; n != 3 {
		t.Fatalf("tail replay hashed %d blocks, want 3", n)
	}
	if c2.Height() != 3 {
		t.Fatalf("height %d", c2.Height())
	}
}

type bigInt = big.Int

func bigFrom(n int64) *big.Int { return big.NewInt(n) }

// F8: a kernel signature made for another network does not validate here.
func TestKernelSignatureIsBoundToNetwork(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t) // network magic 0 in this fixture
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	source := appendBlocks(t, c, 1, 1)[0]
	appendBlocks(t, c, 2, 61)
	for _, tc := range []struct {
		name  string
		magic uint32
		ok    bool
	}{{"this network", g.Header.NetworkMagic, true}, {"other network", g.Header.NetworkMagic + 1, false}} {
		spend, _ := fixtureSpendFor(t, source, 62, tc.magic)
		tx := &types.Transaction{Inputs: spend.Inputs, Outputs: spend.Outputs[:1], Kernels: spend.Kernels[:1]}
		err := c.ValidateTransaction(tx)
		if tc.ok && err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !tc.ok && (err == nil || !strings.Contains(err.Error(), "kernel authorization")) {
			t.Fatalf("%s: signature accepted or wrong error: %v", tc.name, err)
		}
	}
}

// A load that fails verification must not leave a marker behind, even though
// the caller closes the chain (deferred Close is the usual shape).
func TestFailedLoadNeverWritesMarker(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "chain")
	g := easyGenesisBlock(t)
	c, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.LoadOrInit(root, g); err != nil {
		t.Fatal(err)
	}
	blocks := appendBlocks(t, c, 1, 3)
	key := append([]byte{kUTXO}, blocks[0].Outputs[0].Commit[:]...)
	if err := c.store.(*BadgerStore).mutate(func(txn *stageTxn) error { return txn.Set(key, []byte("corrupt")) }); err != nil {
		t.Fatal(err)
	}
	if err := c.store.Close(); err != nil { // no marker: "crash"
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(root, markerFile))
	for i := 0; i < 2; i++ {
		c2, err := NewBadger(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := c2.LoadOrInit(root, g); err == nil {
			t.Fatalf("attempt %d: corrupt UTXO state accepted", i)
		}
		_ = c2.Close()
		if _, err := os.Stat(filepath.Join(root, markerFile)); err == nil {
			t.Fatalf("attempt %d: failed load left a verified marker", i)
		}
	}
}
