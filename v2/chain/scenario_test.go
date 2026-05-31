package chain

import (
	"testing"
	"time"

	"github.com/noso-project/noso-go/v2/pow"
	"github.com/noso-project/noso-go/v2/types"
)

// mineAt builds and mines a block at the requested difficulty. Caller
// supplies the parent hash and target height. Used by long-run scenario
// tests where the difficulty changes mid-run via LWMA-3.
//
// Timestamps are spaced TargetBlockTimeSeconds apart so LWMA-3 stays
// stable (otherwise rapid-fire blocks make the algorithm ramp
// difficulty exponentially and the nonce search budget runs out).
func mineAt(parent types.Hash, height uint64, difficulty uint64) *types.Block {
	hdr := types.BlockHeader{
		Version:    types.BlockVersion,
		Height:     height,
		Timestamp:  baseTime + int64(height)*types.TargetBlockTimeSeconds,
		PrevHash:   parent,
		Difficulty: difficulty,
	}
	for n := uint64(0); n < 1<<22; n++ {
		hdr.Nonce = n
		if pow.Verify(&hdr) {
			break
		}
	}
	return &types.Block{Header: hdr}
}

// baseTime anchors block timestamps so the difficulty algorithm sees a
// stable block interval. Far enough in the past that nothing leaks
// from real wall-clock variance.
var baseTime = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Unix()

// Large-scale chain scenario tests. These cover behaviors that
// individual unit tests don't: a hundred-block run, deep reorgs,
// checkpoint protection under attempted rewrite, restart under load.

func TestScenarioLongRunMinesHundredBlocks(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	dir := t.TempDir()
	c, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(dir, g); err != nil {
		t.Fatal(err)
	}
	const N = 100
	parent := types.HeaderID(&g.Header)
	for h := uint64(1); h <= N; h++ {
		// LWMA-3 kicks in after block 90; ask the chain for the next
		// expected difficulty rather than hardcoding 1.
		diff := c.NextDifficulty()
		b := mineAt(parent, h, diff)
		if err := c.AddBlock(b); err != nil {
			t.Fatalf("add block %d (diff=%d): %v", h, diff, err)
		}
		parent = types.HeaderID(&b.Header)
	}
	if c.Height() != N {
		t.Fatalf("height = %d, want %d", c.Height(), N)
	}
	// Sanity: each height returns a header and the chain is linked.
	for h := uint64(1); h <= N; h++ {
		prev, _ := c.HeaderByHeight(h - 1)
		cur, ok := c.HeaderByHeight(h)
		if !ok {
			t.Fatalf("missing header at %d", h)
		}
		if cur.PrevHash != types.HeaderID(&prev) {
			t.Fatalf("link broken at %d", h)
		}
	}
}

func TestScenarioBadgerRestartPreservesState(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	dir := t.TempDir()
	c, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(dir, g); err != nil {
		t.Fatal(err)
	}
	parent := types.HeaderID(&g.Header)
	for h := uint64(1); h <= 25; h++ {
		b := mineEasy(parent, h)
		if err := c.AddBlock(b); err != nil {
			t.Fatal(err)
		}
		parent = types.HeaderID(&b.Header)
	}
	wantTip, _ := c.Tip()
	wantHeight := c.Height()
	c.Close()

	// Reopen
	c2, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if c2.Height() != wantHeight {
		t.Fatalf("height after reopen = %d, want %d", c2.Height(), wantHeight)
	}
	gotTip, _ := c2.Tip()
	if types.HeaderID(&gotTip) != types.HeaderID(&wantTip) {
		t.Fatalf("tip hash diverged after reopen")
	}
	// Continue mining; the chain must accept new blocks after restart.
	parent = types.HeaderID(&gotTip)
	for h := uint64(26); h <= 30; h++ {
		b := mineEasy(parent, h)
		if err := c2.AddBlock(b); err != nil {
			t.Fatalf("post-restart add %d: %v", h, err)
		}
		parent = types.HeaderID(&b.Header)
	}
}

func TestScenarioDeepReorg(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	// Build chain to height 20.
	parent := types.HeaderID(&g.Header)
	mainBlocks := make([]*types.Block, 0, 20)
	for h := uint64(1); h <= 20; h++ {
		b := mineEasy(parent, h)
		mainBlocks = append(mainBlocks, b)
		if err := c.AddBlock(b); err != nil {
			t.Fatal(err)
		}
		parent = types.HeaderID(&b.Header)
	}
	// Build a 15-block fork from height 5.
	anchor, _ := c.HeaderByHeight(5)
	anchorHash := types.HeaderID(&anchor)
	fork := make([]*types.Block, 0, 15)
	parent = anchorHash
	for h := uint64(6); h <= 20; h++ {
		// Mutate timestamp to ensure fork hashes differ from main chain.
		hdr := types.BlockHeader{
			Version:    types.BlockVersion,
			Height:     h,
			Timestamp:  time.Now().Unix() + int64(h*7), // distinctive
			PrevHash:   parent,
			Difficulty: 1,
		}
		for n := uint64(0); n < 64; n++ {
			hdr.Nonce = n
			if pow.Verify(&hdr) {
				break
			}
		}
		b := &types.Block{Header: hdr}
		fork = append(fork, b)
		parent = types.HeaderID(&hdr)
	}
	// Reorg to the fork.
	if err := c.ReorgTo(fork); err != nil {
		t.Fatalf("reorg 15-block deep: %v", err)
	}
	if c.Height() != 20 {
		t.Fatalf("post-reorg height = %d, want 20", c.Height())
	}
	tip, _ := c.Tip()
	wantTipHash := types.HeaderID(&fork[len(fork)-1].Header)
	if types.HeaderID(&tip) != wantTipHash {
		t.Fatalf("post-reorg tip != fork tip")
	}
}

func TestScenarioCheckpointSurvivesRewriteAttempt(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	// Build chain to height 10.
	parent := types.HeaderID(&g.Header)
	for h := uint64(1); h <= 10; h++ {
		b := mineEasy(parent, h)
		if err := c.AddBlock(b); err != nil {
			t.Fatal(err)
		}
		parent = types.HeaderID(&b.Header)
	}
	// Pin block 7.
	h7, _ := c.HeaderByHeight(7)
	c.SetCheckpoints([]types.Checkpoint{{Height: 7, Hash: types.HeaderID(&h7)}})
	// Attempt to reorg from block 5 (crosses the checkpoint). Must fail.
	anchor, _ := c.HeaderByHeight(5)
	parent = types.HeaderID(&anchor)
	fork := make([]*types.Block, 0, 10)
	for h := uint64(6); h <= 11; h++ {
		hdr := types.BlockHeader{
			Version:    types.BlockVersion,
			Height:     h,
			Timestamp:  time.Now().Unix() + int64(h*13),
			PrevHash:   parent,
			Difficulty: 1,
		}
		for n := uint64(0); n < 64; n++ {
			hdr.Nonce = n
			if pow.Verify(&hdr) {
				break
			}
		}
		fork = append(fork, &types.Block{Header: hdr})
		parent = types.HeaderID(&hdr)
	}
	err := c.ReorgTo(fork)
	if err != ErrCheckpoint {
		t.Fatalf("expected ErrCheckpoint, got %v", err)
	}
	// Tip must remain unchanged.
	if c.Height() != 10 {
		t.Fatalf("chain disturbed by failed reorg: height = %d", c.Height())
	}
}
