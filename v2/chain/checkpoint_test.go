package chain

import (
	"testing"
	"time"

	"github.com/noso-project/noso-go/v2/pow"
	"github.com/noso-project/noso-go/v2/types"
)

// TestCheckpointEnforcement: a block at a pinned height with the wrong
// hash must be rejected; one with the right hash must be accepted.
func TestCheckpointEnforcement(t *testing.T) {
	c := NewMemory()
	genesis := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), genesis); err != nil {
		t.Fatal(err)
	}
	// Mine block 1.
	parent := types.HeaderID(&genesis.Header)
	b1 := mineEasy(parent, 1)
	hash1 := types.HeaderID(&b1.Header)

	// Pin block 1 to its known hash → AddBlock accepts.
	c.SetCheckpoints([]types.Checkpoint{{Height: 1, Hash: hash1}})
	if err := c.AddBlock(b1); err != nil {
		t.Fatalf("legit block rejected: %v", err)
	}

	// Reset chain and pin block 1 to a WRONG hash → AddBlock rejects.
	c2 := NewMemory()
	g2 := easyGenesisBlock(t)
	_ = c2.LoadOrInit(t.TempDir(), g2)
	wrong := types.Hash{}
	wrong[31] = 0xff
	c2.SetCheckpoints([]types.Checkpoint{{Height: 1, Hash: wrong}})
	b1again := mineEasy(types.HeaderID(&g2.Header), 1)
	err := c2.AddBlock(b1again)
	if err == nil || err != ErrCheckpoint {
		t.Fatalf("checkpoint mismatch should fail with ErrCheckpoint, got %v", err)
	}
}

// TestCheckpointRefusesCrossingReorg: reorg whose common ancestor is
// below the highest checkpoint is rejected, even if the fork is heavier.
func TestCheckpointRefusesCrossingReorg(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	_ = c.LoadOrInit(t.TempDir(), g)
	// Build chain to height 3.
	parent := types.HeaderID(&g.Header)
	for h := uint64(1); h <= 3; h++ {
		b := mineEasy(parent, h)
		if err := c.AddBlock(b); err != nil {
			t.Fatal(err)
		}
		parent = types.HeaderID(&b.Header)
	}
	tipH, _ := c.HeaderByHeight(3)
	// Pin block 2.
	c.SetCheckpoints([]types.Checkpoint{{Height: 2, Hash: types.HeaderID(mustHeaderPtr(c.HeaderByHeight(2)))}})
	// Attempt a reorg whose ancestor is block 1 — crosses the checkpoint.
	anc, _ := c.HeaderByHeight(1)
	anchorHash := types.HeaderID(&anc)
	forkA := mineEasy(anchorHash, 2)
	forkB := mineEasy(types.HeaderID(&forkA.Header), 3)
	err := c.ReorgTo([]*types.Block{forkA, forkB})
	if err == nil || err != ErrCheckpoint {
		t.Fatalf("ReorgTo across checkpoint should fail with ErrCheckpoint, got %v", err)
	}
	// Tip should still be the original block 3.
	tipNow, _ := c.Tip()
	if types.HeaderID(&tipNow) != types.HeaderID(&tipH) {
		t.Fatalf("reorg should have been refused; tip changed")
	}
}

// easyGenesisBlock returns a genesis block that satisfies PoW at the
// trivial difficulty=1. Used to bootstrap mem-store tests.
func easyGenesisBlock(t *testing.T) *types.Block {
	t.Helper()
	hdr := types.BlockHeader{
		Version:    types.BlockVersion,
		Height:     0,
		Timestamp:  time.Now().Unix() - 600,
		Difficulty: 1,
	}
	for n := uint64(0); n < 64; n++ {
		hdr.Nonce = n
		if pow.Verify(&hdr) {
			break
		}
	}
	return &types.Block{Header: hdr}
}

func mustHeaderPtr(h types.BlockHeader, ok bool) *types.BlockHeader {
	if !ok {
		panic("header missing")
	}
	return &h
}
