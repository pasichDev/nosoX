package chain

import (
	"path/filepath"
	"testing"

	"github.com/pasichDev/nosoX/v2/pow"
	"github.com/pasichDev/nosoX/v2/types"
)

// helper: produce a low-difficulty header that meets PoW after a few
// tries. Difficulty=1 means any hash works, so a single attempt does it.
func easyHeader(parentHash types.Hash, height uint64) types.BlockHeader {
	return types.BlockHeader{
		Version:    types.BlockVersion,
		Height:     height,
		Timestamp:  baseTime + int64(height)*types.TargetBlockTimeSeconds,
		PrevHash:   parentHash,
		Difficulty: 1,
		Nonce:      1,
	}
}

func mineEasy(parentHash types.Hash, height uint64) *types.Block {
	h := easyHeader(parentHash, height)
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

func TestMemoryStoreAddAndUndo(t *testing.T) {
	c := NewMemory()
	genesis := mineEasy(types.Hash{}, 0)
	if err := c.LoadOrInit(t.TempDir(), genesis); err != nil {
		t.Fatal(err)
	}
	// Add three more blocks.
	parent := types.HeaderID(&genesis.Header)
	for h := uint64(1); h <= 3; h++ {
		b := mineEasy(parent, h)
		if err := c.AddBlock(b); err != nil {
			t.Fatalf("add %d: %v", h, err)
		}
		parent = types.HeaderID(&b.Header)
	}
	if c.Height() != 3 {
		t.Fatalf("height after adds = %d", c.Height())
	}
	// Reorg back to height 1 with a brand-new fork.
	anchor, _ := c.HeaderByHeight(1)
	anchorHash := types.HeaderID(&anchor)
	forkA := mineEasy(anchorHash, 2)
	forkB := mineEasy(types.HeaderID(&forkA.Header), 3)
	forkC := mineEasy(types.HeaderID(&forkB.Header), 4)
	if err := c.ReorgTo([]*types.Block{forkA, forkB, forkC}); err != nil {
		t.Fatalf("ReorgTo: %v", err)
	}
	if c.Height() != 4 {
		t.Fatalf("height after reorg = %d", c.Height())
	}
	tip, _ := c.Tip()
	if types.HeaderID(&tip) != types.HeaderID(&forkC.Header) {
		t.Fatalf("tip != forkB after reorg")
	}
}

func TestBadgerStorePersistence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "badger")
	c, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	genesis := mineEasy(types.Hash{}, 0)
	types.SetBlockRoots(genesis)
	if err := c.LoadOrInit(dir, genesis); err != nil {
		t.Fatal(err)
	}
	for h := uint64(1); h <= 3; h++ {
		parent, _ := c.Tip()
		b := mineEasy(types.HeaderID(&parent), h)
		if err := c.AddBlock(b); err != nil {
			t.Fatalf("add %d: %v", h, err)
		}
	}
	wantTip, _ := c.Tip()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen — state must persist.
	c2, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if c2.Height() != 3 {
		t.Fatalf("reopened height = %d", c2.Height())
	}
	gotTip, _ := c2.Tip()
	if types.HeaderID(&gotTip) != types.HeaderID(&wantTip) {
		t.Fatalf("reopened tip differs")
	}
}

func TestUTXODeltaThroughBadger(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "badger")
	c, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	genesis := mineEasy(types.Hash{}, 0)
	if err := c.LoadOrInit(dir, genesis); err != nil {
		t.Fatal(err)
	}
	// Genesis is empty: nothing is spendable before the first mined block.
	if c.store.HasUTXO(storePoint(t, 1)) {
		t.Fatal("empty genesis produced a UTXO")
	}
	b := mineEasy(types.HeaderID(&genesis.Header), 1)
	if err := c.AddBlock(b); err != nil {
		t.Fatal(err)
	}
	cb := b.Outputs[0]
	got, ok := c.store.UTXOByCommit(cb.Commit)
	if !ok || got.Features != types.OutputFeaturesCoinbase || got.Commit != cb.Commit {
		t.Fatalf("coinbase output missing from UTXO set: ok=%v out=%+v", ok, got)
	}
	if !c.store.HasOutput(cb.Commit) {
		t.Fatal("coinbase output missing from historical index")
	}
}
