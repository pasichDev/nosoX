package p2p

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/noso-project/noso-go/v2/chain"
	"github.com/noso-project/noso-go/v2/mempool"
	"github.com/noso-project/noso-go/v2/pow"
	"github.com/noso-project/noso-go/v2/types"
)

// helper: trivial-PoW genesis used by these scenarios.
func easyGenesis() *types.Block {
	hdr := types.BlockHeader{
		Version:    types.BlockVersion,
		Height:     0,
		Timestamp:  time.Now().Unix() - 600,
		Difficulty: 1,
	}
	for n := uint64(0); n < 32; n++ {
		hdr.Nonce = n
		if pow.Verify(&hdr) {
			break
		}
	}
	return &types.Block{Header: hdr}
}

func mineEasyBlock(parent types.Hash, height uint64) *types.Block {
	hdr := types.BlockHeader{
		Version:    types.BlockVersion,
		Height:     height,
		Timestamp:  time.Now().Unix() - int64(60-(height%60)),
		PrevHash:   parent,
		Difficulty: 1,
	}
	for n := uint64(0); n < 32; n++ {
		hdr.Nonce = n
		if pow.Verify(&hdr) {
			break
		}
	}
	return &types.Block{Header: hdr}
}

// bringUpNode spins up a libp2p node on an OS-allocated port with the
// supplied genesis block and returns the node plus a cleanup func.
func bringUpNode(t *testing.T, name string, g *types.Block) (*Libp2pNode, *chain.Chain, *mempool.Pool, func()) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	c := chain.NewMemory()
	if err := c.LoadOrInit(dir, g); err != nil {
		t.Fatalf("%s: load chain: %v", name, err)
	}
	mp := mempool.New(0)
	n, err := NewLibp2p([]string{"/ip4/127.0.0.1/tcp/0"}, types.NetworkMagicTestnet, c, mp)
	if err != nil {
		t.Fatalf("%s: NewLibp2p: %v", name, err)
	}
	n.SetLogger(func(format string, args ...any) {
		t.Logf("["+name+"] "+format, args...)
	})
	if err := n.Start(); err != nil {
		t.Fatalf("%s: start: %v", name, err)
	}
	cleanup := func() { _ = n.Shutdown() }
	return n, c, mp, cleanup
}

// TestTwoNodeColdSync verifies that a fresh node, once dialed to a peer
// with a longer chain, requests and applies the missing blocks via the
// /noso/hello/1 → /noso/sync/1 protocol pair.
//
// This is the central proof that a new node joining the network
// catches up automatically. Without this, every new operator would
// need to download the chain via a side channel.
func TestTwoNodeColdSync(t *testing.T) {
	if testing.Short() {
		t.Skip("libp2p scenario takes seconds; -short skips")
	}
	// Both nodes MUST start from the same genesis block. In production
	// genesis is deterministic via genesis.Build(cfg) with a fixed
	// timestamp; in tests we build one and share it.
	g := easyGenesis()
	nodeA, chainA, _, stopA := bringUpNode(t, "A", g)
	defer stopA()

	parent := types.HeaderID(&g.Header)
	for h := uint64(1); h <= 5; h++ {
		b := mineEasyBlock(parent, h)
		if err := chainA.AddBlock(b); err != nil {
			t.Fatalf("nodeA add block %d: %v", h, err)
		}
		parent = types.HeaderID(&b.Header)
	}
	if chainA.Height() != 5 {
		t.Fatalf("nodeA height after seeding = %d, want 5", chainA.Height())
	}

	// Node B: fresh, SAME genesis bytes, dials node A.
	nodeB, chainB, _, stopB := bringUpNode(t, "B", &types.Block{Header: g.Header, Outputs: g.Outputs, Inputs: g.Inputs, Kernels: g.Kernels})
	defer stopB()

	// Build a dial multiaddr for A and connect from B.
	var aAddr string
	for _, addr := range nodeA.Addrs() {
		aAddr = addr
		break
	}
	if aAddr == "" {
		t.Fatal("nodeA has no listen addresses")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := nodeB.ConnectSeed(ctx, aAddr); err != nil {
		t.Fatalf("B dial A: %v", err)
	}

	// Cold-sync is triggered by the HELLO exchange; poll up to 20 s.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if chainB.Height() >= 5 {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}

	if got := chainB.Height(); got != 5 {
		t.Fatalf("nodeB cold-synced to height %d, want 5", got)
	}
	// Tip hashes must match.
	tA, _ := chainA.Tip()
	tB, _ := chainB.Tip()
	if types.HeaderID(&tA) != types.HeaderID(&tB) {
		t.Fatalf("tip hashes diverge after sync")
	}
}

// TestTwoNodeBlockGossip verifies that a block mined on node A reaches
// node B via gossipsub within a few seconds. This is the canonical
// happy-path for an already-synced peer that just stays online.
func TestTwoNodeBlockGossip(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	g := easyGenesis()
	nodeA, chainA, _, stopA := bringUpNode(t, "A", g)
	defer stopA()
	nodeB, chainB, _, stopB := bringUpNode(t, "B", &types.Block{Header: g.Header, Outputs: g.Outputs, Inputs: g.Inputs, Kernels: g.Kernels})
	defer stopB()

	var aAddr string
	for _, addr := range nodeA.Addrs() {
		aAddr = addr
		break
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := nodeB.ConnectSeed(ctx, aAddr); err != nil {
		t.Fatalf("B dial A: %v", err)
	}
	// Give gossipsub a moment to mesh.
	time.Sleep(2 * time.Second)

	// A produces a block; broadcast.
	parent := types.HeaderID(&g.Header)
	b1 := mineEasyBlock(parent, 1)
	if err := chainA.AddBlock(b1); err != nil {
		t.Fatal(err)
	}
	if err := nodeA.BroadcastBlock(b1); err != nil {
		t.Fatal(err)
	}

	// B should pick it up within 10 s.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if chainB.Height() >= 1 {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if chainB.Height() < 1 {
		t.Fatalf("nodeB did not receive gossiped block within 10 s")
	}
}
