package p2p

import (
	"context"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pasichDev/nosoX/v2/chain"
	v2crypto "github.com/pasichDev/nosoX/v2/crypto"
	"github.com/pasichDev/nosoX/v2/mempool"
	"github.com/pasichDev/nosoX/v2/pow"
	"github.com/pasichDev/nosoX/v2/types"
	"github.com/pasichDev/nosoX/v2/wallet"
)

// helper: trivial-PoW genesis used by these scenarios.
func easyGenesis() *types.Block {
	hdr := types.BlockHeader{
		Version:      types.BlockVersion,
		NetworkMagic: types.NetworkMagicTestnet,
		Height:       0,
		Timestamp:    time.Now().Unix() - 600,
		Difficulty:   1,
	}
	for n := uint64(0); n < 32; n++ {
		hdr.Nonce = n
		if pow.Verify(&hdr) {
			break
		}
	}
	b := &types.Block{Header: hdr}
	types.SetBlockRoots(b)
	return b
}

func mineEasyBlock(parent types.Hash, height uint64) *types.Block {
	hdr := types.BlockHeader{
		Version:      types.BlockVersion,
		NetworkMagic: types.NetworkMagicTestnet,
		Height:       height,
		Timestamp:    time.Now().Unix() - 300 + int64(height),
		PrevHash:     parent,
		Difficulty:   1,
	}
	var blind [32]byte
	blind[31] = byte(height + 1)
	blind[30] = byte(parent[0])
	if height > 200 { // long test chains: keep coinbase commitments unique across forks
		blind[29] = byte((height + 1) >> 8)
		blind[28], blind[27], blind[26] = parent[1], parent[2], parent[3]
	}
	commit, err := v2crypto.PedersenCommit(types.BlockReward(height), blind[:])
	if err != nil {
		panic(err)
	}
	sig, err := wallet.SignCoinbase(hdr.NetworkMagic, wallet.CoinbaseRecord{Height: height, Amount: types.BlockReward(height), Commit: commit, Blinding: blind})
	if err != nil {
		panic(err)
	}
	b := &types.Block{Header: hdr, Outputs: []types.Output{{Features: types.OutputFeaturesCoinbase, Commit: commit}}, Kernels: []types.Kernel{{Features: types.KernelFeaturesCoinbase, LockHeight: height + types.CoinbaseLock, Excess: commit, ExcessSig: sig}}}
	types.SetBlockRoots(b)
	for n := uint64(0); n < 32; n++ {
		b.Header.Nonce = n
		if pow.Verify(&b.Header) {
			break
		}
	}
	return b
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
	mp := mempool.NewValidated(0, c.ValidateTransaction)
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
// /NosoX/hello/v5 → /NosoX/sync/v5 protocol pair.
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

// Local-only three-peer exercise: transport propagation, catch-up after a
// restart, and atomic selection of a competing validated suffix.
func TestThreeNodePropagationRestartAndFork(t *testing.T) {
	if testing.Short() {
		t.Skip("local libp2p integration")
	}
	g := easyGenesis()
	a, ca, _, stopA := bringUpNode(t, "A", g)
	defer stopA()
	b, cb, _, stopB := bringUpNode(t, "B", g)
	defer stopB()
	cdir := filepath.Join(t.TempDir(), "C")
	cc := chain.NewMemory()
	if err := cc.LoadOrInit(cdir, g); err != nil {
		t.Fatal(err)
	}
	c, err := NewLibp2p([]string{"/ip4/127.0.0.1/tcp/0"}, types.NetworkMagicTestnet, cc, mempool.New(4))
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	stopC := func() { _ = c.Shutdown() }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := b.ConnectSeed(ctx, a.Addrs()[0]); err != nil {
		t.Fatal(err)
	}
	if err := c.ConnectSeed(ctx, b.Addrs()[0]); err != nil {
		t.Fatal(err)
	}
	// Wait until the gossip mesh can carry messages across both edges.
	time.Sleep(2 * time.Second)
	b1 := mineEasyBlock(types.HeaderID(&g.Header), 1)
	if err := ca.AddBlock(b1); err != nil {
		t.Fatal(err)
	}
	if err := a.BroadcastBlock(b1); err != nil {
		t.Fatal(err)
	}
	waitHeight := func(ch *chain.Chain, h uint64) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if ch.Height() == h {
				return
			}
			time.Sleep(30 * time.Millisecond)
		}
		t.Fatalf("height %d, want %d", ch.Height(), h)
	}
	waitHeight(cb, 1)
	waitHeight(cc, 1)
	stopC()
	// Persist C, reopen a fresh chain object, then reconnect a fresh host.
	if err := cc.Save(); err != nil {
		t.Fatal(err)
	}
	b2 := mineEasyBlock(types.HeaderID(&b1.Header), 2)
	if err := ca.AddBlock(b2); err != nil {
		t.Fatal(err)
	}
	if err := a.BroadcastBlock(b2); err != nil {
		t.Fatal(err)
	}
	waitHeight(cb, 2)
	restarted := chain.NewMemory()
	if err := restarted.LoadOrInit(cdir, g); err != nil {
		t.Fatal(err)
	}
	if restarted.Height() != 1 {
		t.Fatal("persisted restart lost history")
	}
	c2, err := NewLibp2p([]string{"/ip4/127.0.0.1/tcp/0"}, types.NetworkMagicTestnet, restarted, mempool.New(4))
	if err != nil {
		t.Fatal(err)
	}
	if err = c2.Start(); err != nil {
		t.Fatal(err)
	}
	defer c2.Shutdown()
	if err = c2.ConnectSeed(ctx, b.Addrs()[0]); err != nil {
		t.Fatal(err)
	}
	waitHeight(restarted, 2)
	// A creates a valid longer competing suffix from the common genesis.
	f1 := mineEasyBlock(types.HeaderID(&g.Header), 1)
	f1.Header.Timestamp--
	f1.Header.Nonce = 1
	f2 := mineEasyBlock(types.HeaderID(&f1.Header), 2)
	f3 := mineEasyBlock(types.HeaderID(&f2.Header), 3)
	if err = ca.ReorgTo([]*types.Block{f1, f2, f3}); err != nil {
		t.Fatal(err)
	}
	// Fetch through the real sync protocol, then use each receiver's independent
	// consensus/reorg checks. Equal histories must converge on the exact tip.
	for _, receiver := range []*Libp2pNode{b, c2} {
		if err = receiver.ConnectSeed(ctx, a.Addrs()[0]); err != nil {
			t.Fatal(err)
		}
		blocks, e := receiver.GetBlocks(ctx, a.host.ID(), 1, 3)
		if e != nil {
			t.Fatal(e)
		}
		if e = receiver.chain.ReorgTo(blocks); e != nil {
			t.Fatal(e)
		}
		got, _ := receiver.chain.Tip()
		if types.HeaderID(&got) != types.HeaderID(&f3.Header) {
			t.Fatal("fork did not converge")
		}
	}
}

func TestThreeNodeInvalidBlockIsNotForwarded(t *testing.T) {
	if testing.Short() {
		t.Skip("local gossip mesh")
	}
	g := easyGenesis()
	a, _, _, stopA := bringUpNode(t, "source", g)
	defer stopA()
	b, cb, _, stopB := bringUpNode(t, "validating", g)
	defer stopB()
	c, _, _, stopC := bringUpNode(t, "observer", g)
	defer stopC()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e := b.ConnectSeed(ctx, a.Addrs()[0]); e != nil {
		t.Fatal(e)
	}
	if e := c.ConnectSeed(ctx, b.Addrs()[0]); e != nil {
		t.Fatal(e)
	}
	// The untrusted source bypasses its own application validator deliberately;
	// the observer records whether the middle node forwards the invalid block.
	if e := a.ps.UnregisterTopicValidator(topicBlocks(a.magic)); e != nil {
		t.Fatal(e)
	}
	if e := c.ps.UnregisterTopicValidator(topicBlocks(c.magic)); e != nil {
		t.Fatal(e)
	}
	var received atomic.Int64
	if e := c.ps.RegisterTopicValidator(topicBlocks(c.magic), func(_ context.Context, _ peer.ID, _ *pubsub.Message) bool { received.Add(1); return false }); e != nil {
		t.Fatal(e)
	}
	time.Sleep(2 * time.Second)
	bad := mineEasyBlock(types.HeaderID(&g.Header), 1)
	bad.Kernels[0].ExcessSig[5] ^= 1
	types.SetBlockRoots(bad)
	if e := a.BroadcastBlock(bad); e != nil {
		t.Fatal(e)
	}
	time.Sleep(time.Second)
	if cb.Height() != 0 {
		t.Fatal("invalid block applied")
	}
	if received.Load() != 0 {
		t.Fatal("invalid block forwarded to observer")
	}
	good := mineEasyBlock(types.HeaderID(&g.Header), 1)
	if e := a.BroadcastBlock(good); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(3 * time.Second)
	for received.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if received.Load() == 0 || cb.Height() != 1 {
		t.Fatal("control valid block did not traverse middle node")
	}
}

func TestPreAdmittedNativeTransactionGossips(t *testing.T) {
	if testing.Short() {
		t.Skip("mature signed coinbase history and native proof")
	}
	g := easyGenesis()
	a, ca, pa, stopA := bringUpNode(t, "sender", g)
	defer stopA()
	b, cb, pb, stopB := bringUpNode(t, "receiver", g)
	defer stopB()
	parent := types.HeaderID(&g.Header)
	genesisHash := parent
	var first *types.Block
	for h := uint64(1); h <= types.CoinbaseLock; h++ {
		block := mineEasyBlock(parent, h)
		if h == 1 {
			first = block
		}
		if e := ca.AddBlock(block); e != nil {
			t.Fatal(e)
		}
		if e := cb.AddBlock(block); e != nil {
			t.Fatal(e)
		}
		parent = types.HeaderID(&block.Header)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if e := b.ConnectSeed(ctx, a.Addrs()[0]); e != nil {
		t.Fatal(e)
	}
	time.Sleep(2 * time.Second)
	output, e := wallet.NewPlainOutput(types.BlockReward(1))
	if e != nil {
		t.Fatal(e)
	}
	var inputBlind [32]byte
	inputBlind[31] = 2
	inputBlind[30] = genesisHash[0]
	var excess, negative secp.ModNScalar
	outBlind := [32]byte(output.Blinding)
	excess.SetBytes(&outBlind)
	negative.SetBytes(&inputBlind)
	negative.Negate()
	excess.Add(&negative)
	secret := excess.Bytes()
	commit, e := v2crypto.PedersenCommit(0, secret[:])
	if e != nil {
		t.Fatal(e)
	}
	kernel := types.Kernel{Features: types.KernelFeaturesPlain, Excess: commit}
	// Kernel signatures bind the chain's network magic: the test chain's headers
	// carry NetworkMagicTestnet, the same value the libp2p nodes are given.
	digest := types.KernelSigningMessage(g.Header.NetworkMagic, &kernel)
	kernel.ExcessSig, e = v2crypto.SchnorrSign(secret[:], digest)
	if e != nil {
		t.Fatal(e)
	}
	tx := &types.Transaction{Inputs: []types.Input{{Features: types.OutputFeaturesCoinbase, Commit: first.Outputs[0].Commit}}, Outputs: []types.Output{output.Output}, Kernels: []types.Kernel{kernel}}
	if _, e = pa.Add(tx); e != nil {
		t.Fatalf("real mature transaction admission: %v", e)
	}
	if e = a.BroadcastTx(tx); e != nil {
		t.Fatalf("pre-admitted transaction publish: %v", e)
	}
	deadline := time.Now().Add(5 * time.Second)
	for pb.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if pb.Len() != 1 || mempool.TxID(pb.Snapshot()[0]) != mempool.TxID(tx) {
		t.Fatal("native transaction did not propagate")
	}
}
