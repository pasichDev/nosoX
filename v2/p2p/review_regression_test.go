package p2p

// Regression tests for the network review (N1, N3, N5-N9, N11, N15, F2, F9,
// H2, M9 and the p2p Low items). Each test fails on the pre-fix tree.

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/record"
	"github.com/libp2p/go-msgio"

	"github.com/pasichDev/noso-go/v2/chain"
	"github.com/pasichDev/noso-go/v2/mempool"
	"github.com/pasichDev/noso-go/v2/types"
)

// ---- helpers -----------------------------------------------------------

func rawHost(t *testing.T) host.Host {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func link(t *testing.T, h host.Host, n *Libp2pNode) {
	t.Helper()
	ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	if err := h.Connect(ctx, peer.AddrInfo{ID: n.host.ID(), Addrs: n.host.Addrs()}); err != nil {
		t.Fatal(err)
	}
}

// extend mines blocks from..to on parent. When c is set they are applied to it.
func extend(t *testing.T, c *chain.Chain, parent types.Hash, from, to uint64, salt byte) (types.Hash, []*types.Block) {
	t.Helper()
	var out []*types.Block
	for h := from; h <= to; h++ {
		b := mineEasyBlock(parent, h)
		b.Header.Timestamp += int64(salt)
		// salt changes the header, so the PoW must be redone (difficulty 1 passes at once)
		b.Header.Nonce = 0
		if c != nil {
			if err := c.AddBlock(b); err != nil {
				t.Fatalf("extend height %d: %v", h, err)
			}
		}
		parent = types.HeaderID(&b.Header)
		out = append(out, b)
	}
	return parent, out
}

func apply(t *testing.T, c *chain.Chain, blocks []*types.Block) {
	t.Helper()
	for _, b := range blocks {
		if err := c.AddBlock(b); err != nil {
			t.Fatalf("apply height %d: %v", b.Header.Height, err)
		}
	}
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timeout after %v: %s", d, what)
}

func sameTip(a, b *chain.Chain) bool {
	ta, _ := a.Tip()
	tb, _ := b.Tip()
	return types.HeaderID(&ta) == types.HeaderID(&tb)
}

func dial(t *testing.T, from, to *Libp2pNode) {
	t.Helper()
	ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	if err := from.ConnectSeed(ctx, to.Addrs()[0]); err != nil {
		t.Fatal(err)
	}
}

// evilHello makes a raw host answer hello with the given status.
func evilHello(h host.Host, st Status) {
	h.SetStreamHandler(ProtocolHello, func(s network.Stream) {
		defer s.Close()
		_, _ = readFrame(s, maxStatusBytes)
		_ = writeFrame(s, encodeStatus(st))
	})
}

func bigWork(bits uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), bits) }

// ---- N1 / F2: convergence by work -------------------------------------

func TestConvergePartitionedPairDeepFork(t *testing.T) {
	g := easyGenesis()
	a, ca, _, sa := bringUpNode(t, "A", g)
	defer sa()
	b, cb, _, sb := bringUpNode(t, "B", g)
	defer sb()
	root := types.HeaderID(&g.Header)
	extend(t, ca, root, 1, 12, 0)
	extend(t, cb, root, 1, 6, 1)
	dial(t, b, a)
	waitFor(t, 30*time.Second, "B adopts the heavier fork from genesis", func() bool { return sameTip(ca, cb) })
	if cb.Height() != 12 {
		t.Fatalf("height %d", cb.Height())
	}
	if ca.Height() != 12 {
		t.Fatalf("heavier chain was disturbed: %d", ca.Height())
	}
}

func TestFreshNodePoisonedByShortForkRecovers(t *testing.T) {
	g := easyGenesis()
	evil, ce, _, s1 := bringUpNode(t, "evil", g)
	defer s1()
	honest, ch, _, s2 := bringUpNode(t, "honest", g)
	defer s2()
	root := types.HeaderID(&g.Header)
	extend(t, ce, root, 1, 2, 1)
	extend(t, ch, root, 1, 30, 0)
	v, cv, _, s3 := bringUpNode(t, "victim", g)
	defer s3()
	dial(t, v, evil)
	waitFor(t, 20*time.Second, "victim takes the short fork first", func() bool { return cv.Height() == 2 })
	dial(t, v, honest)
	waitFor(t, 60*time.Second, "victim leaves the short fork for the honest chain", func() bool { return sameTip(cv, ch) })
}

// A fork whose heavier side is longer than one 64-block batch and deeper than
// the old 4-block window.
func TestConvergeForkLongerThanOneBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("mines ~80 blocks")
	}
	g := easyGenesis()
	a, ca, _, sa := bringUpNode(t, "A", g)
	defer sa()
	b, cb, _, sb := bringUpNode(t, "B", g)
	defer sb()
	root := types.HeaderID(&g.Header)
	tip, common := extend(t, ca, root, 1, 3, 0)
	apply(t, cb, common)
	extend(t, ca, tip, 4, 74, 0) // 71 blocks on A
	extend(t, cb, tip, 4, 9, 1)  // 6 blocks on B
	dial(t, b, a)
	waitFor(t, 120*time.Second, "B adopts 71-block fork", func() bool { return sameTip(ca, cb) })
}

// Two nodes that were connected, split, mined different forks and reconnect.
func TestHealedPartitionConverges(t *testing.T) {
	g := easyGenesis()
	a, ca, _, sa := bringUpNode(t, "A", g)
	defer sa()
	b, cb, _, sb := bringUpNode(t, "B", g)
	defer sb()
	dial(t, b, a)
	time.Sleep(time.Second)
	_ = a.host.Network().ClosePeer(b.host.ID())
	waitFor(t, 5*time.Second, "split", func() bool { return a.PeerCount() == 0 && b.PeerCount() == 0 })
	root := types.HeaderID(&g.Header)
	extend(t, ca, root, 1, 6, 0)
	extend(t, cb, root, 1, 9, 1) // B is heavier
	dial(t, a, b)
	waitFor(t, 30*time.Second, "A converges onto B", func() bool { return sameTip(ca, cb) })
	if ca.Height() != 9 {
		t.Fatalf("height %d", ca.Height())
	}
}

func TestHelloAdvertisesCumulativeWork(t *testing.T) {
	g := easyGenesis()
	a, ca, _, sa := bringUpNode(t, "A", g)
	defer sa()
	b, _, _, sb := bringUpNode(t, "B", g)
	defer sb()
	extend(t, ca, types.HeaderID(&g.Header), 1, 3, 0)
	dial(t, b, a)
	waitFor(t, 10*time.Second, "B learns A's status", func() bool {
		b.book.mu.Lock()
		defer b.book.mu.Unlock()
		ps := b.book.peers[a.host.ID()]
		return ps != nil && ps.haveStatus
	})
	b.book.mu.Lock()
	got := b.book.peers[a.host.ID()].status
	b.book.mu.Unlock()
	if got.TotalWork == nil || got.TotalWork.Cmp(ca.TotalWork()) != 0 || got.Height != 3 {
		t.Fatalf("status %+v want work %v", got, ca.TotalWork())
	}
}

// A peer that is SHORTER but heavier must be the one we sync from; a taller peer
// with no more work must be left alone.
func TestSyncChoosesByWorkNotHeight(t *testing.T) {
	g := easyGenesis()
	v, cv, _, sv := bringUpNode(t, "victim", g)
	defer sv()
	extend(t, cv, types.HeaderID(&g.Header), 1, 5, 0)
	var shortAsked, tallAsked atomic.Int32
	serve := func(h host.Host, st Status, ctr *atomic.Int32) {
		evilHello(h, st)
		h.SetStreamHandler(ProtocolSync, func(s network.Stream) {
			defer s.Close()
			ctr.Add(1)
			_, _ = readFrame(s, maxSyncReqBytes)
			_ = writeFrame(s, []byte{respRateLimited})
		})
	}
	short, tall := rawHost(t), rawHost(t)
	serve(short, Status{Version: types.BlockVersion, NetworkMagic: v.magic, Height: 1, TotalWork: bigWork(200)}, &shortAsked)
	serve(tall, Status{Version: types.BlockVersion, NetworkMagic: v.magic, Height: 1 << 40, TotalWork: cv.TotalWork()}, &tallAsked)
	link(t, tall, v)
	link(t, short, v)
	waitFor(t, 10*time.Second, "victim syncs from the heavier peer", func() bool { return shortAsked.Load() > 0 })
	time.Sleep(time.Second)
	if tallAsked.Load() != 0 {
		t.Fatal("synced from a taller peer that has no more work")
	}
}

// ---- N3: the fetcher cannot be pinned ---------------------------------

func TestFetcherCannotBePinned(t *testing.T) {
	g := easyGenesis()
	honest, ch, _, s2 := bringUpNode(t, "honest", g)
	defer s2()
	extend(t, ch, types.HeaderID(&g.Header), 1, 8, 0)
	evil := rawHost(t)
	evilHello(evil, Status{Version: types.BlockVersion, NetworkMagic: types.NetworkMagicTestnet, Height: 1 << 40, TotalWork: bigWork(250)})
	evil.SetStreamHandler(ProtocolSync, func(s network.Stream) {
		defer s.Close()
		_, _ = readFrame(s, maxSyncReqBytes)
		_ = writeFrame(s, []byte{respRateLimited})
	})
	v, cv, _, s3 := bringUpNode(t, "victim", g)
	defer s3()
	link(t, evil, v)
	time.Sleep(time.Second)
	dial(t, v, honest)
	waitFor(t, 60*time.Second, "victim syncs the honest chain despite the stalling peer", func() bool { return sameTip(cv, ch) })
}

func TestLyingPeerIsScoredAndDropped(t *testing.T) {
	g := easyGenesis()
	evil := rawHost(t)
	evilHello(evil, Status{Version: types.BlockVersion, NetworkMagic: types.NetworkMagicTestnet, Height: 10, TotalWork: bigWork(250)})
	evil.SetStreamHandler(ProtocolSync, func(s network.Stream) {
		defer s.Close()
		_, _ = readFrame(s, maxSyncReqBytes)
		_ = writeFrame(s, []byte{0xee, 0xee}) // not a valid response
	})
	v, _, _, s3 := bringUpNode(t, "victim", g)
	defer s3()
	link(t, evil, v)
	waitFor(t, 20*time.Second, "liar banned", func() bool { return v.book.isBanned(evil.ID()) })
	waitFor(t, 5*time.Second, "liar disconnected", func() bool { return v.ConnectionState(evil.ID()) != network.Connected })
}

func TestPenaltiesAccumulateAndDecay(t *testing.T) {
	b := newPeerBook()
	p := peer.ID("p")
	if b.penalize(p, penaltyWorkLie) || b.isBanned(p) {
		t.Fatal("one work lie must not ban")
	}
	if !b.penalize(p, penaltyWorkLie) || !b.isBanned(p) {
		t.Fatal("two work lies must ban")
	}
	q := peer.ID("q")
	if !b.penalize(q, penaltyInvalid) {
		t.Fatal("invalid data bans at once")
	}
}

// A node far more than 64 blocks behind, told about the tip by gossip only.
func TestFarBehindNodeRecoversFromGossip(t *testing.T) {
	if testing.Short() {
		t.Skip("mines ~90 blocks")
	}
	g := easyGenesis()
	a, ca, _, sa := bringUpNode(t, "A", g)
	defer sa()
	b, cb, _, sb := bringUpNode(t, "B", g)
	defer sb()
	dial(t, b, a)
	time.Sleep(2500 * time.Millisecond) // hello + mesh while both are at genesis
	_, blocks := extend(t, ca, types.HeaderID(&g.Header), 1, 90, 0)
	if err := a.BroadcastBlock(blocks[len(blocks)-1]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 120*time.Second, "B recovers 90 blocks", func() bool { return cb.Height() == 90 })
}

// ---- N9 / N15: sync service limits ------------------------------------

func TestIdleStreamsDoNotExhaustSyncSlots(t *testing.T) {
	g := easyGenesis()
	srv, cs, _, s1 := bringUpNode(t, "srv", g)
	defer s1()
	extend(t, cs, types.HeaderID(&g.Header), 1, 3, 0)
	var held []network.Stream
	for range 3 {
		h := rawHost(t)
		link(t, h, srv)
		for range 3 {
			st, err := h.NewStream(context.Background(), srv.host.ID(), ProtocolSync)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = st.Write([]byte{0}) // negotiate, never finish the frame
			held = append(held, st)
		}
	}
	time.Sleep(500 * time.Millisecond)
	if len(srv.sync.slots) != 0 {
		t.Fatalf("idle streams hold %d global slots", len(srv.sync.slots))
	}
	c2, _, _, s2 := bringUpNode(t, "client", g)
	defer s2()
	dial(t, c2, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	blocks, err := c2.GetBlocks(ctx, srv.host.ID(), 1, 3)
	if err != nil || len(blocks) != 3 {
		t.Fatalf("honest GetBlocks: %v %d", len(blocks), err)
	}
	_ = held
}

func TestOneSyncStreamPerPeer(t *testing.T) {
	s := newSyncServer()
	p := peer.ID("p")
	if !s.enter(p) || s.enter(p) {
		t.Fatal("per-peer stream cap not enforced")
	}
	s.leave(p)
	if !s.enter(p) {
		t.Fatal("slot not released")
	}
}

func TestByteBudgetBoundsGlobalServing(t *testing.T) {
	b := newByteBudget(1, 100)
	if !b.available() {
		t.Fatal("fresh budget empty")
	}
	b.spend(1000)
	if b.available() {
		t.Fatal("overdrawn budget still serves")
	}
}

func TestMaintenanceGarbageCollectsLimiters(t *testing.T) {
	old := limiterTTL
	limiterTTL = 0
	defer func() { limiterTTL = old }()
	g := easyGenesis()
	dir := filepath.Join(t.TempDir(), "n")
	c := chain.NewMemory()
	if err := c.LoadOrInit(dir, g); err != nil {
		t.Fatal(err)
	}
	n, err := NewLibp2pWithOptions(Options{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}, Magic: types.NetworkMagicTestnet, MaintenanceInterval: 100 * time.Millisecond}, c, mempool.NewValidated(0, c.ValidateTransaction))
	if err != nil {
		t.Fatal(err)
	}
	defer n.Shutdown()
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	for i := range 50 {
		n.sync.limiter.allow(peerID(i))
	}
	waitFor(t, 5*time.Second, "limiter gc", func() bool {
		n.sync.limiter.mu.Lock()
		defer n.sync.limiter.mu.Unlock()
		return len(n.sync.limiter.buckets) == 0
	})
}

// ---- N7: wire limits ---------------------------------------------------

func TestDecodeAmplificationIsBounded(t *testing.T) {
	// The old JSON payload that allocated 2.4 GiB, and a generic oversize blob.
	var buf bytes.Buffer
	buf.WriteString(`{"Kernels":[{}`)
	for buf.Len() < 15<<20 {
		buf.WriteString(`,{}`)
	}
	buf.WriteString(`]}`)
	for _, raw := range [][]byte{buf.Bytes(), bytes.Repeat([]byte{4}, 15<<20)} {
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		_, e1 := decodeBlockMsg(raw)
		_, e2 := decodeTxMsg(raw)
		runtime.ReadMemStats(&m1)
		if e1 == nil || e2 == nil {
			t.Fatal("oversized payload accepted")
		}
		if d := m1.TotalAlloc - m0.TotalAlloc; d > 1<<20 {
			t.Fatalf("decoding a %d MiB payload allocated %d KiB", len(raw)>>20, d>>10)
		}
	}
}

func TestWireLimitsDerivedFromProtocol(t *testing.T) {
	if maxBlockWireBytes > types.MaxBlockBodyBytes+4096 {
		t.Fatalf("block wire limit %d is not derived from MaxBlockBodyBytes", maxBlockWireBytes)
	}
	// A maximal legal block fits the limit and round-trips.
	b := &types.Block{Header: types.BlockHeader{Height: 1, Nonce: 7}}
	for range types.MaxBlockInputs {
		b.Inputs = append(b.Inputs, types.Input{Features: 1})
	}
	for range types.MaxBlockOutputs {
		b.Outputs = append(b.Outputs, types.Output{RangeProof: bytes.Repeat([]byte{9}, types.MaxRangeProofBytes)})
	}
	for range types.MaxBlockKernels {
		b.Kernels = append(b.Kernels, types.Kernel{Fee: 3, ExcessSig: make([]byte, 65)})
	}
	raw, err := encodeBlockMsg(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > maxBlockWireBytes {
		t.Fatalf("maximal block %d > limit %d", len(raw), maxBlockWireBytes)
	}
	got, err := decodeBlockMsg(raw)
	if err != nil || types.HeaderID(&got.Header) != types.HeaderID(&b.Header) || len(got.Outputs[3].RangeProof) != types.MaxRangeProofBytes {
		t.Fatalf("round trip: %v", err)
	}
	// Counts above the limit are rejected before anything is allocated.
	bad := append([]byte(nil), raw[:headerWireBytes]...)
	bad = append(bad, 200, 0, 0)
	if _, err := decodeBlockMsg(bad); err == nil {
		t.Fatal("200 inputs accepted")
	}
	st := Status{Version: 5, NetworkMagic: 1, Height: 9, TotalWork: bigWork(100)}
	back, err := decodeStatus(encodeStatus(st))
	if err != nil || back.TotalWork.Cmp(st.TotalWork) != 0 || back.Height != 9 {
		t.Fatalf("status round trip: %v %+v", err, back)
	}
}

// ---- N8 / H2: gossip ---------------------------------------------------

func pubsubHost(t *testing.T) (host.Host, *pubsub.PubSub) {
	t.Helper()
	h := rawHost(t)
	ps, err := pubsub.NewGossipSub(context.Background(), h, pubsub.WithMaxMessageSize(maxGossipRPCBytes))
	if err != nil {
		t.Fatal(err)
	}
	return h, ps
}

func TestReplayedBlockIsNotForwarded(t *testing.T) {
	g := easyGenesis()
	v, cv, _, s1 := bringUpNode(t, "victim", g)
	defer s1()
	_, blocks := extend(t, cv, types.HeaderID(&g.Header), 1, 10, 0)
	ah, aps := pubsubHost(t)
	oh, ops := pubsubHost(t)
	link(t, ah, v)
	link(t, oh, v)
	at, _ := aps.Join(topicBlocks(v.magic))
	_, _ = at.Subscribe()
	ot, _ := ops.Join(topicBlocks(v.magic))
	osub, _ := ot.Subscribe()
	time.Sleep(2500 * time.Millisecond)
	raw, _ := encodeBlockMsg(blocks[2])
	var got atomic.Int32
	ctx, c := context.WithTimeout(context.Background(), 6*time.Second)
	defer c()
	go func() {
		for {
			if _, err := osub.Next(ctx); err != nil {
				return
			}
			got.Add(1)
		}
	}()
	for range 50 {
		_ = at.Publish(ctx, raw)
		time.Sleep(20 * time.Millisecond)
	}
	<-ctx.Done()
	if got.Load() != 0 {
		t.Fatalf("third party received %d copies of a replayed old block", got.Load())
	}
}

func TestDuplicateTxIsNotRevalidated(t *testing.T) {
	g := easyGenesis()
	c := chain.NewMemory()
	if err := c.LoadOrInit(filepath.Join(t.TempDir(), "c"), g); err != nil {
		t.Fatal(err)
	}
	var validations atomic.Int32
	mp := mempool.NewValidated(0, func(*types.Transaction) error { validations.Add(1); return nil })
	n, err := NewLibp2p([]string{"/ip4/127.0.0.1/tcp/0"}, types.NetworkMagicTestnet, c, mp)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Shutdown()
	tx := &types.Transaction{Kernels: []types.Kernel{{Fee: 1, ExcessSig: make([]byte, 65)}}}
	raw, err := encodeTxMsg(tx)
	if err != nil {
		t.Fatal(err)
	}
	remote := peer.ID("remote")
	if r := n.validateTxMsg(remote, raw); r != pubsub.ValidationAccept {
		t.Fatalf("first copy: %v", r)
	}
	for range 20 {
		if r := n.validateTxMsg(remote, raw); r != pubsub.ValidationIgnore {
			t.Fatalf("duplicate must be ignored, got %v", r)
		}
	}
	if validations.Load() != 1 {
		t.Fatalf("transaction validated %d times", validations.Load())
	}
	// Our own re-broadcast of a pooled tx must still go out.
	if r := n.validateTxMsg(n.host.ID(), raw); r != pubsub.ValidationAccept {
		t.Fatalf("local re-broadcast: %v", r)
	}
}

func TestGossipMessageIDIsContentHash(t *testing.T) {
	topic := "t"
	m1 := &pb.Message{Topic: &topic, Data: []byte("same"), Seqno: []byte{1}, From: []byte("a")}
	m2 := &pb.Message{Topic: &topic, Data: []byte("same"), Seqno: []byte{2}, From: []byte("b")}
	m3 := &pb.Message{Topic: &topic, Data: []byte("other"), Seqno: []byte{1}, From: []byte("a")}
	if contentMsgID(m1) != contentMsgID(m2) || contentMsgID(m1) == contentMsgID(m3) {
		t.Fatal("message ID is not a content hash")
	}
}

// A transaction flood that fills the transaction validator must not stop blocks.
func TestTxFloodDoesNotStarveBlocks(t *testing.T) {
	g := easyGenesis()
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	defer free()

	vc := chain.NewMemory()
	if err := vc.LoadOrInit(filepath.Join(t.TempDir(), "v"), g); err != nil {
		t.Fatal(err)
	}
	mp := mempool.NewValidated(0, func(*types.Transaction) error { <-release; return nil })
	v, err := NewLibp2p([]string{"/ip4/127.0.0.1/tcp/0"}, types.NetworkMagicTestnet, vc, mp)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { free(); _ = v.Shutdown() }()

	honest, ch, _, sh := bringUpNode(t, "honest", g)
	defer sh()
	ah, aps := pubsubHost(t)
	link(t, ah, v)
	dial(t, honest, v)
	at, _ := aps.Join(topicTxs(v.magic))
	_, _ = at.Subscribe()
	time.Sleep(2500 * time.Millisecond)
	for i := range 40 {
		tx := &types.Transaction{Kernels: []types.Kernel{{Fee: uint64(i + 1), ExcessSig: make([]byte, 65)}}}
		raw, _ := encodeTxMsg(tx)
		_ = at.Publish(context.Background(), raw)
	}
	time.Sleep(300 * time.Millisecond)
	_, blocks := extend(t, ch, types.HeaderID(&g.Header), 1, 1, 0)
	if err := honest.BroadcastBlock(blocks[0]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "block accepted during a tx flood", func() bool { return vc.Height() == 1 })
}

// ---- N5: scoring, gater, PX -------------------------------------------

func TestGarbagePeerIsDroppedAndBanned(t *testing.T) {
	g := easyGenesis()
	v, _, _, s1 := bringUpNode(t, "victim", g)
	defer s1()
	ah, aps := pubsubHost(t)
	link(t, ah, v)
	at, _ := aps.Join(topicBlocks(v.magic))
	time.Sleep(2500 * time.Millisecond)
	for i := range 2000 {
		_ = at.Publish(context.Background(), []byte(fmt.Sprintf("garbage%d", i)))
		if v.book.isBanned(ah.ID()) {
			break
		}
	}
	waitFor(t, 5*time.Second, "garbage sender banned", func() bool { return v.book.isBanned(ah.ID()) })
	waitFor(t, 5*time.Second, "garbage sender disconnected", func() bool { return v.ConnectionState(ah.ID()) != network.Connected })
	ctx, c := context.WithTimeout(context.Background(), 3*time.Second)
	defer c()
	if err := ah.Connect(ctx, peer.AddrInfo{ID: v.host.ID(), Addrs: v.host.Addrs()}); err == nil {
		time.Sleep(500 * time.Millisecond)
		if v.ConnectionState(ah.ID()) == network.Connected {
			t.Fatal("banned peer reconnected")
		}
	}
}

func TestWrongNetworkPeerIsDropped(t *testing.T) {
	g := easyGenesis()
	v, _, _, s1 := bringUpNode(t, "victim", g)
	defer s1()
	other := rawHost(t)
	evilHello(other, Status{Version: types.BlockVersion, NetworkMagic: types.NetworkMagicMainnet, TotalWork: big.NewInt(1)})
	link(t, other, v)
	waitFor(t, 10*time.Second, "wrong-network peer dropped", func() bool {
		return v.ConnectionState(other.ID()) != network.Connected && v.book.isBanned(other.ID())
	})
}

func sendRPC(t *testing.T, h host.Host, to peer.ID, rpc *pb.RPC) {
	t.Helper()
	s, err := h.NewStream(context.Background(), to, "/meshsub/1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := rpc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := msgio.NewVarintWriter(s).WriteMsg(raw); err != nil {
		t.Log("send:", err)
	}
}

func TestPeerExchangeCannotSteerDials(t *testing.T) {
	g := easyGenesis()
	v, _, _, s1 := bringUpNode(t, "victim", g)
	defer s1()
	h := rawHost(t)
	link(t, h, v)
	sybil := rawHost(t)
	time.Sleep(300 * time.Millisecond)
	rec := &peer.PeerRecord{PeerID: sybil.ID(), Addrs: sybil.Addrs(), Seq: 1}
	var priv crypto.PrivKey = sybil.Peerstore().PrivKey(sybil.ID())
	env, err := record.Seal(rec, priv)
	if err != nil {
		t.Fatal(err)
	}
	spr, _ := env.Marshal()
	topic := topicBlocks(v.magic)
	sendRPC(t, h, v.host.ID(), &pb.RPC{Control: &pb.ControlMessage{Prune: []*pb.ControlPrune{{TopicID: &topic, Peers: []*pb.PeerInfo{{PeerID: []byte(sybil.ID()), SignedPeerRecord: spr}}}}}})
	time.Sleep(3 * time.Second)
	if v.ConnectionState(sybil.ID()) == network.Connected {
		t.Fatal("victim dialed an attacker-named peer from PX")
	}
}

// ---- N6: subscription flood -------------------------------------------

func TestSubscriptionFloodIsBounded(t *testing.T) {
	g := easyGenesis()
	v, _, _, s1 := bringUpNode(t, "victim", g)
	defer s1()
	h := rawHost(t)
	link(t, h, v)
	time.Sleep(300 * time.Millisecond)
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	tr := true
	rpc := &pb.RPC{}
	for i := 0; len(rpc.Subscriptions) < 400000; i++ {
		s := fmt.Sprintf("%x", i)
		rpc.Subscriptions = append(rpc.Subscriptions, &pb.RPC_SubOpts{Subscribe: &tr, Topicid: &s})
	}
	sendRPC(t, h, v.host.ID(), rpc)
	rpc = nil
	time.Sleep(3 * time.Second)
	runtime.GC()
	runtime.ReadMemStats(&m1)
	if d := (int64(m1.HeapAlloc) - int64(m0.HeapAlloc)) >> 20; d > 48 {
		t.Fatalf("subscription flood retained %d MiB", d)
	}
}

func TestOnlyOurTopicsAreTracked(t *testing.T) {
	g := easyGenesis()
	v, _, _, s1 := bringUpNode(t, "victim", g)
	defer s1()
	ah, aps := pubsubHost(t)
	link(t, ah, v)
	ours, junk := topicBlocks(v.magic), "junk-topic"
	for _, name := range []string{ours, junk} {
		tp, err := aps.Join(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tp.Subscribe(); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 5*time.Second, "our topic tracked", func() bool { return len(v.ps.ListPeers(ours)) == 1 })
	if len(v.ps.ListPeers(junk)) != 0 {
		t.Fatal("subscription to a foreign topic was retained")
	}
}

// ---- N11: identity, reconnect, empty seeds ----------------------------

func TestIdentityPersistsWith0600(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateIdentity(dir)
	if err != nil || !k1.Equals(k2) {
		t.Fatalf("identity changed across loads: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, IdentityFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v err %v", fi.Mode(), err)
	}
	if err := os.Chmod(filepath.Join(dir, IdentityFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateIdentity(dir); err == nil {
		t.Fatal("world-readable key accepted")
	}
}

func newPersistentNode(t *testing.T, dir string, listen string, g *types.Block) (*Libp2pNode, *chain.Chain) {
	t.Helper()
	c := chain.NewMemory()
	if err := c.LoadOrInit(filepath.Join(t.TempDir(), "c"), g); err != nil {
		t.Fatal(err)
	}
	n, err := NewLibp2pWithOptions(Options{ListenAddrs: []string{listen}, Magic: types.NetworkMagicTestnet, DataDir: dir, MaintenanceInterval: 200 * time.Millisecond}, c, mempool.NewValidated(0, c.ValidateTransaction))
	if err != nil {
		t.Fatal(err)
	}
	n.SetLogger(func(f string, a ...any) { t.Logf(f, a...) })
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	return n, c
}

func TestSeedAddressSurvivesRestartAndNodeReconnects(t *testing.T) {
	g := easyGenesis()
	seedDir := t.TempDir()
	a, _ := newPersistentNode(t, seedDir, "/ip4/127.0.0.1/tcp/0", g)
	addr := a.Addrs()[0]
	id := a.ID()
	_ = a.Shutdown()

	// The seed is down when B starts.
	b, _ := newPersistentNode(t, t.TempDir(), "/ip4/127.0.0.1/tcp/0", g)
	defer b.Shutdown()
	b.Bootstrap(BootstrapConfig{Network: "testnet", Seeds: []string{addr}})
	time.Sleep(500 * time.Millisecond)
	if b.PeerCount() != 0 {
		t.Fatal("connected to a seed that is down")
	}
	// Same data dir, same port: same peer ID, so the published address still works.
	listen := strings.SplitN(addr, "/p2p/", 2)[0]
	a2, _ := newPersistentNode(t, seedDir, listen, g)
	defer a2.Shutdown()
	if a2.ID() != id {
		t.Fatalf("peer ID changed across restart: %s -> %s", id, a2.ID())
	}
	waitFor(t, 15*time.Second, "B reconnects to the restarted seed", func() bool { return b.ConnectionState(id) == network.Connected })
	// And again after the connection is cut.
	_ = b.host.Network().ClosePeer(id)
	waitFor(t, 15*time.Second, "B redials after a dropped connection", func() bool { return b.ConnectionState(id) == network.Connected })
}

func TestKnownPeersPersistAndAreRedialed(t *testing.T) {
	g := easyGenesis()
	a, _ := newPersistentNode(t, t.TempDir(), "/ip4/127.0.0.1/tcp/0", g)
	defer a.Shutdown()
	dirB := t.TempDir()
	b, _ := newPersistentNode(t, dirB, "/ip4/127.0.0.1/tcp/0", g)
	dial(t, b, a)
	waitFor(t, 10*time.Second, "B knows A", func() bool {
		b.netMu.Lock()
		defer b.netMu.Unlock()
		return len(b.known) == 1
	})
	_ = b.Shutdown()
	fi, err := os.Stat(filepath.Join(dirB, peersFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("peer book: %v %v", fi, err)
	}
	b2, _ := newPersistentNode(t, dirB, "/ip4/127.0.0.1/tcp/0", g)
	defer b2.Shutdown()
	waitFor(t, 15*time.Second, "restarted node redials its known peer without seeds", func() bool { return b2.ConnectionState(a.ID()) == network.Connected })
}

func TestEmptySeedListWarns(t *testing.T) {
	g := easyGenesis()
	n, _, _, stop := bringUpNode(t, "n", g)
	defer stop()
	var mu sync.Mutex
	var logs []string
	n.SetLogger(func(f string, a ...any) { mu.Lock(); logs = append(logs, fmt.Sprintf(f, a...)); mu.Unlock() })
	n.Bootstrap(BootstrapConfig{Network: "testnet"})
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(strings.Join(logs, "\n"), "WARNING: no seed") {
		t.Fatalf("no warning for an empty seed list: %v", logs)
	}
}

// ---- Low: NAT mapping is opt-in ---------------------------------------

func TestNATPortMapIsOptIn(t *testing.T) {
	if (Options{}).NATPortMap {
		t.Fatal("NAT port mapping must be off by default")
	}
}

// ---- M9: seed list ----------------------------------------------------

func TestSeedListRejectsPrivateAddresses(t *testing.T) {
	const id = "/p2p/12D3KooWBmwXbZQYZ8s8s9q5jq4dGq4dGq4dGq4dGq4dGq4dGq4d"
	for _, a := range []string{"/ip4/127.0.0.1/tcp/1", "/ip4/10.1.2.3/tcp/1", "/ip4/192.168.0.9/tcp/1", "/ip4/172.16.0.1/tcp/1",
		"/ip4/169.254.1.1/tcp/1", "/ip4/100.64.0.1/tcp/1", "/ip4/0.0.0.0/tcp/1", "/ip6/::1/tcp/1", "/ip6/fd00::1/tcp/1",
		"/dns4/localhost/tcp/1", "/dns4/printer.local/tcp/1"} {
		if IsPublicMultiaddr(a + id) {
			t.Errorf("%s accepted", a)
		}
	}
	for _, a := range []string{"/ip4/198.51.100.7/tcp/1", "/ip6/2001:db8::1/tcp/1", "/dns4/seed.example.com/tcp/1"} {
		if !IsPublicMultiaddr(a + id) {
			t.Errorf("%s rejected", a)
		}
	}
	got := FilterPublicSeeds([]string{"/ip4/127.0.0.1/tcp/1", "/ip4/198.51.100.7/tcp/1"})
	if len(got) != 1 || !strings.Contains(got[0], "198.51.100.7") {
		t.Fatalf("filter: %v", got)
	}
}

func TestSeedFetchIsPinnedAndRedirectsAreRestricted(t *testing.T) {
	for network, urls := range HTTPSeedURLs {
		for _, u := range urls {
			if strings.Contains(u, "/main/") || strings.Contains(u, "/master/") || !strings.Contains(u, "/"+SeedsRef+"/") {
				t.Errorf("%s seed URL is not pinned: %s", network, u)
			}
		}
	}
	c := newSeedClient()
	mk := func(u string) *http.Request { r, _ := http.NewRequest("GET", u, nil); return r }
	via := []*http.Request{mk("https://seeds.example/a")}
	if c.CheckRedirect(mk("https://seeds.example/b"), via) != nil {
		t.Error("same-host https redirect refused")
	}
	if c.CheckRedirect(mk("http://seeds.example/b"), via) == nil {
		t.Error("https->http redirect allowed")
	}
	if c.CheckRedirect(mk("https://evil.example/b"), via) == nil {
		t.Error("cross-host redirect allowed")
	}
	if c.CheckRedirect(mk("https://seeds.example/b"), append(via, via[0], via[0])) == nil {
		t.Error("redirect chain not bounded")
	}
}

// Go reports 0666 for every file on Windows, so a mode-bit check would refuse
// the key file on the second start. The decision is a function of GOOS so the
// Windows branch is testable anywhere.
func TestLooseModeIgnoresWindowsPseudoPermissions(t *testing.T) {
	if !looseMode("linux", 0o644) || !looseMode("darwin", 0o640) {
		t.Fatal("group/world readable key accepted on Unix")
	}
	if looseMode("linux", 0o600) {
		t.Fatal("0600 refused on Unix")
	}
	if looseMode("windows", 0o666) {
		t.Fatal("Windows' constant 0666 refused: the node could never restart")
	}
}
