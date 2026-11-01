package p2p

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/pasichDev/nosoX/v2/chain"
	v2crypto "github.com/pasichDev/nosoX/v2/crypto"
	"github.com/pasichDev/nosoX/v2/mempool"
	"github.com/pasichDev/nosoX/v2/types"
)

// extendSpaced mines blocks from..to on parent with the target spacing from g's
// timestamp, so difficulty stays at 1 beyond the 90-block LWMA window. salt
// shifts the fork's timestamps by a few seconds.
func extendSpaced(t *testing.T, c *chain.Chain, g *types.Block, parent types.Hash, from, to uint64, salt int64) (types.Hash, []*types.Block) {
	t.Helper()
	var out []*types.Block
	for h := from; h <= to; h++ {
		b := mineEasyBlock(parent, h)
		b.Header.Timestamp = g.Header.Timestamp + int64(h)*types.TargetBlockTimeSeconds + salt
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

// spacedGenesis is old enough that n target-spaced blocks stay within the
// future-drift limit.
func spacedGenesis(n uint64) *types.Block {
	g := easyGenesis()
	g.Header.Timestamp = time.Now().Unix() - int64(n+10)*types.TargetBlockTimeSeconds
	return g
}

// serveSync makes a raw host answer the sync protocol through onReq.
func serveSync(h host.Host, onReq func(syncReq) []byte) {
	h.SetStreamHandler(ProtocolSync, func(s network.Stream) {
		defer s.Close()
		raw, err := readFrame(s, maxSyncReqBytes)
		if err != nil {
			return
		}
		req, err := decodeSyncReq(raw)
		if err != nil {
			return
		}
		_ = writeFrame(s, onReq(req))
	})
}

func honestStatus(c *chain.Chain, magic uint32) Status {
	tip, _ := c.Tip()
	return Status{Version: types.BlockVersion, NetworkMagic: magic, Height: tip.Height, TipHash: types.HeaderID(&tip), TotalWork: c.TotalWork()}
}

// A peer that merely CLAIMS the honest tip and then serves garbage must cost
// itself a ban and nothing else: the claimed hash used to be remembered globally,
// after which every honest peer advertising that tip was skipped for ten
// minutes (S1).
func TestPoisonedClaimDoesNotBlockHonestPeers(t *testing.T) {
	g := easyGenesis()
	honest, ch, _, s1 := bringUpNode(t, "honest", g)
	defer s1()
	extend(t, ch, types.HeaderID(&g.Header), 1, 20, 0)
	claim := honestStatus(ch, honest.magic)
	claim.TotalWork = bigWork(250)

	evil := rawHost(t)
	evilHello(evil, claim)
	serveSync(evil, func(req syncReq) []byte {
		if req.Kind == reqLocator {
			return encodeLocatorResp(locatorResp{Found: true, Height: 0})
		}
		b, _ := ch.BlockByHeight(req.Blocks.From)
		bad := *b
		bad.Kernels = append([]types.Kernel(nil), b.Kernels...)
		bad.Kernels[0].LockHeight++ // body no longer matches the header's roots
		out, _ := encodeBlocksResp(&GetBlocksResp{Blocks: []*types.Block{&bad}})
		return out
	})
	v, cv, _, s2 := bringUpNode(t, "victim", g)
	defer s2()
	link(t, evil, v)
	waitFor(t, 20*time.Second, "provably invalid blocks ban the liar", func() bool { return v.book.isBanned(evil.ID()) })
	dial(t, v, honest)
	waitFor(t, 40*time.Second, "honest peer advertising the same tip is still used", func() bool { return sameTip(cv, ch) })
}

// Free identities that claim huge work and then stall must not starve sync: a
// peer that has delivered blocks outranks any number of unproven claims (S2).
func TestProvenPeerOutranksStallingClaims(t *testing.T) {
	g := easyGenesis()
	honest, ch, _, s1 := bringUpNode(t, "honest", g)
	defer s1()
	_, first := extend(t, ch, types.HeaderID(&g.Header), 1, 6, 0)
	v, cv, _, s2 := bringUpNode(t, "victim", g)
	defer s2()
	dial(t, v, honest)
	waitFor(t, 30*time.Second, "first sync", func() bool { return sameTip(cv, ch) })
	for i := 0; i < 3; i++ {
		e := rawHost(t)
		evilHello(e, Status{Version: types.BlockVersion, NetworkMagic: v.magic, Height: 1 << 30, TotalWork: bigWork(uint(250 + i))})
		serveSync(e, func(syncReq) []byte { time.Sleep(12 * time.Second); return []byte{respRateLimited} })
		link(t, e, v)
	}
	time.Sleep(time.Second)
	extend(t, ch, types.HeaderID(&first[len(first)-1].Header), 7, 9, 0) // no gossip: only sync can deliver them
	v.queryStatus(honest.host.ID())
	waitFor(t, 4*time.Second, "honest peer is asked before the stallers", func() bool { return cv.Height() == 9 })
}

// The locator must find the true common ancestor, not the sparse entry above it.
func TestAncestorSearchIsExact(t *testing.T) {
	g := spacedGenesis(320)
	a, ca, _, sa := bringUpNode(t, "A", g)
	defer sa()
	b, cb, _, sb := bringUpNode(t, "B", g)
	defer sb()
	root := types.HeaderID(&g.Header)
	tip, common := extendSpaced(t, ca, g, root, 1, 150, 0)
	apply(t, cb, common)
	extendSpaced(t, ca, g, tip, 151, 300, 1) // A: 150 more
	extendSpaced(t, cb, g, tip, 151, 310, 2) // B: 160 more (B's tip is 310, fork after 150)
	dial(t, b, a)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	got, err := b.FindAncestor(ctx, a.host.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got != 150 {
		t.Fatalf("common ancestor = %d, want 150 (the sparse locator would answer an older entry)", got)
	}
}

func TestSpreadHeights(t *testing.T) {
	for _, c := range [][2]uint64{{10, 11}, {10, 12}, {10, 40}, {0, 512}, {5, 1100}} {
		lo, hi := c[0], c[1]
		got := spreadHeights(lo, hi, 63)
		if hi-lo == 1 {
			if len(got) != 0 {
				t.Fatalf("%v: %v", c, got)
			}
			continue
		}
		if len(got) == 0 || len(got) > 63 || got[0] != hi-1 {
			t.Fatalf("%v: %d heights, first %v", c, len(got), got[:1])
		}
		for i, h := range got {
			if h <= lo || h >= hi || (i > 0 && h >= got[i-1]) {
				t.Fatalf("%v: bad height %d at %d", c, h, i)
			}
		}
		if hi-lo <= 64 && uint64(len(got)) != hi-lo-1 {
			t.Fatalf("%v: small gap must list every height, got %d", c, len(got))
		}
	}
}

// A fork 520-1024 blocks deep: the old sparse locator could only reach an entry
// 1031 blocks back, which it then refused as "too deep" (and, with the claimed
// hash remembered, never retried). Slow: it mines about 1500 blocks.
func TestDeepForkBeyondTheSparseLocatorConverges(t *testing.T) {
	if testing.Short() {
		t.Skip("mines ~1500 blocks")
	}
	if raceEnabled {
		t.Skip("about 1500 Argon2 blocks: too slow under the race detector (run without -race; the sync path itself is raced by the other multi-node tests)")
	}
	g := spacedGenesis(1050)
	a, ca, _, sa := bringUpNode(t, "A", g)
	defer sa()
	b, cb, _, sb := bringUpNode(t, "B", g)
	defer sb()
	root := types.HeaderID(&g.Header)
	tip, common := extendSpaced(t, nil, g, root, 1, 512, 0)
	apply(t, ca, common)
	apply(t, cb, common)
	_, fa := extendSpaced(t, nil, g, tip, 513, 1040, 1) // A: 528 blocks above the fork (heavier)
	_, fb := extendSpaced(t, nil, g, tip, 513, 1032, 2) // B: 520 blocks above the fork, tip 1032
	apply(t, ca, fa)
	apply(t, cb, fb)
	if cb.Height() != 1032 {
		t.Fatalf("setup: B at %d", cb.Height())
	}
	dial(t, b, a)
	waitFor(t, 240*time.Second, "B leaves its 520-deep fork for the heavier chain", func() bool { return sameTip(ca, cb) })
}

// What a failed hand-off costs the serving peer.
func TestBlameOnlyProvableInvalidity(t *testing.T) {
	g := easyGenesis()
	v, _, _, stop := bringUpNode(t, "victim", g)
	defer stop()
	blk := mineEasyBlock(types.HeaderID(&g.Header), 1)
	claim := Status{TipHash: types.Hash{1}}
	local := []error{chain.ErrStale, chain.ErrLowWork, chain.ErrFutureTimestamp, chain.ErrResourceBudget, chain.ErrTooDeep,
		chain.ErrCheckpoint, chain.ErrUnknownAnc, errors.New("badger: disk full"), fmt.Errorf("%w: x", chain.ErrStorage)}
	for i, e := range local {
		pid := peer.ID(fmt.Sprintf("local-%d", i))
		if err := v.blameBlock(pid, claim, blk, e); err == nil {
			t.Fatalf("%v: no error returned", e)
		}
		if err := v.blameFork(pid, claim, []*types.Block{blk}, e); err == nil {
			t.Fatalf("%v: no fork error returned", e)
		}
		if v.book.isBanned(pid) || v.book.appScore(pid) != 0 {
			t.Fatalf("%v penalized an honest peer for our own condition (score %v)", e, v.book.appScore(pid))
		}
		if v.isBadTip(pid, claim.TipHash) && !errors.Is(e, chain.ErrCheckpoint) && !errors.Is(e, chain.ErrTooDeep) {
			t.Fatalf("%v marked the peer's tip", e)
		}
	}
	for i, e := range []error{
		fmt.Errorf("%w: %w", chain.ErrInvalidBlock, chain.ErrBadPoW),
		fmt.Errorf("%w: wrong coinbase", chain.ErrInvalidBlock),
	} {
		pid := peer.ID(fmt.Sprintf("bad-%d", i))
		_ = v.blameBlock(pid, claim, blk, e)
		if !v.book.isBanned(pid) {
			t.Fatalf("provably invalid block (%v) did not ban", e)
		}
		pid2 := peer.ID(fmt.Sprintf("badfork-%d", i))
		_ = v.blameFork(pid2, claim, []*types.Block{blk}, e)
		if !v.book.isBanned(pid2) {
			t.Fatalf("provably invalid fork (%v) did not ban", e)
		}
	}
}

// A busy server's "rate limited" answer is not a failure to deliver (V1).
func TestBusyServerIsNotPenalized(t *testing.T) {
	g := easyGenesis()
	evil := rawHost(t)
	evilHello(evil, Status{Version: types.BlockVersion, NetworkMagic: types.NetworkMagicTestnet, Height: 5, TotalWork: bigWork(250)})
	serveSync(evil, func(syncReq) []byte { return []byte{respRateLimited} })
	v, _, _, stop := bringUpNode(t, "victim", g)
	defer stop()
	link(t, evil, v)
	waitFor(t, 5*time.Second, "status", func() bool {
		v.book.mu.Lock()
		defer v.book.mu.Unlock()
		ps := v.book.peers[evil.ID()]
		return ps != nil && ps.haveStatus
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := v.syncSession(ctx, evil.ID(), Status{Height: 5, TotalWork: bigWork(250)})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("session error = %v", err)
	}
	if got := v.book.appScore(evil.ID()); got != 0 {
		t.Fatalf("busy server scored %v", got)
	}
}

// The second stream of a peer is answered "busy", not reset (M7).
func TestSecondStreamGetsBusyNotReset(t *testing.T) {
	g := easyGenesis()
	srv, _, _, stop := bringUpNode(t, "srv", g)
	defer stop()
	cli := rawHost(t)
	link(t, cli, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	first, err := cli.NewStream(ctx, srv.host.ID(), ProtocolSync)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Reset()
	if _, err := first.Write([]byte{0}); err != nil { // start the frame, never finish it
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // the server's handler now holds the peer's one stream
	second, err := cli.NewStream(ctx, srv.host.ID(), ProtocolSync)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = writeFrame(second, encodeSyncReq(syncReq{Kind: reqLocator, Locator: []types.Hash{{1}}}))
	raw, err := readFrame(second, 16)
	if err != nil || len(raw) != 1 || raw[0] != respRateLimited {
		t.Fatalf("second stream: %v %v (want a rate-limited frame)", raw, err)
	}
}

// A node that is behind must not punish the honest relays that are ahead of it
// for transactions it cannot place yet (V1/M2).
func TestBehindNodeDoesNotPenalizeStateDependentTx(t *testing.T) {
	g := easyGenesis()
	v, _, _, stop := bringUpNode(t, "victim", g)
	defer stop()
	for _, e := range []error{
		fmt.Errorf("%w: %w", chain.ErrDoubleSpend, chain.ErrTxState),
		fmt.Errorf("%w: immature", chain.ErrTxState),
		chain.ErrDoubleSpend, mempool.ErrConflict, mempool.ErrReplaceFee,
	} {
		if res, pen := classifyTxAdmission(e, false); res != pubsub.ValidationIgnore || pen {
			t.Fatalf("%v: result %v penalize %v", e, res, pen)
		}
	}
	if res, pen := classifyTxAdmission(errors.New("chain: invalid kernel authorization"), false); res != pubsub.ValidationReject || !pen {
		t.Fatalf("stateless invalidity must still be rejected: %v %v", res, pen)
	}
	// End to end through the real validator: a spend of an input this node does
	// not hold, relayed many times by one honest peer.
	tx := unknownInputTx(t)
	data, err := encodeTxMsg(tx)
	if err != nil {
		t.Fatal(err)
	}
	relay := peer.ID("honest-relay")
	for i := 0; i < 40; i++ {
		if res := v.validateTxMsg(relay, data); res != pubsub.ValidationIgnore {
			t.Fatalf("relay %d: %v", i, res)
		}
	}
	if v.book.isBanned(relay) || v.book.appScore(relay) != 0 {
		t.Fatalf("honest relay penalized: banned=%v score=%v", v.book.isBanned(relay), v.book.appScore(relay))
	}
}

func unknownInputTx(t *testing.T) *types.Transaction {
	t.Helper()
	commit := func(seed byte) types.Commitment {
		blind := make([]byte, 32)
		blind[31] = seed
		c, err := v2crypto.PedersenCommit(5, blind)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	return &types.Transaction{
		Inputs:  []types.Input{{Features: types.OutputFeaturesPlain, Commit: commit(1)}},
		Outputs: []types.Output{{Features: types.OutputFeaturesPlain, Commit: commit(2), RangeProof: make([]byte, 600)}},
		Kernels: []types.Kernel{{Features: types.KernelFeaturesPlain, Fee: 10, Excess: commit(3), ExcessSig: make([]byte, 65)}},
	}
}

// Over-budget gossip is trimmed before pubsub marks it seen (G1): the validator
// runs after markSeen, so an Ignore there would burn the content ID.
func TestInspectorTrimsOverBudgetBeforePubsubSeesIt(t *testing.T) {
	g := easyGenesis()
	v, _, _, stop := bringUpNode(t, "victim", g)
	defer stop()
	m := peer.ID("flooder")
	topic := topicBlocks(v.magic)
	rpc := &pubsub.RPC{}
	for i := 0; i < 30; i++ {
		d := []byte{byte(i)}
		rpc.Publish = append(rpc.Publish, &pb.Message{Topic: &topic, Data: d})
	}
	v.inspectRPC(m, rpc)
	if n := len(rpc.Publish); n == 0 || n > 10 {
		t.Fatalf("%d of 30 block messages passed a burst-8 budget", n)
	}
	// A drained bucket removes a valid block's copy entirely.
	rpc2 := &pubsub.RPC{Publish: []*pb.Message{{Topic: &topic, Data: []byte("the block")}}}
	v.inspectRPC(m, rpc2)
	if len(rpc2.Publish) != 0 {
		t.Fatal("over-budget copy still reaches pubsub, where it would burn the message ID")
	}
	// Another peer's copy of the same message is untouched.
	rpc3 := &pubsub.RPC{Publish: []*pb.Message{{Topic: &topic, Data: []byte("the block")}}}
	v.inspectRPC(peer.ID("honest"), rpc3)
	if len(rpc3.Publish) != 1 {
		t.Fatal("honest peer's copy trimmed by someone else's budget")
	}
}

// Eight idle inbound connections must not stop the node redialing (E1).
func TestInboundSybilsDoNotStopRedialingHonestPeers(t *testing.T) {
	g := easyGenesis()
	honest, _, _, s1 := bringUpNode(t, "honest", g)
	defer s1()
	c := chain.NewMemory()
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	v, err := NewLibp2pWithOptions(Options{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}, Magic: types.NetworkMagicTestnet, TargetPeers: 4}, c, mempool.NewValidated(0, c.ValidateTransaction))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Shutdown()
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		link(t, rawHost(t), v)
	}
	waitFor(t, 5*time.Second, "sybils connected", func() bool { return v.PeerCount() >= 6 })
	info := peer.AddrInfo{ID: honest.host.ID(), Addrs: honest.host.Addrs()}
	v.netMu.Lock()
	v.seeds = []peer.AddrInfo{info}
	v.netMu.Unlock()
	v.reconnect()
	if v.ConnectionState(honest.host.ID()) != network.Connected {
		t.Fatal("the node counted inbound sybils toward its target and never dialed its seed")
	}
}

// Dead seeds must not use up the dial budget (api 6).
func TestDeadSeedsCannotExhaustDials(t *testing.T) {
	g := easyGenesis()
	honest, _, _, s1 := bringUpNode(t, "honest", g)
	defer s1()
	v, _, _, s2 := bringUpNode(t, "victim", g)
	defer s2()
	var dead []peer.AddrInfo
	for i := 0; i < 6; i++ {
		h := rawHost(t)
		info := peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()}
		_ = h.Close() // nothing listens any more
		dead = append(dead, info)
	}
	v.netMu.Lock()
	v.seeds = dead
	v.known[honest.host.ID()] = &knownPeer{Addrs: []string{honest.Addrs()[0][:len(honest.Addrs()[0])-len("/p2p/"+honest.host.ID().String())]}}
	v.netMu.Unlock()
	v.reconnect() // one tick: the dial budget is shared, not spent on the dead seeds first
	if v.ConnectionState(honest.host.ID()) != network.Connected {
		t.Fatal("six dead seeds starved the known peer of dials")
	}
	// The dead seeds back off instead of being redialed every tick.
	v.netMu.Lock()
	backedOff := 0
	for _, st := range v.seedState {
		if st.fails > 0 && st.nextAt.After(time.Now()) {
			backedOff++
		}
	}
	v.netMu.Unlock()
	if backedOff == 0 {
		t.Fatal("failed seeds are not backed off")
	}
}

type fakeConn struct {
	network.Conn
	dir  network.Direction
	addr ma.Multiaddr
}

func (f fakeConn) Stat() network.ConnStats {
	return network.ConnStats{Stats: network.Stats{Direction: f.dir}}
}
func (f fakeConn) RemoteMultiaddr() ma.Multiaddr { return f.addr }

func TestInboundLimitPerNetworkAndLoopbackExempt(t *testing.T) {
	m := func(s string) ma.Multiaddr { a, _ := ma.NewMultiaddr(s); return a }
	var conns []network.Conn
	for i := 0; i < maxInboundPerNet; i++ {
		conns = append(conns, fakeConn{dir: network.DirInbound, addr: m(fmt.Sprintf("/ip4/203.0.113.%d/tcp/1", 10+i))})
	}
	if inboundAllowed(m("/ip4/203.0.113.99/tcp/1"), conns, maxInboundPerNet, 48) {
		t.Fatal("a fourth inbound peer from one /24 was admitted")
	}
	if !inboundAllowed(m("/ip4/198.51.100.1/tcp/1"), conns, maxInboundPerNet, 48) {
		t.Fatal("another network refused")
	}
	if !inboundAllowed(m("/ip4/127.0.0.1/tcp/1"), append(conns, fakeConn{dir: network.DirInbound, addr: m("/ip4/127.0.0.1/tcp/2")}), maxInboundPerNet, 48) {
		t.Fatal("loopback is limited")
	}
	// Outbound connections never count against inbound budgets.
	out := []network.Conn{fakeConn{dir: network.DirOutbound, addr: m("/ip4/203.0.113.10/tcp/1")}, fakeConn{dir: network.DirOutbound, addr: m("/ip4/203.0.113.11/tcp/1")}}
	if !inboundAllowed(m("/ip4/203.0.113.12/tcp/1"), out, maxInboundPerNet, 48) {
		t.Fatal("outbound connections counted as inbound")
	}
	if netGroup(m("/ip6/2001:db8:1:2::1/tcp/1")) != netGroup(m("/ip6/2001:db8:1:ffff::9/tcp/1")) {
		t.Fatal("IPv6 /48 grouping")
	}
}

// Inbound peers do not enter the address book first come, first served (E1).
func TestAddressBookAdmission(t *testing.T) {
	g := easyGenesis()
	v, _, _, s1 := bringUpNode(t, "victim", g)
	defer s1()
	honest, _, _, s2 := bringUpNode(t, "honest", g)
	defer s2()
	in := rawHost(t)
	evilHello(in, Status{Version: types.BlockVersion, NetworkMagic: v.magic, TotalWork: bigWork(1)})
	link(t, in, v)
	waitFor(t, 5*time.Second, "status", func() bool {
		v.book.mu.Lock()
		defer v.book.mu.Unlock()
		ps := v.book.peers[in.ID()]
		return ps != nil && ps.haveStatus
	})
	dial(t, v, honest)
	waitFor(t, 5*time.Second, "the peer we dialed is remembered", func() bool {
		v.netMu.Lock()
		defer v.netMu.Unlock()
		return v.known[honest.host.ID()] != nil
	})
	v.netMu.Lock()
	_, sybil := v.known[in.ID()]
	v.netMu.Unlock()
	if sybil {
		t.Fatal("an unproven inbound peer entered the address book")
	}
	v.creditPeer(in.ID(), 3) // after it delivers blocks we accepted, it may
	v.netMu.Lock()
	_, nowKnown := v.known[in.ID()]
	v.netMu.Unlock()
	if !nowKnown {
		t.Fatal("a peer that delivered blocks was not admitted")
	}
}

// Synced is honest about what it knows (M5/S1).
func TestSyncedNeedsConfirmationNotJustAnyPeer(t *testing.T) {
	g := easyGenesis()
	g.Header.Timestamp = time.Now().Unix() - 100000 // a stale view of the world
	g.Header.Nonce = 0
	v, cv, _, stop := bringUpNode(t, "victim", g)
	defer stop()
	if v.Synced() {
		t.Fatal("synced with no peers")
	}
	low := rawHost(t)
	evilHello(low, Status{Version: types.BlockVersion, NetworkMagic: v.magic, TotalWork: big.NewInt(0)}) // below our genesis-only work of 1
	link(t, low, v)
	waitFor(t, 5*time.Second, "low-work status", func() bool {
		v.book.mu.Lock()
		defer v.book.mu.Unlock()
		ps := v.book.peers[low.ID()]
		return ps != nil && ps.haveStatus
	})
	if v.Synced() {
		t.Fatal("a stale node was satisfied by a peer with less work than its own")
	}
	same := rawHost(t)
	evilHello(same, honestStatus(cv, v.magic))
	link(t, same, v)
	waitFor(t, 5*time.Second, "equal-work status", func() bool {
		v.book.mu.Lock()
		defer v.book.mu.Unlock()
		ps := v.book.peers[same.ID()]
		return ps != nil && ps.haveStatus
	})
	if !v.Synced() {
		t.Fatal("a peer at our work level did not confirm our tip")
	}
	silent := rawHost(t) // connects, never completes the handshake
	silent.RemoveStreamHandler(ProtocolHello)
	link(t, silent, v)
	if v.Synced() {
		t.Fatal("Synced ignored a peer whose handshake is still in flight")
	}
	heavier := rawHost(t)
	evilHello(heavier, Status{Version: types.BlockVersion, NetworkMagic: v.magic, TotalWork: bigWork(250)})
	link(t, heavier, v)
	waitFor(t, 5*time.Second, "heavier status", func() bool {
		v.book.mu.Lock()
		defer v.book.mu.Unlock()
		ps := v.book.peers[heavier.ID()]
		return ps != nil && ps.haveStatus
	})
	if v.Synced() {
		t.Fatal("synced although a peer advertises more work")
	}
}

func TestClockSkewWarnsOnlyWhenPeersAgree(t *testing.T) {
	var warns atomic.Int32
	var tr skewTracker
	now := time.Now()
	warn := func(time.Duration) { warns.Add(1) }
	future := now.Unix() + 3600
	tr.note(peer.ID("a"), future, now, warn)
	tr.note(peer.ID("a"), future, now, warn)
	time.Sleep(50 * time.Millisecond)
	if warns.Load() != 0 {
		t.Fatal("warned on a single peer")
	}
	tr.note(peer.ID("b"), now.Unix()+10, now, warn) // within drift: ignored
	tr.note(peer.ID("b"), future, now, warn)
	time.Sleep(50 * time.Millisecond)
	if warns.Load() != 1 {
		t.Fatalf("warnings = %d, want 1", warns.Load())
	}
	tr.note(peer.ID("c"), future, now.Add(time.Minute), warn) // rate limited
	time.Sleep(50 * time.Millisecond)
	if warns.Load() != 1 {
		t.Fatal("warning repeated within ten minutes")
	}
}

// A peer that advertises work it cannot back must be penalized and set aside, so
// `-mine` does not wait for it forever (api 4).
func TestFakeWorkPeerDoesNotHoldTheMinerGateForever(t *testing.T) {
	g := easyGenesis()
	v, cv, _, stop := bringUpNode(t, "victim", g)
	defer stop()
	same := rawHost(t)
	evilHello(same, honestStatus(cv, v.magic))
	link(t, same, v)
	liar := rawHost(t)
	evilHello(liar, Status{Version: types.BlockVersion, NetworkMagic: v.magic, Height: 5, TipHash: types.Hash{9}, TotalWork: bigWork(250)})
	serveSync(liar, func(req syncReq) []byte {
		if req.Kind == reqLocator {
			return encodeLocatorResp(locatorResp{Found: true, Height: 0})
		}
		out, _ := encodeBlocksResp(&GetBlocksResp{}) // promises, never delivers
		return out
	})
	link(t, liar, v)
	waitFor(t, 10*time.Second, "liar penalized and set aside", func() bool { return v.book.appScore(liar.ID()) < 0 || v.book.isBanned(liar.ID()) })
	waitFor(t, 5*time.Second, "gate opens without the liar", v.Synced)
}
