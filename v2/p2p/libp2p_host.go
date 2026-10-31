// libp2p_host.go — production P2P layer.
//
// go-libp2p + gossipsub:
//
//   - NAT help: opt-in port mapping (UPnP / NAT-PMP), hole punching and the
//     circuit-relay client. There is no AutoRelay: `-relay` addresses are only
//     added to the peerstore and dialed once, no relay reservation is made.
//   - No local-network (mDNS) discovery and no DHT. Peers come from the seed
//     lists, `-seed`/`-relay`, and peers we met before (see bootstrap.go).
//   - Encrypted transports (noise) and stream multiplexing (yamux).
//   - Topic-based gossip via gossipsub with peer scoring, peer exchange off and
//     a subscription allowlist.
//
// Two binary topics, namespaced by network magic (%08x):
//
//	"NosoX/%08x/blocks/v6" — new full blocks (wire.go)
//	"NosoX/%08x/txs/v6"    — new transactions (wire.go)
//
// The gossip message ID is the SHA-256 of topic and payload, so a replay under a
// new sequence number is a duplicate and is never validated again. Block and
// transaction validators have separate concurrency and per-peer budgets, so a
// transaction flood cannot starve block validation.
package p2p

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/pasichDev/noso-go/v2/chain"
	"github.com/pasichDev/noso-go/v2/mempool"
	"github.com/pasichDev/noso-go/v2/types"
)

// Topic names. Namespaced by network magic so testnet and mainnet
// peers don't accidentally cross-talk.
func topicBlocks(magic uint32) string { return fmt.Sprintf("NosoX/%08x/blocks/v6", magic) }
func topicTxs(magic uint32) string    { return fmt.Sprintf("NosoX/%08x/txs/v6", magic) }

// Options configures a node.
type Options struct {
	// ListenAddrs are multiaddr strings; empty means TCP and QUIC on :7781.
	ListenAddrs []string
	Magic       uint32
	// DataDir holds the persistent node identity (p2p_identity.key, 0600) and the
	// address book (peers.json). Empty means an ephemeral identity and no book.
	DataDir string
	// NATPortMap asks the router for a port mapping via UPnP / NAT-PMP.
	// Off by default: listening on 0.0.0.0 must not open a router port unasked.
	NATPortMap bool
	// MaintenanceInterval is the reconnect period (default 30 s).
	MaintenanceInterval time.Duration
	// TargetPeers is the connection count below which seeds and known peers are
	// redialed (default 8).
	TargetPeers int
}

// Libp2pNode is the production replacement for `Node`.
type Libp2pNode struct {
	magic   uint32
	chain   *chain.Chain
	mempool *mempool.Pool
	logger  func(string, ...any)
	opts    Options

	host     host.Host
	ps       *pubsub.PubSub
	tBlk     *pubsub.Topic
	tTx      *pubsub.Topic
	sBlk     *pubsub.Subscription
	sTx      *pubsub.Subscription
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	taskMu   sync.Mutex
	stopping bool

	book     *peerBook
	sync     *syncServer
	hello    *rateLimiter
	blkLimit *rateLimiter
	txLimit  *rateLimiter
	syncKick chan struct{}

	badMu   sync.Mutex
	badTips map[badKey]time.Time
	skew    skewTracker

	netMu sync.Mutex
	seeds []peer.AddrInfo
	known map[peer.ID]*knownPeer
	// seedState backs off configured seeds that fail to answer.
	seedState map[peer.ID]*seedBackoff
	dirty     bool
}

// NewLibp2p creates a libp2p host with an ephemeral identity listening on the
// given multi-address strings (e.g. []string{"/ip4/0.0.0.0/tcp/7781"}). Pass an
// empty slice to use the libp2p defaults. Daemons should use
// NewLibp2pWithOptions so the identity survives restarts.
func NewLibp2p(listenAddrs []string, magic uint32, c *chain.Chain, p *mempool.Pool) (*Libp2pNode, error) {
	return NewLibp2pWithOptions(Options{ListenAddrs: listenAddrs, Magic: magic}, c, p)
}

// NewLibp2pWithOptions creates a node from opts.
func NewLibp2pWithOptions(opts Options, c *chain.Chain, p *mempool.Pool) (*Libp2pNode, error) {
	if opts.MaintenanceInterval <= 0 {
		opts.MaintenanceInterval = 30 * time.Second
	}
	if opts.TargetPeers <= 0 {
		opts.TargetPeers = 8
	}
	book := newPeerBook()
	g := &gater{book: book}
	cm, err := connmgr.NewConnManager(32, 96, connmgr.WithGracePeriod(time.Minute))
	if err != nil {
		return nil, err
	}
	hopts := []libp2p.Option{
		libp2p.DefaultTransports,
		libp2p.DefaultSecurity,
		libp2p.DefaultMuxers,
		libp2p.EnableHolePunching(),
		libp2p.EnableRelay(),
		libp2p.ConnectionManager(cm),
		libp2p.ConnectionGater(g),
	}
	if opts.NATPortMap {
		hopts = append(hopts, libp2p.NATPortMap())
	}
	if opts.DataDir != "" {
		key, err := LoadOrCreateIdentity(opts.DataDir)
		if err != nil {
			return nil, err
		}
		hopts = append(hopts, libp2p.Identity(key))
	}
	if len(opts.ListenAddrs) > 0 {
		hopts = append(hopts, libp2p.ListenAddrStrings(opts.ListenAddrs...))
	} else {
		// Listen on both TCP and QUIC-v1 (UDP). QUIC recovers from packet loss
		// per stream and survives NAT rebinds.
		hopts = append(hopts, libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/7781",
			"/ip4/0.0.0.0/udp/7781/quic-v1",
		))
	}
	h, err := libp2p.New(hopts...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	var self atomic.Pointer[Libp2pNode]
	inspect := func(from peer.ID, rpc *pubsub.RPC) error {
		if n := self.Load(); n != nil {
			n.inspectRPC(from, rpc)
		}
		return nil
	}
	ps, err := pubsub.NewGossipSub(ctx, h, gossipOptions(opts.Magic, book, inspect)...)
	if err != nil {
		cancel()
		_ = h.Close()
		return nil, err
	}
	n := &Libp2pNode{
		magic:     opts.Magic,
		chain:     c,
		mempool:   p,
		opts:      opts,
		host:      h,
		ps:        ps,
		book:      book,
		sync:      newSyncServer(),
		hello:     newRateLimiterRate(1, 6),
		blkLimit:  newRateLimiterRate(1, 8),
		txLimit:   newRateLimiterRate(20, 60),
		syncKick:  make(chan struct{}, 1),
		badTips:   map[badKey]time.Time{},
		known:     map[peer.ID]*knownPeer{},
		seedState: map[peer.ID]*seedBackoff{},
		ctx:       ctx,
		cancel:    cancel,
		logger:    func(string, ...any) {},
	}
	g.net = h.Network()
	g.maxInbound = maxInboundTotal
	n.loadKnown()
	self.Store(n)
	return n, nil
}

// contentMsgID makes the gossip message ID a hash of topic and payload.
func contentMsgID(m *pb.Message) string {
	h := sha256.New()
	h.Write([]byte(m.GetTopic()))
	h.Write([]byte{0})
	h.Write(m.Data)
	return string(h.Sum(nil))
}

func gossipOptions(magic uint32, book *peerBook, inspect func(peer.ID, *pubsub.RPC) error) []pubsub.Option {
	tb, tt := topicBlocks(magic), topicTxs(magic)
	topicScore := func() *pubsub.TopicScoreParams {
		return &pubsub.TopicScoreParams{
			SkipAtomicValidation:           true,
			TopicWeight:                    1,
			TimeInMeshQuantum:              time.Second, // weight 0: only avoids a zero divisor
			FirstMessageDeliveriesWeight:   1,
			FirstMessageDeliveriesDecay:    0.9,
			FirstMessageDeliveriesCap:      10,
			InvalidMessageDeliveriesWeight: -20,
			InvalidMessageDeliveriesDecay:  0.9,
		}
	}
	_, lo4, _ := net.ParseCIDR("127.0.0.0/8")
	_, lo6, _ := net.ParseCIDR("::1/128")
	params := &pubsub.PeerScoreParams{
		SkipAtomicValidation: true,
		Topics:               map[string]*pubsub.TopicScoreParams{tb: topicScore(), tt: topicScore()},
		TopicScoreCap:        50,
		AppSpecificScore:     book.appScore,
		AppSpecificWeight:    1,
		// Many nodes behind one address are a Sybil signal; loopback is exempt
		// so local test networks work.
		IPColocationFactorWeight:    -10,
		IPColocationFactorThreshold: 4,
		IPColocationFactorWhitelist: []*net.IPNet{lo4, lo6},
		BehaviourPenaltyWeight:      -5,
		BehaviourPenaltyThreshold:   3,
		BehaviourPenaltyDecay:       0.9,
		DecayInterval:               10 * time.Second,
		DecayToZero:                 0.01,
		RetainScore:                 10 * time.Minute,
	}
	thresholds := &pubsub.PeerScoreThresholds{
		GossipThreshold:   -100,
		PublishThreshold:  -200,
		GraylistThreshold: -400,
		// Peer exchange is off; the threshold is unreachable as well, so even a
		// forged PRUNE with peer records cannot steer our dials.
		AcceptPXThreshold:           1e9,
		OpportunisticGraftThreshold: 5,
	}
	return []pubsub.Option{
		pubsub.WithMaxMessageSize(maxGossipRPCBytes),
		pubsub.WithMessageIdFn(contentMsgID),
		pubsub.WithSeenMessagesTTL(30 * time.Minute),
		// Queue and global throttle are generous; the per-topic validator
		// concurrency below is the real budget, so tx floods only exhaust the tx
		// validator and never the block one.
		pubsub.WithValidateQueueSize(256),
		pubsub.WithValidateThrottle(64),
		pubsub.WithValidateWorkers(4),
		pubsub.WithPeerOutboundQueueSize(16),
		pubsub.WithPeerExchange(false),
		pubsub.WithPeerScore(params, thresholds),
		// Per-peer message budgets are enforced here, BEFORE pubsub marks a message
		// as seen: a validator that returns Ignore for an over-budget copy would
		// burn the content-hash ID, and every honest copy arriving afterwards would
		// be dropped as a duplicate (go-libp2p-pubsub validation.go: markSeen runs
		// before the user validators).
		pubsub.WithAppSpecificRpcInspector(inspect),
		pubsub.WithSubscriptionFilter(pubsub.WrapLimitSubscriptionFilter(pubsub.NewAllowlistSubscriptionFilter(tb, tt), 8)),
	}
}

// SetLogger overrides the default no-op logger.
func (n *Libp2pNode) SetLogger(fn func(string, ...any)) { n.logger = fn }

// ID returns the node's libp2p peer ID.
func (n *Libp2pNode) ID() peer.ID { return n.host.ID() }

// Start joins the topics and begins listening for inbound messages.
func (n *Libp2pNode) Start() error {
	if err := n.ps.RegisterTopicValidator(topicTxs(n.magic), func(_ context.Context, pid peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		return n.validateTxMsg(pid, msg.Data)
	}, pubsub.WithValidatorConcurrency(2)); err != nil {
		return err
	}
	if err := n.ps.RegisterTopicValidator(topicBlocks(n.magic), func(_ context.Context, pid peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		return n.validateBlockMsg(pid, msg.Data)
	}, pubsub.WithValidatorConcurrency(4)); err != nil {
		return err
	}
	tBlk, err := n.ps.Join(topicBlocks(n.magic))
	if err != nil {
		return err
	}
	tTx, err := n.ps.Join(topicTxs(n.magic))
	if err != nil {
		return err
	}
	n.tBlk, n.tTx = tBlk, tTx

	sBlk, err := tBlk.Subscribe()
	if err != nil {
		return err
	}
	sTx, err := tTx.Subscribe()
	if err != nil {
		return err
	}
	n.sBlk, n.sTx = sBlk, sTx
	n.installSyncHandler()
	n.installHelloHandler()

	n.wg.Add(4)
	go n.consumeBlocks()
	go n.consumeTxs()
	go n.syncLoop()
	go n.maintenanceLoop()
	return nil
}

// inspectRPC enforces the per-peer block and transaction budgets on an incoming
// RPC before pubsub sees its messages. Over-budget messages are trimmed from the
// RPC, so a throttled copy never burns the message's content ID. It runs on
// pubsub's single processing goroutine: no decoding, no chain access.
func (n *Libp2pNode) inspectRPC(from peer.ID, rpc *pubsub.RPC) {
	if from == n.host.ID() || len(rpc.Publish) == 0 {
		return
	}
	tb, tt := topicBlocks(n.magic), topicTxs(n.magic)
	kept := rpc.Publish[:0]
	dropped := false
	for _, m := range rpc.Publish {
		switch m.GetTopic() {
		case tb:
			if !n.blkLimit.allow(from) {
				dropped = true
				continue
			}
		case tt:
			if !n.txLimit.allow(from) {
				continue
			}
		}
		kept = append(kept, m)
	}
	rpc.Publish = kept
	if dropped {
		// The block we refused may be one we need: ask the sender what it has, so
		// sync fetches it directly instead of waiting for a gossip copy.
		n.noteFork(from)
	}
}

// validateBlockMsg is the pre-forward validator for the blocks topic.
func (n *Libp2pNode) validateBlockMsg(pid peer.ID, data []byte) pubsub.ValidationResult {
	b, err := decodeBlockMsg(data)
	if err != nil {
		n.penalize(pid, penaltyGarbage, "undecodable block")
		return pubsub.ValidationReject
	}
	if pid == n.host.ID() {
		return pubsub.ValidationAccept // we applied it before publishing
	}
	// A block we already hold is a replay: never forward it again.
	if stored, ok := n.chain.HeaderByHeight(b.Header.Height); ok {
		if types.HeaderID(&stored) != types.HeaderID(&b.Header) {
			n.noteFork(pid) // a competing block at a known height: ask for its work
		}
		return pubsub.ValidationIgnore
	}
	if err = n.chain.ValidateBlock(b); err != nil {
		switch {
		case errors.Is(err, chain.ErrStale):
			n.noteFork(pid)
			return pubsub.ValidationIgnore
		case errors.Is(err, chain.ErrFutureTimestamp):
			// Our clock or theirs: never a reason to score the relay.
			n.noteFutureBlock(pid, b.Header.Timestamp)
			return pubsub.ValidationIgnore
		case chain.IsPeerFault(err):
			n.penalize(pid, penaltyBadGossip, "invalid block")
			return pubsub.ValidationReject
		}
		return pubsub.ValidationIgnore // resource limits, disk errors: ours, not theirs
	}
	return pubsub.ValidationAccept
}

// validateTxMsg is the pre-forward validator for the txs topic. A transaction
// we already pool is ignored without revalidation.
func (n *Libp2pNode) validateTxMsg(pid peer.ID, data []byte) pubsub.ValidationResult {
	tx, err := decodeTxMsg(data)
	if err != nil {
		n.penalize(pid, penaltyGarbage, "undecodable transaction")
		return pubsub.ValidationReject
	}
	local := pid == n.host.ID()
	_, err = n.mempool.Add(tx)
	res, penalize := classifyTxAdmission(err, local)
	if penalize {
		n.penalize(pid, penaltyBadTx, "invalid transaction")
	}
	return res
}

// classifyTxAdmission maps the mempool's answer for a gossiped transaction to a
// validation result and whether the sender is penalized. Only a transaction that
// is invalid whatever the chain state (bad shape, signature, range proof,
// balance) is rejected and penalized. Everything that depends on what THIS node
// currently holds is ignored without a penalty: an input we do not know yet, an
// immature coinbase, a lock height, an output or kernel we already have, relay
// policy (fee floor, full pool, conflict), and local transient conditions. A
// node that is behind must not punish the honest relays that are ahead of it.
func classifyTxAdmission(err error, local bool) (res pubsub.ValidationResult, penalize bool) {
	switch {
	case err == nil:
		return pubsub.ValidationAccept, false
	case errors.Is(err, mempool.ErrDuplicate):
		if local {
			return pubsub.ValidationAccept, false // let our own re-broadcast through
		}
		return pubsub.ValidationIgnore, false
	case mempool.IsPolicy(err), errors.Is(err, mempool.ErrUnavailable), errors.Is(err, chain.ErrResourceBudget),
		errors.Is(err, chain.ErrTxState), errors.Is(err, chain.ErrDoubleSpend), errors.Is(err, chain.ErrStorage):
		return pubsub.ValidationIgnore, false
	}
	return pubsub.ValidationReject, true
}

// Shutdown stops the goroutines and closes the libp2p host.
func (n *Libp2pNode) Shutdown() error {
	n.taskMu.Lock()
	n.stopping = true
	n.taskMu.Unlock()
	n.cancel()
	if n.sBlk != nil {
		n.sBlk.Cancel()
	}
	if n.sTx != nil {
		n.sTx.Cancel()
	}
	if n.tBlk != nil {
		_ = n.tBlk.Close()
	}
	if n.tTx != nil {
		_ = n.tTx.Close()
	}
	n.wg.Wait()
	n.saveKnown()
	return n.host.Close()
}

// Addrs returns the multi-addresses this host listens on, formatted
// with the peer ID suffix (i.e. dial strings).
func (n *Libp2pNode) Addrs() []string {
	id := n.host.ID()
	var out []string
	for _, a := range n.host.Addrs() {
		out = append(out, fmt.Sprintf("%s/p2p/%s", a, id))
	}
	return out
}

// ConnectSeed dials a /ip4/host/tcp/port/p2p/peerid multi-address and protects
// the connection from being trimmed.
func (n *Libp2pNode) ConnectSeed(ctx context.Context, addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	m, err := ma.NewMultiaddr(addr)
	if err != nil {
		return fmt.Errorf("p2p: parse %s: %w", addr, err)
	}
	info, err := peer.AddrInfoFromP2pAddr(m)
	if err != nil {
		return fmt.Errorf("p2p: addrInfo %s: %w", addr, err)
	}
	return n.dial(ctx, *info, true)
}

func (n *Libp2pNode) dial(ctx context.Context, info peer.AddrInfo, protect bool) error {
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := n.host.Connect(connectCtx, info); err != nil {
		return err
	}
	if protect {
		n.host.ConnManager().Protect(info.ID, "seed")
	}
	return nil
}

// BroadcastBlock publishes b to the blocks topic.
func (n *Libp2pNode) BroadcastBlock(b *types.Block) error {
	if n.tBlk == nil {
		return nil
	}
	raw, err := encodeBlockMsg(b)
	if err != nil {
		return err
	}
	return n.tBlk.Publish(n.ctx, raw)
}

// BroadcastTx publishes tx to the txs topic.
func (n *Libp2pNode) BroadcastTx(tx *types.Transaction) error {
	if n.tTx == nil {
		return nil
	}
	raw, err := encodeTxMsg(tx)
	if err != nil {
		return err
	}
	return n.tTx.Publish(n.ctx, raw)
}

// consumeBlocks pulls accepted block messages from the subscription and applies
// them to the local chain.
func (n *Libp2pNode) consumeBlocks() {
	defer n.wg.Done()
	for {
		msg, err := n.sBlk.Next(n.ctx)
		if err != nil {
			return
		}
		if msg.ReceivedFrom == n.host.ID() {
			continue
		}
		b, err := decodeBlockMsg(msg.Data)
		if err != nil {
			n.logger("p2p: block decode from %s: %v", msg.ReceivedFrom, err)
			continue
		}
		if err := n.chain.AddBlock(b); err != nil {
			if errors.Is(err, chain.ErrStale) {
				n.noteFork(msg.ReceivedFrom)
				continue
			}
			n.logger("p2p: reject block: %v", err)
		}
	}
}

// consumeTxs drains the txs topic; admission happened in the topic validator.
func (n *Libp2pNode) consumeTxs() {
	defer n.wg.Done()
	for {
		if _, err := n.sTx.Next(n.ctx); err != nil {
			return
		}
	}
}

// PeerCount returns the number of currently connected libp2p peers.
func (n *Libp2pNode) PeerCount() int {
	return len(n.host.Network().Peers())
}

// ConnectionState reports the connectedness of p.
func (n *Libp2pNode) ConnectionState(p peer.ID) network.Connectedness {
	return n.host.Network().Connectedness(p)
}

// launch serializes task registration with Shutdown so accepted background work
// is joined before callers close the chain store.
func (n *Libp2pNode) launch(fn func()) bool {
	n.taskMu.Lock()
	defer n.taskMu.Unlock()
	if n.stopping {
		return false
	}
	n.wg.Add(1)
	go func() { defer n.wg.Done(); fn() }()
	return true
}
