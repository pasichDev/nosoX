// libp2p_host.go — production P2P layer.
//
// Replaces the previous JSON-over-TCP gossip with go-libp2p +
// gossipsub. Benefits:
//
//   - NAT traversal (AutoRelay, hole punching).
//   - mDNS auto-discovery on the local network.
//   - Encrypted transports (noise) and stream multiplexing (yamux).
//   - Topic-based gossip via gossipsub (used by ETH, Filecoin, etc).
//
// Two versioned JSON topics:
//
//	"noso-v2/blocks"  — new full blocks (JSON-encoded *types.Block)
//	"noso-v2/txs"     — new transactions (JSON-encoded *types.Transaction)
//
// Inbound payloads are validated by the local Chain / Mempool before
// being re-published; libp2p-gossipsub handles dedup via message IDs.
package p2p

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/pasichDev/noso-go/v2/chain"
	"github.com/pasichDev/noso-go/v2/mempool"
	"github.com/pasichDev/noso-go/v2/types"
)

// Topic names. Namespaced by network magic so testnet and mainnet
// peers don't accidentally cross-talk.
func topicBlocks(magic uint32) string { return fmt.Sprintf("noso-v2/%08x/blocks-v2", magic) }
func topicTxs(magic uint32) string    { return fmt.Sprintf("noso-v2/%08x/txs-v2", magic) }

// Libp2pNode is the production replacement for `Node`.
type Libp2pNode struct {
	magic   uint32
	chain   *chain.Chain
	mempool *mempool.Pool
	logger  func(string, ...any)

	host      host.Host
	ps        *pubsub.PubSub
	tBlk      *pubsub.Topic
	tTx       *pubsub.Topic
	sBlk      *pubsub.Subscription
	sTx       *pubsub.Subscription
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	taskMu    sync.Mutex
	stopping  bool
	fetcher   reorgFetcher
	syncSlots chan struct{}
	limiter   *rateLimiter
}

// NewLibp2p creates a libp2p host listening on the given multi-address
// strings (e.g. []string{"/ip4/0.0.0.0/tcp/7781"}). Pass an empty slice
// to use the libp2p defaults.
func NewLibp2p(listenAddrs []string, magic uint32, c *chain.Chain, p *mempool.Pool) (*Libp2pNode, error) {
	opts := []libp2p.Option{
		libp2p.DefaultTransports,
		libp2p.DefaultSecurity,
		libp2p.DefaultMuxers,
		libp2p.NATPortMap(),
		libp2p.EnableHolePunching(),
		libp2p.EnableRelay(),
	}
	if len(listenAddrs) > 0 {
		opts = append(opts, libp2p.ListenAddrStrings(listenAddrs...))
	} else {
		// Listen on both TCP and QUIC-v1 (UDP). QUIC — the transport
		// Google (HTTP/3) and other latency-sensitive apps use — recovers
		// from packet loss per-stream and survives NAT rebinds, so it stays
		// usable on poor/mobile networks where TCP stalls. DefaultTransports
		// already registers the QUIC dialer; we just need to listen on it.
		opts = append(opts, libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/7781",
			"/ip4/0.0.0.0/udp/7781/quic-v1",
		))
	}
	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	ps, err := pubsub.NewGossipSub(ctx, h, pubsub.WithMaxMessageSize(maxWireBytes), pubsub.WithValidateQueueSize(8), pubsub.WithValidateThrottle(2), pubsub.WithValidateWorkers(2), pubsub.WithPeerOutboundQueueSize(8))
	if err != nil {
		cancel()
		_ = h.Close()
		return nil, err
	}
	return &Libp2pNode{
		magic:     magic,
		chain:     c,
		mempool:   p,
		host:      h,
		ps:        ps,
		limiter:   newRateLimiter(),
		syncSlots: make(chan struct{}, 8),
		ctx:       ctx,
		cancel:    cancel,
		logger:    func(string, ...any) {},
	}, nil
}

// SetLogger overrides the default no-op logger.
func (n *Libp2pNode) SetLogger(fn func(string, ...any)) { n.logger = fn }

// Start joins the topics and begins listening for inbound messages.
func (n *Libp2pNode) Start() error {
	if err := n.ps.RegisterTopicValidator(topicTxs(n.magic), func(_ context.Context, _ peer.ID, msg *pubsub.Message) bool {
		tx, err := decodeTxMsg(msg.Data)
		if err != nil {
			return false
		}
		_, err = n.mempool.Add(tx)
		if errors.Is(err, mempool.ErrDuplicate) {
			return n.mempool.Validate(tx) == nil
		}
		return err == nil
	}, pubsub.WithValidatorConcurrency(2)); err != nil {
		return err
	}
	if err := n.ps.RegisterTopicValidator(topicBlocks(n.magic), func(_ context.Context, pid peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		b, err := decodeBlockMsg(msg.Data)
		if err != nil {
			return pubsub.ValidationReject
		}
		// An already accepted header binds every body field through consensus roots.
		// This also allows producers to publish blocks after locally applying them.
		if stored, ok := n.chain.HeaderByHeight(b.Header.Height); ok && types.HeaderID(&stored) == types.HeaderID(&b.Header) {
			o, k := types.BlockRoots(b)
			if o == b.Header.OutputRoot && k == b.Header.KernelRoot {
				return pubsub.ValidationAccept
			}
			return pubsub.ValidationReject
		}
		if err = n.chain.ValidateBlock(b); err != nil {
			if errors.Is(err, chain.ErrStale) {
				n.tryReorgFetch(pid, b)
				return pubsub.ValidationIgnore
			}
			return pubsub.ValidationReject
		}
		return pubsub.ValidationAccept
	}, pubsub.WithValidatorConcurrency(2)); err != nil {
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

	n.wg.Add(2)
	go n.consumeBlocks()
	go n.consumeTxs()
	return nil
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

// ConnectSeed dials a /ip4/host/tcp/port/p2p/peerid multi-address.
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
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return n.host.Connect(connectCtx, *info)
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

// consumeBlocks pulls block messages from the subscription and applies
// them to the local chain.
func (n *Libp2pNode) consumeBlocks() {
	defer n.wg.Done()
	for {
		msg, err := n.sBlk.Next(n.ctx)
		if err != nil {
			return
		}
		// Skip our own messages.
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
				n.tryReorgFetch(msg.ReceivedFrom, b)
				continue
			}
			n.logger("p2p: reject block: %v", err)
		}
	}
}

// consumeTxs similarly drains the txs topic.
func (n *Libp2pNode) consumeTxs() {
	defer n.wg.Done()
	for {
		msg, err := n.sTx.Next(n.ctx)
		if err != nil {
			return
		}
		if msg.ReceivedFrom == n.host.ID() {
			continue
		}
		tx, err := decodeTxMsg(msg.Data)
		if err != nil {
			n.logger("p2p: tx decode: %v", err)
			continue
		}
		_ = tx // admission occurred in the pre-forward topic validator
	}
}

// PeerCount returns the number of currently connected libp2p peers.
func (n *Libp2pNode) PeerCount() int {
	return len(n.host.Network().Peers())
}

// EnsurePeerScore is a future hook for slashing misbehaving peers; for
// now we just check the network state to keep the symbol exported.
func (n *Libp2pNode) ConnectionState(p peer.ID) network.Connectedness {
	return n.host.Network().Connectedness(p)
}

// ---- encoding helpers --------------------------------------------------

const maxWireBytes = 16 << 20

// JSON decoding allocates only as bytes are consumed; unlike gob it cannot
// request huge slice allocations from attacker supplied element counts.
func decodeWire(raw []byte, dst any, max int) error {
	if len(raw) == 0 || len(raw) > max {
		return errors.New("p2p: payload size")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errors.New("p2p: trailing payload")
	}
	return nil
}
func encodeBlockMsg(b *types.Block) ([]byte, error) { return json.Marshal(b) }
func decodeBlockMsg(raw []byte) (*types.Block, error) {
	var b types.Block
	if err := decodeWire(raw, &b, maxWireBytes); err != nil {
		return nil, err
	}
	if err := checkBody(b.Inputs, b.Outputs, b.Kernels); err != nil {
		return nil, err
	}
	return &b, nil
}
func encodeTxMsg(tx *types.Transaction) ([]byte, error) { return json.Marshal(tx) }
func decodeTxMsg(raw []byte) (*types.Transaction, error) {
	var tx types.Transaction
	if err := decodeWire(raw, &tx, maxWireBytes); err != nil {
		return nil, err
	}
	if err := checkBody(tx.Inputs, tx.Outputs, tx.Kernels); err != nil {
		return nil, err
	}
	return &tx, nil
}
func checkBody(in []types.Input, out []types.Output, k []types.Kernel) error {
	if len(in) > 10000 || len(out) > 10000 || len(k) > 10000 {
		return errors.New("p2p: body count limit")
	}
	for _, i := range in {
		if len(i.LegacySig) > 256 || len(i.LegacyAddr) > 256 {
			return errors.New("p2p: input size limit")
		}
	}
	for _, o := range out {
		if len(o.RangeProof) > 65536 || len(o.LegacyAddress) > 256 {
			return errors.New("p2p: output size limit")
		}
	}
	for _, v := range k {
		if len(v.ExcessSig) > 65 {
			return errors.New("p2p: signature size limit")
		}
	}
	return nil
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
