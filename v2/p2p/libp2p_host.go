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
// Two topics:
//
//	"noso-v2/blocks"  — new full blocks (gob-encoded *types.Block)
//	"noso-v2/txs"     — new transactions (gob-encoded *types.Transaction)
//
// Inbound payloads are validated by the local Chain / Mempool before
// being re-published; libp2p-gossipsub handles dedup via message IDs.
package p2p

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/noso-project/noso-go/v2/chain"
	"github.com/noso-project/noso-go/v2/mempool"
	"github.com/noso-project/noso-go/v2/types"
)

// Topic names. Namespaced by network magic so testnet and mainnet
// peers don't accidentally cross-talk.
func topicBlocks(magic uint32) string { return fmt.Sprintf("noso-v2/%08x/blocks", magic) }
func topicTxs(magic uint32) string    { return fmt.Sprintf("noso-v2/%08x/txs", magic) }

// Libp2pNode is the production replacement for `Node`.
type Libp2pNode struct {
	magic   uint32
	chain   *chain.Chain
	mempool *mempool.Pool
	logger  func(string, ...any)

	host    host.Host
	ps      *pubsub.PubSub
	tBlk    *pubsub.Topic
	tTx     *pubsub.Topic
	sBlk    *pubsub.Subscription
	sTx     *pubsub.Subscription
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	fetcher reorgFetcher
	limiter *rateLimiter
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
		opts = append(opts, libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/7781"))
	}
	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		cancel()
		_ = h.Close()
		return nil, err
	}
	return &Libp2pNode{
		magic:   magic,
		chain:   c,
		mempool: p,
		host:    h,
		ps:      ps,
		limiter: newRateLimiter(),
		ctx:     ctx,
		cancel:  cancel,
		logger:  func(string, ...any) {},
	}, nil
}

// SetLogger overrides the default no-op logger.
func (n *Libp2pNode) SetLogger(fn func(string, ...any)) { n.logger = fn }

// Start joins the topics and begins listening for inbound messages.
func (n *Libp2pNode) Start() error {
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
		if _, err := n.mempool.Add(tx); err != nil {
			n.logger("p2p: tx rejected: %v", err)
		}
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

func encodeBlockMsg(b *types.Block) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeBlockMsg(raw []byte) (*types.Block, error) {
	var b types.Block
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

func encodeTxMsg(tx *types.Transaction) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(tx); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeTxMsg(raw []byte) (*types.Transaction, error) {
	var tx types.Transaction
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&tx); err != nil {
		return nil, err
	}
	return &tx, nil
}
