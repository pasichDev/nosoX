package p2p

import (
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

const (
	banThreshold   = -100.0
	banDuration    = 10 * time.Minute
	scoreHalfLife  = 10 * time.Minute
	maxTrackedPeer = 4096
)

// Penalty sizes. Verifiably invalid data bans at once; slowness only adds up.
const (
	penaltyInvalid     = -100.0 // invalid block / wire garbage / lying about the chain
	penaltyGarbage     = -34.0  // undecodable gossip: the third one bans
	penaltyBadGossip   = -34.0  // consensus-invalid gossip block or tx
	penaltyBadTx       = -5.0   // invalid tx: honest relays race with confirmations
	penaltyUndelivered = -25.0  // timeouts, empty answers, broken streams
	penaltyWorkLie     = -60.0  // advertised more work than it could prove
	penaltyMoved       = -10.0  // batch did not continue the chain it was announced on
)

type peerState struct {
	status     Status
	haveStatus bool
	statusAt   time.Time
	refreshAt  time.Time
	fails      int
	retryAt    time.Time
	score      float64
	scoreAt    time.Time
	created    time.Time
	// delivered counts blocks this peer served that we accepted: the only thing
	// that earns priority in sync and a place in the address book.
	delivered uint64
}

// peerBook tracks what we know about each connected or recently seen peer.
type peerBook struct {
	mu    sync.Mutex
	peers map[peer.ID]*peerState
	bans  map[peer.ID]time.Time
}

func newPeerBook() *peerBook {
	return &peerBook{peers: map[peer.ID]*peerState{}, bans: map[peer.ID]time.Time{}}
}

// get requires b.mu.
func (b *peerBook) get(p peer.ID) *peerState {
	st, ok := b.peers[p]
	if !ok {
		if len(b.peers) >= maxTrackedPeer {
			b.evictLocked()
		}
		st = &peerState{scoreAt: time.Now(), created: time.Now()}
		b.peers[p] = st
	}
	return st
}

func (b *peerBook) evictLocked() {
	var oldest peer.ID
	var at time.Time
	for id, st := range b.peers {
		if at.IsZero() || st.scoreAt.Before(at) {
			oldest, at = id, st.scoreAt
		}
	}
	delete(b.peers, oldest)
}

func (st *peerState) decay(now time.Time) {
	if st.score < 0 {
		half := float64(now.Sub(st.scoreAt)) / float64(scoreHalfLife)
		for ; half >= 1; half-- {
			st.score /= 2
		}
		st.score *= 1 - half/2
	}
	st.scoreAt = now
}

func (b *peerBook) isBanned(p peer.ID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.bans[p]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(b.bans, p)
		return false
	}
	return true
}

// penalize adds pts (negative) to the peer's decaying score and reports
// whether the peer is now banned.
func (b *peerBook) penalize(p peer.ID, pts float64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	st := b.get(p)
	st.decay(now)
	st.score += pts
	if st.score > banThreshold {
		return false
	}
	if len(b.bans) >= maxTrackedPeer {
		for id, until := range b.bans {
			if now.After(until) {
				delete(b.bans, id)
			}
		}
	}
	if len(b.bans) < maxTrackedPeer {
		b.bans[p] = now.Add(banDuration)
	}
	st.score = 0
	return true
}

func (b *peerBook) appScore(p peer.ID) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.peers[p]
	if !ok {
		return 0
	}
	st.decay(time.Now())
	return st.score
}

func (b *peerBook) gc() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for id, until := range b.bans {
		if now.After(until) {
			delete(b.bans, id)
		}
	}
	for id, st := range b.peers {
		if now.Sub(st.scoreAt) > time.Hour && st.score > -1 {
			delete(b.peers, id)
		}
	}
}

// penalize scores a peer, and disconnects and bans it when the score is bad.
func (n *Libp2pNode) penalize(p peer.ID, pts float64, why string) {
	if p == "" || p == n.host.ID() {
		return
	}
	if n.book.penalize(p, pts) {
		n.logger("p2p: dropping %s for %s", p, why)
		_ = n.host.Network().ClosePeer(p)
	}
}

// Inbound admission. Eight idle inbound connections from one address used to be
// enough to fill every peer slot (the reconnect logic counted them toward its
// target), so inbound connections are limited per network and in total, and the
// node tracks and fills its OUTBOUND slots separately (see reconnect).
const (
	// maxInboundPerNet is how many inbound connections one /24 (IPv4) or /48
	// (IPv6) may hold. Loopback and private addresses are exempt, so local test
	// networks and LANs behave as before.
	maxInboundPerNet = 3
	// maxInboundTotal leaves the rest of the connection budget to outbound dials.
	maxInboundTotal = 48
)

// netGroup returns the abuse-bucket of an address: its /24 or /48 prefix, or ""
// for loopback, private and unparsable addresses (which are never limited).
func netGroup(a ma.Multiaddr) string {
	if a == nil {
		return ""
	}
	var ip net.IP
	ma.ForEach(a, func(c ma.Component) bool {
		switch c.Protocol().Code {
		case ma.P_IP4, ma.P_IP6:
			ip = net.ParseIP(c.Value())
			return false
		}
		return true
	})
	if ip == nil || !isGlobalIP(ip) {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(48, 128)).String() + "/48"
}

// gater refuses connections from banned peers and limits inbound connections.
type gater struct {
	book       *peerBook
	net        network.Network
	maxInbound int
}

var _ connmgr.ConnectionGater = (*gater)(nil)

// inboundAllowed decides whether one more inbound connection from remote is
// acceptable given the connections we hold.
func inboundAllowed(remote ma.Multiaddr, conns []network.Conn, maxPerNet, maxTotal int) bool {
	group := netGroup(remote)
	inbound, same := 0, 0
	for _, c := range conns {
		if c.Stat().Direction != network.DirInbound {
			continue
		}
		inbound++
		if group != "" && netGroup(c.RemoteMultiaddr()) == group {
			same++
		}
	}
	if group != "" && same >= maxPerNet {
		return false
	}
	return maxTotal <= 0 || inbound < maxTotal || group == ""
}

func (g *gater) InterceptPeerDial(p peer.ID) bool                 { return !g.book.isBanned(p) }
func (g *gater) InterceptAddrDial(p peer.ID, _ ma.Multiaddr) bool { return !g.book.isBanned(p) }
func (g *gater) InterceptAccept(m network.ConnMultiaddrs) bool {
	if g.net == nil {
		return true
	}
	return inboundAllowed(m.RemoteMultiaddr(), g.net.Conns(), maxInboundPerNet, g.maxInbound)
}
func (g *gater) InterceptSecured(_ network.Direction, p peer.ID, _ network.ConnMultiaddrs) bool {
	return !g.book.isBanned(p)
}
func (g *gater) InterceptUpgraded(network.Conn) (bool, control.DisconnectReason) { return true, 0 }
