package p2p

import (
	"context"
	"encoding/json"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// MainnetBootstrap is the canonical seed peer list for the public
// Noso v2 mainnet. Operators of long-lived public nodes can submit
// their own multi-addrs upstream; until that happens this is an empty
// placeholder that operators override via the -seed flag.
var MainnetBootstrap = []string{
	// Reserved for the official seed nodes. The launch operator should
	// publish their /dns4/ multi-addrs here in a tagged release commit.
}

// TestnetBootstrap is the seed list for testnet. Same structure.
var TestnetBootstrap = []string{
	// Reserved.
}

// MainnetRelays are publicly-reachable libp2p relay nodes. They are only
// dialed (see AddRelays); the node does not run AutoRelay or reserve slots.
var MainnetRelays = []string{
	// Reserved. Until then nodes behind symmetric NAT must publish via
	// libp2p hole-punching or be reachable directly.
}

// BootstrapConfig bundles the seed and relay lists into one struct so
// the daemon can override either independently.
type BootstrapConfig struct {
	Network string   // "mainnet" | "testnet" | custom name
	Seeds   []string // multi-addresses
	Relays  []string // multi-addresses
	// AllowPrivateSeeds keeps loopback, private and link-local addresses that
	// come from DNS seeds. Explicit -seed addresses are never filtered.
	AllowPrivateSeeds bool
}

// DefaultBootstrap selects the canonical bootstrap config for a network.
func DefaultBootstrap(network string) BootstrapConfig {
	switch network {
	case "mainnet":
		return BootstrapConfig{Network: "mainnet", Seeds: MainnetBootstrap, Relays: MainnetRelays}
	case "testnet":
		return BootstrapConfig{Network: "testnet", Seeds: TestnetBootstrap}
	default:
		return BootstrapConfig{Network: network}
	}
}

// ParseMultiaddrs validates a comma- or whitespace-separated list of
// libp2p multi-address strings, returning only the parsable entries.
// Bad entries are skipped silently — log them at the call site if you
// want notifications.
func ParseMultiaddrs(s string) []peer.AddrInfo {
	if s == "" {
		return nil
	}
	var out []peer.AddrInfo
	for _, raw := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		m, err := ma.NewMultiaddr(raw)
		if err != nil {
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(m)
		if err != nil {
			continue
		}
		out = append(out, *info)
	}
	return out
}

// IsPublicMultiaddr reports whether addr points at a globally routable host.
// Loopback, private, link-local, CGNAT, unspecified and multicast IPs are
// rejected, as are "localhost" and *.local / *.internal names. Other DNS names
// pass: they cannot be judged before they are resolved.
func IsPublicMultiaddr(addr string) bool {
	m, err := ma.NewMultiaddr(addr)
	if err != nil {
		return false
	}
	for _, c := range m {
		switch c.Protocol().Code {
		case ma.P_IP4, ma.P_IP6:
			ip := net.ParseIP(c.Value())
			return ip != nil && isGlobalIP(ip)
		case ma.P_DNS, ma.P_DNS4, ma.P_DNS6, ma.P_DNSADDR:
			name := strings.ToLower(strings.TrimSuffix(c.Value(), "."))
			return name != "localhost" && !strings.HasSuffix(name, ".localhost") &&
				!strings.HasSuffix(name, ".local") && !strings.HasSuffix(name, ".internal") &&
				!strings.HasSuffix(name, ".lan")
		}
	}
	return false
}

var cgnat = func() *net.IPNet { _, n, _ := net.ParseCIDR("100.64.0.0/10"); return n }()

func isGlobalIP(ip net.IP) bool {
	local := ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || cgnat.Contains(ip)
	return !local
}

// FilterPublicSeeds drops non-public addresses.
func FilterPublicSeeds(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		if IsPublicMultiaddr(a) {
			out = append(out, a)
		}
	}
	return out
}

// AddRelays registers static relay peers with the libp2p host. They are
// added to the peerstore and dialed once. No relay reservation is made.
func (n *Libp2pNode) AddRelays(relays []string) {
	if len(relays) > 32 {
		relays = relays[:32]
	}
	for _, info := range ParseMultiaddrs(strings.Join(relays, ",")) {
		n.host.Peerstore().AddAddrs(info.ID, info.Addrs, time.Hour*24*30)
		n.launch(func() {
			ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
			defer cancel()
			_ = n.host.Connect(ctx, info)
		})
	}
}

// startBootstrap dials a list of seed multi-addrs concurrently, ignoring
// individual failures.
func (n *Libp2pNode) startBootstrap(seeds []string) {
	var wg sync.WaitGroup
	for _, s := range seeds {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
			defer cancel()
			if err := n.ConnectSeed(ctx, addr); err != nil {
				n.logger("p2p: seed dial %s: %v", addr, err)
			}
		}(s)
	}
	wg.Wait()
}

// Bootstrap applies a BootstrapConfig: registers relays, remembers and dials
// seeds, optionally resolves DNS seeds. The seeds are redialed by the
// maintenance loop whenever the node has too few peers.
//
// Safe to call after Start.
func (n *Libp2pNode) Bootstrap(cfg BootstrapConfig) {
	if len(cfg.Relays) > 0 {
		n.AddRelays(cfg.Relays)
	}
	seeds := append([]string(nil), cfg.Seeds...)
	dnsCtx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	dns := ResolveDNSSeeds(dnsCtx, cfg.Network, 5*time.Second)
	cancel()
	if !cfg.AllowPrivateSeeds {
		dns = FilterPublicSeeds(dns)
	}
	seeds = append(seeds, dns...)
	if len(seeds) > 512 {
		seeds = seeds[:512]
	}
	n.netMu.Lock()
	n.seeds = ParseMultiaddrs(strings.Join(seeds, ","))
	known := len(n.known)
	n.netMu.Unlock()
	if len(seeds) == 0 && len(cfg.Relays) == 0 && known == 0 {
		n.logger("WARNING: no seed addresses configured and no known peers: this node " +
			"will not find the network (a miner would build a chain alone). Pass -seed.")
	}
	if len(seeds) > 0 {
		n.launch(func() { n.startBootstrap(seeds) })
	}
}

// ---- known peers and reconnect ----------------------------------------

// limiterTTL is how long an idle per-peer rate-limit record is kept.
var limiterTTL = 5 * time.Minute

const (
	maxKnownPeers   = 128
	maxDialsPerTick = 4
	peersFile       = "peers.json"
)

type knownPeer struct {
	Addrs  []string  `json:"addrs"`
	Fails  int       `json:"-"`
	NextAt time.Time `json:"-"`
	// Proven: the peer has delivered blocks we accepted. Not persisted: a restart
	// treats every entry as unproven until it proves itself again.
	Proven bool `json:"-"`
}

func (n *Libp2pNode) peersPath() string {
	if n.opts.DataDir == "" {
		return ""
	}
	return filepath.Join(n.opts.DataDir, peersFile)
}

func (n *Libp2pNode) loadKnown() {
	path := n.peersPath()
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 1<<20 {
		return
	}
	var m map[string][]string
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	for ids, addrs := range m {
		id, err := peer.Decode(ids)
		if err != nil || len(n.known) >= maxKnownPeers {
			continue
		}
		n.known[id] = &knownPeer{Addrs: addrs}
	}
}

func (n *Libp2pNode) saveKnown() {
	path := n.peersPath()
	n.netMu.Lock()
	if path == "" || !n.dirty {
		n.netMu.Unlock()
		return
	}
	m := make(map[string][]string, len(n.known))
	for id, k := range n.known {
		m[id.String()] = k.Addrs
	}
	n.dirty = false
	n.netMu.Unlock()
	raw, err := json.Marshal(m)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) == nil {
		_ = os.Rename(tmp, path)
	}
}

// maxKnownPerNet bounds how many address-book entries one /24 or /48 may hold.
const maxKnownPerNet = 2

// remember offers a peer that completed the hello handshake to the address book.
//
// Admission is deliberately not first come, first served: a restart would
// otherwise dial only whoever connected first. A peer enters the book if we
// dialed it (outbound), or if it is inbound and has since delivered blocks we
// accepted. Addresses a public peer advertises are filtered for routability
// (identify can hand us /dns4/ names that resolve inside our network), and one
// /24 or /48 holds at most maxKnownPerNet entries; when the book is full a
// proven peer replaces a failing or unproven entry.
func (n *Libp2pNode) remember(pid peer.ID) {
	conns := n.host.Network().ConnsToPeer(pid)
	outbound, remoteGroup := false, ""
	for _, c := range conns {
		if c.Stat().Direction == network.DirOutbound {
			outbound = true
		}
		if remoteGroup == "" {
			remoteGroup = netGroup(c.RemoteMultiaddr())
		}
	}
	n.book.mu.Lock()
	proven := n.book.get(pid).delivered > 0
	n.book.mu.Unlock()
	if !outbound && !proven {
		return
	}
	filter := remoteGroup != "" // a public peer: do not trust its self-reported addresses blindly
	var addrs []string
	for _, a := range n.host.Peerstore().Addrs(pid) {
		s := a.String()
		if strings.Contains(s, "/p2p-circuit") || (filter && !IsPublicMultiaddr(s)) {
			continue
		}
		addrs = append(addrs, s)
	}
	if len(addrs) == 0 {
		return
	}
	if len(addrs) > 8 {
		addrs = addrs[:8]
	}
	group := ""
	if len(addrs) > 0 {
		if ma1, err := ma.NewMultiaddr(addrs[0]); err == nil {
			group = netGroup(ma1)
		}
	}
	n.netMu.Lock()
	defer n.netMu.Unlock()
	k, ok := n.known[pid]
	if !ok {
		if group != "" {
			same := 0
			for _, other := range n.known {
				if len(other.Addrs) > 0 {
					if m, err := ma.NewMultiaddr(other.Addrs[0]); err == nil && netGroup(m) == group {
						same++
					}
				}
			}
			if same >= maxKnownPerNet {
				return
			}
		}
		if len(n.known) >= maxKnownPeers {
			victim, found := peer.ID(""), false
			for id, other := range n.known {
				if other.Fails > 0 || !other.Proven {
					victim, found = id, true
					break
				}
			}
			if !proven && !outbound || !found {
				return
			}
			delete(n.known, victim)
		}
		k = &knownPeer{}
		n.known[pid] = k
	}
	k.Addrs, k.Fails, k.NextAt = addrs, 0, time.Time{}
	k.Proven = k.Proven || proven
	n.dirty = true
}

// maintenanceLoop keeps the node connected: it redials seeds and known peers
// while below the target peer count, and does housekeeping (rate-limit and
// score garbage collection, address book persistence).
func (n *Libp2pNode) maintenanceLoop() {
	defer n.wg.Done()
	t := time.NewTicker(n.opts.MaintenanceInterval)
	defer t.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
		}
		n.sync.limiter.gc(limiterTTL)
		n.hello.gc(limiterTTL)
		n.blkLimit.gc(limiterTTL)
		n.txLimit.gc(limiterTTL)
		n.book.gc()
		n.saveKnown()
		n.reconnect()
	}
}

// outboundPeers counts connected peers we dialed.
func (n *Libp2pNode) outboundPeers() int {
	count := 0
	for _, pid := range n.host.Network().Peers() {
		for _, c := range n.host.Network().ConnsToPeer(pid) {
			if c.Stat().Direction == network.DirOutbound {
				count++
				break
			}
		}
	}
	return count
}

// targetOutbound is the number of outbound peers reconnect aims for. Inbound
// peers never count toward it, however many connect: otherwise a handful of
// idle inbound sybils would stop the node ever redialing honest peers.
func (n *Libp2pNode) targetOutbound() int {
	return max(2, n.opts.TargetPeers/2)
}

func (n *Libp2pNode) reconnect() {
	if n.outboundPeers() >= n.targetOutbound() {
		return
	}
	type target struct {
		info peer.AddrInfo
		seed bool
	}
	var seeds, known []target
	now := time.Now()
	n.netMu.Lock()
	for _, s := range n.seeds {
		if st := n.seedState[s.ID]; st != nil && now.Before(st.nextAt) {
			continue // a seed that keeps failing waits out its backoff
		}
		seeds = append(seeds, target{info: s, seed: true})
	}
	for id, k := range n.known {
		if now.Before(k.NextAt) {
			continue
		}
		var addrs []ma.Multiaddr
		for _, a := range k.Addrs {
			if m, err := ma.NewMultiaddr(a); err == nil {
				addrs = append(addrs, m)
			}
		}
		if len(addrs) > 0 {
			known = append(known, target{info: peer.AddrInfo{ID: id, Addrs: addrs}})
		}
	}
	n.netMu.Unlock()
	rand.Shuffle(len(seeds), func(i, j int) { seeds[i], seeds[j] = seeds[j], seeds[i] })
	rand.Shuffle(len(known), func(i, j int) { known[i], known[j] = known[j], known[i] })
	// Each tick's budget is split, so neither list can starve the other: first
	// half seeds, half known peers, then whatever is left from either.
	half := maxDialsPerTick / 2
	var todo []target
	take := func(list []target, k int) ([]target, []target) {
		if k > len(list) {
			k = len(list)
		}
		return list[:k], list[k:]
	}
	a, seeds := take(seeds, half)
	b, known := take(known, half)
	todo = append(todo, a...)
	todo = append(todo, b...)
	todo = append(todo, seeds...)
	todo = append(todo, known...)

	dials := 0
	for _, t := range todo {
		if dials >= maxDialsPerTick || n.ctx.Err() != nil {
			return
		}
		if t.info.ID == n.host.ID() || n.host.Network().Connectedness(t.info.ID) == network.Connected || n.book.isBanned(t.info.ID) {
			continue
		}
		dials++
		err := n.dial(n.ctx, t.info, t.seed)
		n.netMu.Lock()
		if t.seed {
			st := n.seedState[t.info.ID]
			if st == nil {
				st = &seedBackoff{}
				n.seedState[t.info.ID] = st
			}
			if err == nil {
				st.fails, st.nextAt = 0, time.Time{}
			} else {
				st.fails++
				st.nextAt = time.Now().Add(min(2*time.Second<<min(st.fails, 8), 5*time.Minute)) // 4s, 8s ... 5min
			}
		} else if k := n.known[t.info.ID]; k != nil {
			if err == nil {
				k.Fails = 0
			} else if k.Fails++; k.Fails >= 5 {
				delete(n.known, t.info.ID)
				n.dirty = true
			} else {
				k.NextAt = time.Now().Add(time.Minute << k.Fails)
			}
		}
		n.netMu.Unlock()
	}
}

// seedBackoff is the redial schedule of a configured seed that keeps failing.
type seedBackoff struct {
	fails  int
	nextAt time.Time
}
