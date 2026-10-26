package p2p

import (
	"context"
	"strings"
	"sync"
	"time"

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

// MainnetRelays are publicly-reachable libp2p relay nodes the AutoRelay
// system uses to help NAT'd peers receive inbound traffic.
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

// AddRelays registers static relay peers with the libp2p host. They are
// added to the peerstore with permanent TTL so AutoRelay can keep
// reservations open.
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
	if len(seeds) == 0 {
		return
	}
	var wg sync.WaitGroup
	if len(seeds) > 512 {
		seeds = seeds[:512]
	}
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

// Bootstrap applies a BootstrapConfig: registers relays, dials seeds,
// optionally resolves DNS seeds.
//
// Order of operations:
//
//  1. Resolve DNS seeds for the network (via ResolveDNSSeeds with a 5 s
//     timeout). Failures are silent — DNS is best-effort and the static
//     list is the source of truth.
//  2. Register relays on the libp2p host.
//  3. Dial every static + DNS-resolved seed.
//
// Safe to call after Start.
func (n *Libp2pNode) Bootstrap(cfg BootstrapConfig) {
	if len(cfg.Relays) > 0 {
		n.AddRelays(cfg.Relays)
	}
	seeds := append([]string(nil), cfg.Seeds...)
	dnsCtx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	seeds = append(seeds, ResolveDNSSeeds(dnsCtx, cfg.Network, 5*time.Second)...)
	cancel()
	if len(seeds) > 0 {
		n.launch(func() { n.startBootstrap(seeds) })
	}
}
