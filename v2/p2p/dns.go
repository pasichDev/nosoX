package p2p

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSSeedDomains is the per-network list of DNS names whose TXT records
// hold "v=nosox1;addr=<multiaddr>" entries. The launcher operates the
// authoritative zone and rotates entries as seed operators come and go.
// Falling back to DNS lets nodes pick up new seeds without binary
// rebuilds.
//
// Operators publish a TXT record like:
//
//	seed.noso-v2.example.com. 3600 IN TXT "v=nosox1;addr=/dns4/seed1.example.com/tcp/7781/p2p/12D3KooW…"
//	seed.noso-v2.example.com. 3600 IN TXT "v=nosox1;addr=/ip4/198.51.100.7/tcp/7781/p2p/12D3KooW…"
//
// Multiple TXT entries per name are accepted; bad entries are silently
// skipped.
var DNSSeedDomains = map[string][]string{
	"mainnet": {
		// "seed.noso-v2.example.com",   // placeholder for the launcher
	},
	"testnet": {
		// "seed.testnet.noso-v2.example.com",
	},
}

// ResolveDNSSeeds returns all multi-address strings recovered from
// every TXT record under the configured DNS seed domains for `network`.
// The lookup is bounded by `timeout`; partial results are returned
// when individual names fail.
func ResolveDNSSeeds(ctx context.Context, network string, timeout time.Duration) []string {
	domains, ok := DNSSeedDomains[network]
	if !ok || len(domains) == 0 {
		return nil
	}
	resolver := &net.Resolver{PreferGo: true}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var addrs []string
	for _, d := range domains {
		records, err := resolver.LookupTXT(c, d)
		if err != nil {
			continue
		}
		for _, r := range records {
			if addr, ok := parseSeedTXT(r); ok {
				addrs = append(addrs, addr)
			}
		}
	}
	return addrs
}

// parseSeedTXT reads a single TXT body of the form
// "v=nosox1;addr=<multiaddr>" and returns the multi-address.
func parseSeedTXT(txt string) (string, bool) {
	if !strings.HasPrefix(txt, "v=nosox1;") {
		return "", false
	}
	const key = "addr="
	idx := strings.Index(txt, key)
	if idx < 0 {
		return "", false
	}
	addr := strings.TrimSpace(txt[idx+len(key):])
	if !strings.HasPrefix(addr, "/") {
		return "", false
	}
	return addr, true
}

// formatSeedTXT is the inverse — used by tools and tests to produce
// the canonical TXT body for a given multi-address.
func formatSeedTXT(addr string) string {
	return fmt.Sprintf("v=nosox1;addr=%s", addr)
}
