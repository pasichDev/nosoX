package p2p

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// HTTPSeedURLs maps a network name to the HTTP(S) endpoints that publish its
// seed list. The list is a plain-text file of libp2p multi-addresses (see
// seeds/mainnet.txt). Serving seeds over HTTPS from a domain lets operators
// rotate the seed set without shipping a new binary; nodes re-fetch on every
// start. Keep the file small and behind a CDN/static host.
var HTTPSeedURLs = map[string][]string{
	"mainnet": {"https://raw.githubusercontent.com/pasichDev/noso-go/main/seeds/mainnet.txt"},
	"testnet": {"https://raw.githubusercontent.com/pasichDev/noso-go/main/seeds/testnet.txt"},
}

// ParseSeedList reads a seed file (one multi-address per line; '#' comments
// and blank lines ignored) and returns the syntactically valid addresses.
// Invalid lines are skipped and reported in skipped for the caller to log.
func ParseSeedList(r io.Reader) (valid []string, skipped []string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if len(valid)+len(skipped) >= 512 {
			break
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Drop inline comments after the address.
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if _, err := ma.NewMultiaddr(line); err != nil {
			skipped = append(skipped, line)
			continue
		}
		valid = append(valid, line)
	}
	return valid, skipped
}

// ResolveHTTPSeeds fetches and parses every seed URL configured for network,
// returning de-duplicated, parseable peer AddrInfos. Network/HTTP errors on an
// individual URL are non-fatal: the function tries the remaining URLs and
// returns whatever it could gather. A nil/empty result simply means the node
// must rely on -seed, DNS seeds, or the DHT.
func ResolveHTTPSeeds(ctx context.Context, network string) []peer.AddrInfo {
	urls := HTTPSeedURLs[network]
	if len(urls) == 0 {
		return nil
	}
	client := &http.Client{Timeout: 8 * time.Second}
	seen := map[string]struct{}{}
	var out []peer.AddrInfo
	for _, url := range urls {
		addrs, err := fetchSeedURL(ctx, client, url)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = struct{}{}
			out = append(out, ParseMultiaddrs(a)...)
		}
	}
	return out
}

// ResolveHTTPSeedStrings is like ResolveHTTPSeeds but returns raw, validated
// multi-address strings suitable for appending to BootstrapConfig.Seeds.
func ResolveHTTPSeedStrings(ctx context.Context, network string) []string {
	urls := HTTPSeedURLs[network]
	if len(urls) == 0 {
		return nil
	}
	client := &http.Client{Timeout: 8 * time.Second}
	seen := map[string]struct{}{}
	var out []string
	for _, url := range urls {
		addrs, err := fetchSeedURL(ctx, client, url)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = struct{}{}
			out = append(out, a)
		}
	}
	return out
}

func fetchSeedURL(ctx context.Context, client *http.Client, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Seed lists are unauthenticated discovery hints. Never allow cleartext
	// retrieval, including a downgrade redirect from an HTTPS seed host.
	if req.URL.Scheme != "https" || req.URL.Host == "" || req.URL.User != nil {
		return nil, fmt.Errorf("seed URL must use HTTPS without credentials")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.Scheme != "https" {
		return nil, fmt.Errorf("seed URL redirected to an insecure transport")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("seed url %s: status %d", url, resp.StatusCode)
	}
	valid, _ := ParseSeedList(io.LimitReader(resp.Body, 1<<20))
	return valid, nil
}
