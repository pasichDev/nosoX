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

// SeedsRef is the release label (a pinned ref, not a branch) the seed lists are
// fetched from: a push to main cannot change what nodes dial. To publish or
// rotate seeds, edit seeds/*.txt, label that commit with a NEW ref (seeds-v2,
// ...), and ship a release that bumps this constant. Until the ref exists the
// fetch gets a 404 and the node simply has no HTTP seeds.
const SeedsRef = "seeds-v1"

// HTTPSeedURLs maps a network name to the HTTP(S) endpoints that publish its
// seed list: a plain-text file of libp2p multi-addresses (see seeds/mainnet.txt)
// at the pinned ref SeedsRef. The list is unsigned; the pin, the HTTPS-only
// transport and the private-address filter limit what it can do, and operators
// who need more should pass -seed instead.
var HTTPSeedURLs = map[string][]string{
	"mainnet": {"https://raw.githubusercontent.com/pasichDev/noso-go/" + SeedsRef + "/seeds/mainnet.txt"},
	"testnet": {"https://raw.githubusercontent.com/pasichDev/noso-go/" + SeedsRef + "/seeds/testnet.txt"},
}

// SeedOptions tunes seed resolution.
type SeedOptions struct {
	// AllowPrivate keeps loopback, private and link-local addresses. Off by
	// default: a seed list must not make a node probe its own LAN.
	AllowPrivate bool
}

// newSeedClient returns an HTTP client that follows at most three redirects, all
// of them HTTPS and to the same host.
func newSeedClient() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("seed URL: too many redirects")
			}
			if req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("seed URL: redirect to %s refused", req.URL.Redacted())
			}
			return nil
		},
	}
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
// returning de-duplicated, parseable peer AddrInfos with private addresses
// removed. Network/HTTP errors on an individual URL are non-fatal. A nil/empty
// result simply means the node must rely on -seed or DNS seeds.
func ResolveHTTPSeeds(ctx context.Context, network string) []peer.AddrInfo {
	return ParseMultiaddrs(strings.Join(ResolveHTTPSeedStrings(ctx, network), ","))
}

// ResolveHTTPSeedStrings is like ResolveHTTPSeeds but returns raw, validated
// multi-address strings suitable for appending to BootstrapConfig.Seeds.
func ResolveHTTPSeedStrings(ctx context.Context, network string) []string {
	return ResolveHTTPSeedStringsOpts(ctx, network, SeedOptions{})
}

// ResolveHTTPSeedStringsOpts is ResolveHTTPSeedStrings with options.
func ResolveHTTPSeedStringsOpts(ctx context.Context, network string, opts SeedOptions) []string {
	urls := HTTPSeedURLs[network]
	if len(urls) == 0 {
		return nil
	}
	client := newSeedClient()
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
			if !opts.AllowPrivate && !IsPublicMultiaddr(a) {
				continue
			}
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
