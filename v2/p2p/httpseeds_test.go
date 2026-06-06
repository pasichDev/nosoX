package p2p

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseSeedList(t *testing.T) {
	in := `
# a comment
/ip4/198.51.100.7/tcp/7781/p2p/12D3KooWBmwXbZQYZ8s8s9q5jq4dGq4dGq4dGq4dGq4dGq4dGq4d

   /dns4/seed1.example.com/tcp/7781/p2p/12D3KooWBmwXbZQYZ8s8s9q5jq4dGq4dGq4dGq4dGq4dGq4dGq4d   # inline
not-a-multiaddr
/ip4/256.256.256.256/tcp/7781
`
	valid, skipped := ParseSeedList(strings.NewReader(in))
	if len(valid) != 2 {
		t.Fatalf("want 2 valid, got %d: %v", len(valid), valid)
	}
	if len(skipped) == 0 {
		t.Fatalf("expected at least one skipped invalid line")
	}
	// inline comment must be stripped
	for _, v := range valid {
		if strings.Contains(v, "#") {
			t.Fatalf("inline comment not stripped: %q", v)
		}
	}
}

func TestResolveHTTPSeeds(t *testing.T) {
	body := "# seeds\n/ip4/198.51.100.7/tcp/7781/p2p/12D3KooWBmwXbZQYZ8s8s9q5jq4dGq4dGq4dGq4dGq4dGq4dGq4d\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	old := HTTPSeedURLs
	HTTPSeedURLs = map[string][]string{"unittest": {srv.URL}}
	defer func() { HTTPSeedURLs = old }()

	got := ResolveHTTPSeeds(context.Background(), "unittest")
	if len(got) != 1 {
		t.Fatalf("want 1 resolved seed, got %d", len(got))
	}
}

func TestResolveHTTPSeedsUnknownNetwork(t *testing.T) {
	if got := ResolveHTTPSeeds(context.Background(), "does-not-exist"); got != nil {
		t.Fatalf("unknown network should return nil, got %v", got)
	}
}
