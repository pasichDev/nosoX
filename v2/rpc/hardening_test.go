package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pasichDev/noso-go/v2/chain"
	"github.com/pasichDev/noso-go/v2/genesis"
	"github.com/pasichDev/noso-go/v2/mempool"
	"github.com/pasichDev/noso-go/v2/miner"
	"github.com/pasichDev/noso-go/v2/types"
)

func rawPost(h http.Handler, host, ctype, body, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	req.Host = host
	if remote != "" {
		req.RemoteAddr = remote
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const versionBody = `{"jsonrpc":"2.0","method":"version","id":1}`

// DNS rebinding: a page on a rebound name reaches 127.0.0.1 with its own name
// in Host. In no-token mode (where any non-browser caller is trusted) that must
// be refused; localhost and IP literals stay fine.
func TestHostAllowlistStopsDNSRebinding(t *testing.T) {
	h := (&Service{}).HTTPHandler()
	for _, host := range []string{"evil.example", "evil.example:7780", "localhost.evil.example"} {
		if rec := rawPost(h, host, "application/json", versionBody, "", nil); rec.Code != 403 {
			t.Errorf("Host %q: status %d, want 403", host, rec.Code)
		}
	}
	for _, host := range []string{"localhost", "localhost:7780", "127.0.0.1:7780", "[::1]:7780", "LOCALHOST."} {
		if rec := rawPost(h, host, "application/json", versionBody, "", nil); rec.Code != 200 {
			t.Errorf("Host %q: status %d, want 200", host, rec.Code)
		}
	}
	// Token mode: a rebinding page has no token, so any Host is fine unless an allowlist is set.
	tok := (&Service{Token: "t"}).HTTPHandler()
	if rec := rawPost(tok, "node.example.org", "application/json", versionBody, "", nil); rec.Code != 200 {
		t.Errorf("token mode, public host: %d", rec.Code)
	}
	lim := (&Service{Token: "t", AllowedHosts: []string{"node.example.org"}}).HTTPHandler()
	if rec := rawPost(lim, "node.example.org:443", "application/json", versionBody, "", nil); rec.Code != 200 {
		t.Errorf("allowlisted host: %d", rec.Code)
	}
	if rec := rawPost(lim, "other.example.org", "application/json", versionBody, "", nil); rec.Code != 403 {
		t.Errorf("non-allowlisted host with allowlist: %d", rec.Code)
	}
}

func TestContentTypeIsEnforced(t *testing.T) {
	h := (&Service{}).HTTPHandler()
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data"} {
		if rec := rawPost(h, "127.0.0.1", ct, versionBody, "", nil); rec.Code != 415 {
			t.Errorf("Content-Type %q: %d, want 415", ct, rec.Code)
		}
	}
	for _, ct := range []string{"application/json", "application/json; charset=utf-8"} {
		if rec := rawPost(h, "127.0.0.1", ct, versionBody, "", nil); rec.Code != 200 {
			t.Errorf("Content-Type %q: %d, want 200", ct, rec.Code)
		}
	}
}

func TestPerClientRateLimitAppliesToEveryMethod(t *testing.T) {
	s := &Service{Token: "tok", RatePerSecond: 0.001, RateBurst: 3}
	h := s.HTTPHandler()
	codes := []int{}
	for i := 0; i < 5; i++ {
		codes = append(codes, rawPost(h, "127.0.0.1", "application/json", versionBody, "10.0.0.1:1", nil).Code)
	}
	if fmt.Sprint(codes) != "[200 200 200 429 429]" {
		t.Fatalf("codes %v", codes)
	}
	// Another client has its own bucket.
	if rec := rawPost(h, "127.0.0.1", "application/json", versionBody, "10.0.0.2:1", nil); rec.Code != 200 {
		t.Fatalf("second client: %d", rec.Code)
	}
	// Authenticated calls and /health are limited too.
	req := httptest.NewRequest("GET", "/health", nil)
	req.Host = "127.0.0.1"
	req.RemoteAddr = "10.0.0.1:9"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("health not limited: %d", rec.Code)
	}
	if rec := rawPost(h, "127.0.0.1", "application/json", `{"jsonrpc":"2.0","method":"stopmining","id":1}`, "10.0.0.1:1", map[string]string{"Authorization": "Bearer tok"}); rec.Code != 429 {
		t.Fatalf("authorized call not limited: %d", rec.Code)
	}
}

func TestConcurrencyCapShedsLoad(t *testing.T) {
	s := &Service{MaxConcurrent: 2}
	s.init()
	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(2)
	h := s.guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		started.Done()
		<-release
	}))
	var done sync.WaitGroup
	for i := 0; i < 2; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = "127.0.0.1"
			req.RemoteAddr = fmt.Sprintf("10.0.0.%d:1", i+1)
			h.ServeHTTP(httptest.NewRecorder(), req)
		}(i)
	}
	started.Wait()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "127.0.0.1"
	req.RemoteAddr = "10.0.0.9:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), fmt.Sprint(CodeBusy)) {
		t.Fatalf("third request: %d %s", rec.Code, rec.Body.String())
	}
	close(release)
	done.Wait()
}

func TestServerCapsHTTP2Streams(t *testing.T) {
	srv := (&Service{}).NewServer("127.0.0.1:0")
	if srv.HTTP2 == nil || srv.HTTP2.MaxConcurrentStreams <= 0 || srv.HTTP2.MaxConcurrentStreams > 32 {
		t.Fatalf("HTTP/2 stream cap not set: %+v", srv.HTTP2)
	}
	if srv.ReadHeaderTimeout == 0 || srv.WriteTimeout == 0 || srv.MaxHeaderBytes == 0 {
		t.Fatal("timeouts not set")
	}
}

func TestTokenComparisonIsOverHashes(t *testing.T) {
	long := strings.Repeat("a", 4096)
	if subtleConstantTimeEq(long, "a") || subtleConstantTimeEq("", "a") || !subtleConstantTimeEq(long, long) || !subtleConstantTimeEq("", "") {
		t.Fatal("comparison wrong")
	}
}

func TestMinerStatsIsNotPublic(t *testing.T) {
	if DefaultPublicMethods["minerstats"] {
		t.Fatal("minerstats leaks mining activity to any caller")
	}
	h := (&Service{}).HTTPHandler()
	rec := rawPost(h, "127.0.0.1", "application/json", `{"jsonrpc":"2.0","method":"minerstats","id":1}`, "", map[string]string{"Origin": "https://evil.example"})
	if rec.Code != 401 {
		t.Fatalf("browser origin read minerstats: %d", rec.Code)
	}
}

// The miner's failure counters reach the operator through minerstats.
func TestMinerStatsReportsFailures(t *testing.T) {
	c := chain.NewMemory()
	g, _ := genesis.Build(genesis.Config{NetworkMagic: types.NetworkMagicTestnet, Timestamp: time.Now().Unix() - 600, InitialDifficulty: 1})
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	m := miner.New(c, mempool.New(4), nil) // no reward key store: every candidate fails
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx, 1, "t"); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	deadline := time.Now().Add(10 * time.Second)
	for m.Stats().Errors == 0 {
		if time.Now().After(deadline) {
			t.Fatal("miner never recorded its failure")
		}
		time.Sleep(10 * time.Millisecond)
	}
	rec := rawPost((&Service{Chain: c, Miner: m}).HTTPHandler(), "127.0.0.1", "application/json", `{"jsonrpc":"2.0","method":"minerstats","id":1}`, "", nil)
	var resp struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"blocks_found", "errors", "last_error", "last_error_at"} {
		if _, ok := resp.Result[k]; !ok {
			t.Errorf("minerstats lacks %q: %s", k, rec.Body.String())
		}
	}
	if e, _ := resp.Result["errors"].(float64); e < 1 {
		t.Errorf("errors = %v", resp.Result["errors"])
	}
	if msg, _ := resp.Result["last_error"].(string); !strings.Contains(msg, "reward keystore") {
		t.Errorf("last_error = %q", msg)
	}
}

func TestTransactionFeeTooLowIsAPolicyRejection(t *testing.T) {
	s := &Service{}
	err := fmt.Errorf("%w: pays 5 for 30000 bytes, the relay minimum is 30000 (1000 per 1000 bytes)", mempool.ErrFeeTooLow)
	e := s.txError(err)
	if e.Code != CodeTxRejected {
		t.Fatalf("fee floor must be a definitive rejection, got %+v", e)
	}
	if !strings.Contains(e.Message, "policy") || !strings.Contains(e.Message, "minimum is 30000") {
		t.Fatalf("message does not say what to change: %q", e.Message)
	}
}

func TestStartMiningParamsAreStrict(t *testing.T) {
	c := chain.NewMemory()
	g, _ := genesis.Build(genesis.Config{NetworkMagic: types.NetworkMagicTestnet, Timestamp: time.Now().Unix() - 600, InitialDifficulty: 1})
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	s := &Service{Chain: c, Miner: miner.New(c, mempool.New(4), nil)}
	h := s.HTTPHandler()
	for name, params := range map[string]string{
		"three params":        `[1,"a",3]`,
		"string threads":      `["1"]`,
		"float threads":       `[1.5]`,
		"zero threads":        `[0]`,
		"negative threads":    `[-1]`,
		"too many threads":    `[17]`,
		"huge threads":        `[100000]`,
		"non-string label":    `[1,5]`,
		"empty label":         `[1,""]`,
		"long label":          `[1,"` + strings.Repeat("a", 65) + `"]`,
		"control chars label": `[1,"a\u001b[2Jb"]`,
		"space label":         `[1,"a b"]`,
		"object":              `[{"threads":1}]`,
	} {
		rec := rawPost(h, "127.0.0.1", "application/json", `{"jsonrpc":"2.0","method":"startmining","params":`+params+`,"id":1}`, "", nil)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), fmt.Sprint(CodeInvalidParams)) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

// The reasons a transaction is refused are returned (clipped); a transient
// refusal is a different code so the wallet does not treat it as final.
func TestTransactionErrorsAreClassified(t *testing.T) {
	s := &Service{}
	if e := s.txError(errors.New("mempool: full")); e.Code != CodeTxRetry {
		t.Errorf("full pool: %+v", e)
	}
	if e := s.txError(chain.ErrResourceBudget); e.Code != CodeTxRetry {
		t.Errorf("budget: %+v", e)
	}
	if e := s.txError(errors.New("mempool: transaction validation unavailable")); e.Code != CodeTxRetry {
		t.Errorf("unavailable: %+v", e)
	}
	if e := s.txError(errors.New("chain: bad kernel signature")); e.Code != CodeTxRejected {
		t.Errorf("invalid tx: %+v", e)
	}
	if e := s.txError(errors.New(strings.Repeat("x", 5000))); len(e.Message) > 200 {
		t.Errorf("message not clipped: %d", len(e.Message))
	}
}

// A competing transaction in the pool is a policy refusal, not a verdict on
// validity: the wallet must not be told it is final (it would be advised to
// cancel a transaction that may still be mined).
func TestPolicyConflictsAreNotFinalRejections(t *testing.T) {
	s := &Service{}
	for _, e := range []error{mempool.ErrConflict, mempool.ErrKernelDup, mempool.ErrReplaceFee, fmt.Errorf("wrapped: %w", mempool.ErrConflict)} {
		if got := s.txError(e); got.Code != CodeTxPolicy {
			t.Errorf("%v: code %d, want CodeTxPolicy", e, got.Code)
		}
	}
	if got := s.txError(fmt.Errorf("%w: pays 1", mempool.ErrFeeTooLow)); got.Code != CodeTxRejected {
		t.Errorf("fee too low stays final: %d", got.Code)
	}
}

func TestInternalErrorsAreLoggedNotReturned(t *testing.T) {
	var logged string
	s := &Service{Logf: func(f string, a ...any) { logged = fmt.Sprintf(f, a...) }}
	e := s.internal("op", errors.New("open /var/secret/path: permission denied"))
	if e.Code != CodeInternal || strings.Contains(e.Message, "secret") || !strings.Contains(logged, "/var/secret/path") {
		t.Fatalf("returned %+v, logged %q", e, logged)
	}
}

func TestGenesisInfoReportsTheChainsNetwork(t *testing.T) {
	c := chain.NewMemory()
	g, _ := genesis.Build(genesis.Config{NetworkMagic: types.NetworkMagicTestnet, Timestamp: time.Now().Unix() - 600, InitialDifficulty: 1})
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	// Service without GenesisConfig: the default config is mainnet, the chain is testnet.
	_, resp := call(t, (&Service{Chain: c}).HTTPHandler(), `{"jsonrpc":"2.0","method":"genesisinfo","id":1}`, "")
	m, _ := resp.Result.(map[string]any)
	if m == nil || uint32(m["network"].(float64)) != types.NetworkMagicTestnet {
		t.Fatalf("genesisinfo: %+v", resp)
	}
}

// Over a real loopback listener the allowlist applies even in token mode: after a
// DNS rebind the page is same-origin and could read the public methods.
func TestHostAllowlistAppliesOnLoopbackListenerEvenWithToken(t *testing.T) {
	srv := httptest.NewServer((&Service{Token: "a-token"}).HTTPHandler())
	defer srv.Close()
	do := func(host string) int {
		req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(versionBody))
		req.Host = host
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := do("evil.example"); c != 403 {
		t.Fatalf("rebinding host over loopback with a token: %d, want 403", c)
	}
	if c := do(""); c != 200 { // Host defaults to the listener's 127.0.0.1:port
		t.Fatalf("legitimate loopback host: %d", c)
	}
}
