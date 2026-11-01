// Package rpc exposes a JSON-RPC 2.0 HTTP API for the node.
package rpc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"mime"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pasichDev/nosoX/v2/chain"
	"github.com/pasichDev/nosoX/v2/genesis"
	"github.com/pasichDev/nosoX/v2/mempool"
	"github.com/pasichDev/nosoX/v2/miner"
	"github.com/pasichDev/nosoX/v2/types"
)

// Service bundles the dependencies for the RPC handlers.
//
// DaemonContext MUST be a long-lived context owned by the daemon, NOT a
// per-request context. The miner uses it as the parent for its workers;
// using the HTTP request's context would cancel mining as soon as the
// RPC response is sent.
//
// The zero value of every optional field is the safe default: no CORS headers,
// Host allowlist on in no-token mode, 64 concurrent requests, 200 requests per
// second per client address.
type Service struct {
	Chain         *chain.Chain
	Mempool       *mempool.Pool
	Miner         *miner.Miner
	Version       string
	DaemonContext context.Context
	// GenesisConfig is captured at daemon boot so RPC endpoints can
	// recompute the genesis summary from the same parameters the chain
	// itself used. nil -> genesis.Default().
	GenesisConfig *genesis.Config

	// Token enables Bearer auth for every method that is not public. Empty means
	// "no token": then only requests without an Origin header may use restricted
	// methods, and the Host header must be a loopback name (DNS-rebinding
	// defence). The daemon refuses a non-loopback bind without a token.
	Token string

	// PublicMethods is the set of JSON-RPC method names that bypass the
	// auth check when Token is set (nil means DefaultPublicMethods). It has no
	// effect in no-token mode, where DefaultPublicMethods alone is what
	// requests carrying an Origin header may call; this is deliberate, so a
	// custom list can never widen what a web page can reach on a local node.
	PublicMethods map[string]bool

	// BroadcastTx, when set, gossips an accepted transaction to the network.
	// The daemon wires it to the p2p node's BroadcastTx. It is called only after
	// the transaction has been admitted to the mempool.
	BroadcastTx func(*types.Transaction) error

	// AllowedHosts are extra Host header values (host names, no port) accepted
	// in addition to localhost and IP literals. In token mode the allowlist is
	// enforced only when this is non-empty.
	AllowedHosts []string
	// CORSOrigin, when non-empty, is the single browser origin allowed to call
	// the API cross-origin ("*" only if set explicitly). Default: no CORS headers.
	CORSOrigin string
	// MaxConcurrent caps requests in flight (default 64).
	MaxConcurrent int
	// RatePerSecond and RateBurst bound requests per client address across all
	// methods (defaults 200 and 400: a wallet sync issues one hasutxo per tracked
	// output).
	RatePerSecond float64
	RateBurst     int
	// Logf receives internal errors, which are never sent to clients.
	Logf func(format string, args ...any)

	initOnce sync.Once
	sem      chan struct{}
	rl       *rateLimiter
	tipMu    sync.Mutex
	tipAt    time.Time
	tipHdr   types.BlockHeader
	tipOK    bool
	hosts    map[string]bool
}

// Maximum JSON-RPC request body. A transaction may be up to
// types.MaxBlockBodyBytes (64 KiB) and travels base64 encoded inside JSON.
const maxRequestBytes = 128 << 10

// maxMiningThreads is the miner's own limit.
const maxMiningThreads = miner.MaxThreads

// tipCacheTTL bounds how stale the public tip answers may be; it keeps
// unauthenticated polling from taking the chain lock on every call.
const tipCacheTTL = 250 * time.Millisecond

// JSON-RPC 2.0 error codes. HTTP statuses accompany transport-level failures;
// method-level application errors are returned with HTTP 200.
const (
	CodeParseError     = -32700 // HTTP 400
	CodeInvalidRequest = -32600 // HTTP 400 (405 non-POST, 413 oversize, 415 content type)
	CodeMethodNotFound = -32601 // HTTP 200 (a well-formed request for an unknown method)
	CodeInvalidParams  = -32602 // HTTP 400
	CodeInternal       = -32603 // HTTP 500, generic message only
	CodeUnavailable    = -32000 // HTTP 503: component not configured
	CodeUnauthorized   = -32001 // HTTP 401
	CodeNotFound       = -32004 // HTTP 200: block / item not found
	CodeTxRejected     = -32010 // HTTP 200: transaction failed validation (definitive)
	CodeTxRetry        = -32011 // HTTP 503: transaction not admitted for a transient reason; retry
	CodeConflict       = -32012 // HTTP 409: state conflict (miner already running)
	CodeTxPolicy       = -32013 // HTTP 200: transaction not admitted by relay policy (conflict, replacement fee); NOT a statement that it is invalid
	CodeBusy           = -32020 // HTTP 503: too many requests in flight
	CodeRateLimited    = -32021 // HTTP 429: per-client rate limit
	CodeForbidden      = -32022 // HTTP 403: Host header not allowed
)

func (s *Service) init() {
	s.initOnce.Do(func() {
		n := s.MaxConcurrent
		if n <= 0 {
			n = 64
		}
		s.sem = make(chan struct{}, n)
		rate, burst := s.RatePerSecond, s.RateBurst
		if rate <= 0 {
			rate = 200
		}
		if burst <= 0 {
			burst = 400
		}
		s.rl = newRateLimiter(rate, float64(burst))
		s.hosts = map[string]bool{"localhost": true}
		for _, h := range s.AllowedHosts {
			s.hosts[strings.ToLower(strings.TrimSuffix(h, "."))] = true
		}
		if s.Logf == nil {
			s.Logf = log.Printf
		}
	})
}

// NewServer returns an http.Server for addr serving this API with the
// daemon's timeouts and an HTTP/2 stream cap. The cap matters in TLS mode: a
// single HTTP/2 connection otherwise carries 250 concurrent handlers.
func (s *Service) NewServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.HTTPHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: 16},
	}
}

// HTTPHandler returns an http.Handler that dispatches JSON-RPC 2.0 calls.
func (s *Service) HTTPHandler() http.Handler {
	s.init()
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.jsonRPC)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	return s.guard(s.cors(mux))
}

// guard applies, in order: Host allowlist, per-client rate limit, concurrency cap.
func (s *Service) guard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r) {
			writeJSON(w, http.StatusForbidden, jrpcResp{JSONRPC: "2.0", Error: &jrpcErr{Code: CodeForbidden, Message: "Host not allowed"}})
			return
		}
		if !s.rl.allow(clientIP(r), time.Now()) {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, jrpcResp{JSONRPC: "2.0", Error: &jrpcErr{Code: CodeRateLimited, Message: "Rate limit exceeded"}})
			return
		}
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusServiceUnavailable, jrpcResp{JSONRPC: "2.0", Error: &jrpcErr{Code: CodeBusy, Message: "Server busy"}})
			return
		}
		h.ServeHTTP(w, r)
	})
}

// hostAllowed implements the DNS-rebinding defence. A page on a rebound
// hostname reaches the node with its own name in the Host header; localhost and
// IP literals cannot be rebound. The allowlist applies whenever the connection
// arrived on a loopback address (token or not: after a rebind the page is
// same-origin, so it can read public methods even without a token), whenever
// there is no token, and whenever AllowedHosts is configured. Only a token-mode
// server reached over a non-loopback address skips it.
func (s *Service) hostAllowed(r *http.Request) bool {
	if s.Token != "" && len(s.AllowedHosts) == 0 && !viaLoopback(r) {
		return true
	}
	h := r.Host
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.ToLower(strings.TrimSuffix(strings.Trim(h, "[]"), "."))
	if net.ParseIP(h) != nil {
		return true
	}
	return s.hosts[h]
}

// viaLoopback reports whether the request came in on a loopback local address.
func viaLoopback(r *http.Request) bool {
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if t, ok := a.(*net.TCPAddr); ok {
			return t.IP.IsLoopback()
		}
	}
	return false
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// rateLimiter is a per-key token bucket.
type rateLimiter struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	m     map[string]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

const maxBuckets = 8192

func newRateLimiter(rate, burst float64) *rateLimiter {
	return &rateLimiter{rate: rate, burst: burst, m: map[string]*bucket{}}
}

func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[key]
	if b == nil {
		if len(l.m) >= maxBuckets {
			for k, v := range l.m { // drop buckets that have refilled completely, else an arbitrary one
				if now.Sub(v.at).Seconds()*l.rate >= l.burst {
					delete(l.m, k)
				}
			}
			for k := range l.m {
				if len(l.m) < maxBuckets {
					break
				}
				delete(l.m, k)
			}
		}
		b = &bucket{tokens: l.burst, at: now}
		l.m[key] = b
	}
	b.tokens += now.Sub(b.at).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// DefaultPublicMethods is the cheap, read-only allow-list shipped with the
// daemon. Methods here can be called without the auth token. Anything that
// mutates node state (startmining, stopmining, submittransaction), reveals the
// node's activity (minerstats) or does per-call lookups on behalf of a wallet
// (hasutxo) is excluded.
var DefaultPublicMethods = map[string]bool{
	"tip":            true,
	"getmainnetinfo": true,
	"getblock":       true,
	"pending":        true,
	"genesisinfo":    true,
	"version":        true,
}

// authorize returns true if the request carries a valid token or the
// requested method is on the public allow-list.
func (s *Service) authorize(r *http.Request, method string) bool {
	if s.Token == "" {
		if r.Header.Get("Origin") != "" {
			return DefaultPublicMethods[strings.ToLower(method)]
		}
		return true
	}
	if s.PublicMethods != nil && s.PublicMethods[strings.ToLower(method)] {
		return true
	}
	if s.PublicMethods == nil && DefaultPublicMethods[strings.ToLower(method)] {
		return true
	}
	authz := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(authz) <= len(prefix) || !strings.EqualFold(authz[:len(prefix)], prefix) {
		return false
	}
	return subtleConstantTimeEq(authz[len(prefix):], s.Token)
}

// subtleConstantTimeEq compares SHA-256 digests of both values in constant
// time, so neither content nor length leaks through timing.
func subtleConstantTimeEq(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// cachedTip returns the tip header, refreshed at most every tipCacheTTL.
func (s *Service) cachedTip() (types.BlockHeader, bool) {
	s.tipMu.Lock()
	defer s.tipMu.Unlock()
	if s.tipOK && time.Since(s.tipAt) < tipCacheTTL {
		return s.tipHdr, true
	}
	t, ok := s.Chain.Tip()
	if ok {
		s.tipHdr, s.tipOK, s.tipAt = t, true, time.Now()
	}
	return t, ok
}

// internal logs err and returns the generic error sent to the client.
func (s *Service) internal(op string, err error) *jrpcErr {
	s.init()
	s.Logf("rpc: %s: %v", op, err)
	return &jrpcErr{Code: CodeInternal, Message: "internal error"}
}

// genesisCfgOrDefault returns the captured genesis config, or Default() if
// the daemon didn't set one (rare; happens in test scaffolds).
func (s *Service) genesisCfgOrDefault() genesis.Config {
	if s.GenesisConfig != nil {
		return *s.GenesisConfig
	}
	return genesis.Default()
}

type jrpcReq struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      interface{}   `json:"id"`
}

type jrpcResp struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *jrpcErr    `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

var errTrailing = errors.New("trailing JSON")

type jrpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Service) jsonRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jrpcResp{JSONRPC: "2.0",
			Error: &jrpcErr{Code: CodeInvalidRequest, Message: "POST required"}})
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || (mt != "application/json" && mt != "application/json-rpc") {
		writeJSON(w, http.StatusUnsupportedMediaType, jrpcResp{JSONRPC: "2.0",
			Error: &jrpcErr{Code: CodeInvalidRequest, Message: "Content-Type must be application/json"}})
		return
	}
	var req jrpcReq
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	err := dec.Decode(&req)
	if err == nil {
		var extra any
		if dec.Decode(&extra) != io.EOF {
			err = errTrailing
		}
	}
	if err != nil {
		status, code := http.StatusBadRequest, CodeParseError
		var tooBig *http.MaxBytesError
		var typeErr *json.UnmarshalTypeError
		switch {
		case errors.As(err, &tooBig):
			status, code = http.StatusRequestEntityTooLarge, CodeInvalidRequest
		case errors.As(err, &typeErr):
			code = CodeInvalidRequest // well-formed JSON of the wrong shape
		}
		writeJSON(w, status, jrpcResp{JSONRPC: "2.0", Error: &jrpcErr{Code: code, Message: "Invalid JSON request"}})
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		writeJSON(w, http.StatusBadRequest, jrpcResp{JSONRPC: "2.0", ID: req.ID,
			Error: &jrpcErr{Code: CodeInvalidRequest, Message: "Invalid JSON request"}})
		return
	}
	if !s.authorize(r, req.Method) {
		writeJSON(w, http.StatusUnauthorized, jrpcResp{JSONRPC: "2.0", ID: req.ID,
			Error: &jrpcErr{Code: CodeUnauthorized, Message: "Not authorized"}})
		return
	}
	resp := jrpcResp{JSONRPC: "2.0", ID: req.ID}
	status := http.StatusOK
	switch strings.ToLower(req.Method) {
	case "version":
		resp.Result = s.Version
	case "tip", "getmainnetinfo":
		if s.Chain == nil || s.Mempool == nil {
			resp.Error = &jrpcErr{Code: CodeUnavailable, Message: "node not configured"}
			break
		}
		t, ok := s.cachedTip()
		resp.Result = map[string]any{
			"valid":      ok,
			"height":     t.Height,
			"hash":       types.HeaderID(&t).String(),
			"difficulty": t.Difficulty,
			"timestamp":  t.Timestamp,
			"pending":    s.Mempool.Len(),
		}
	case "getblock":
		if len(req.Params) < 1 {
			resp.Error = &jrpcErr{Code: CodeInvalidParams, Message: "missing param"}
			break
		}
		h, err := HeightFromParam(req.Params[0])
		if err != nil {
			resp.Error = &jrpcErr{Code: CodeInvalidParams, Message: "invalid height"}
			break
		}
		if s.Chain == nil {
			resp.Error = &jrpcErr{Code: CodeUnavailable, Message: "chain not configured"}
			break
		}
		hdr, ok := s.Chain.HeaderByHeight(h)
		if !ok {
			resp.Error = &jrpcErr{Code: CodeNotFound, Message: "block not found"}
			break
		}
		resp.Result = map[string]any{
			"height":     hdr.Height,
			"hash":       types.HeaderID(&hdr).String(),
			"prev":       hdr.PrevHash.String(),
			"timestamp":  hdr.Timestamp,
			"difficulty": hdr.Difficulty,
			"nonce":      hdr.Nonce,
		}
	case "pending":
		resp.Result = s.Mempool.Len()
	case "startmining":
		s.startMining(&resp, req.Params)
	case "stopmining":
		if s.Miner != nil {
			s.Miner.Stop()
		}
		resp.Result = "stopped"
	case "minerstats":
		if s.Miner == nil {
			resp.Result = nil
			break
		}
		st := s.Miner.Stats()
		out := map[string]any{
			"state":        int(st.State),
			"hashes":       st.Hashes,
			"elapsed":      st.Elapsed.Seconds(),
			"hashesps":     st.HashesPS,
			"blocks_found": st.BlocksFound,
			"errors":       st.Errors,
			"last_error":   st.LastError,
		}
		if !st.LastErrorAt.IsZero() {
			out["last_error_at"] = st.LastErrorAt.UTC().Format(time.RFC3339)
		}
		resp.Result = out
	case "genesisinfo":
		s.genesisInfo(&resp)
	case "hasutxo":
		s.hasUTXO(&resp, req.Params)
	case "submittransaction":
		s.submitTransaction(&resp, req.Params)
	default:
		resp.Error = &jrpcErr{Code: CodeMethodNotFound, Message: fmt.Sprintf("unknown method %q", req.Method)}
	}
	if resp.Error != nil {
		switch resp.Error.Code {
		case CodeInvalidParams:
			status = http.StatusBadRequest
		case CodeInternal:
			status = http.StatusInternalServerError
		case CodeUnavailable, CodeTxRetry:
			status = http.StatusServiceUnavailable
		case CodeConflict:
			status = http.StatusConflict
		}
	}
	writeJSON(w, status, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// cors sends no CORS headers unless CORSOrigin is set: a browser page then
// cannot read any response, so no website can probe or drive a local node.
// With CORSOrigin set, exactly that origin (or "*" if that was configured) is
// allowed to call with Content-Type and Authorization.
func (s *Service) cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.CORSOrigin != "" {
			origin := r.Header.Get("Origin")
			if s.CORSOrigin == "*" || (origin != "" && origin == s.CORSOrigin) {
				w.Header().Set("Access-Control-Allow-Origin", s.CORSOrigin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Max-Age", "600")
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

var rewardLabelOK = func(l string) bool {
	if l == "" || len(l) > 64 {
		return false
	}
	for _, c := range l {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// startMining takes [threads] or [threads, rewardLabel]: threads an integer
// 1..min(NumCPU, 16), the label 1..64 characters of [A-Za-z0-9._-]. Anything
// else, including extra parameters, is rejected.
func (s *Service) startMining(resp *jrpcResp, params []interface{}) {
	if s.Miner == nil {
		resp.Error = &jrpcErr{Code: CodeUnavailable, Message: "miner not configured"}
		return
	}
	if len(params) > 2 {
		resp.Error = &jrpcErr{Code: CodeInvalidParams, Message: "expected [threads] or [threads, rewardLabel]"}
		return
	}
	max := runtime.NumCPU()
	if max > maxMiningThreads {
		max = maxMiningThreads
	}
	threads, rewardTo := 1, "noso"
	if len(params) >= 1 {
		num, ok := params[0].(json.Number)
		n, err := strconv.ParseUint(string(num), 10, 64)
		if !ok || err != nil || n < 1 || n > uint64(max) {
			resp.Error = &jrpcErr{Code: CodeInvalidParams, Message: fmt.Sprintf("threads must be an integer between 1 and %d", max)}
			return
		}
		threads = int(n)
	}
	if len(params) == 2 {
		l, ok := params[1].(string)
		if !ok || !rewardLabelOK(l) {
			resp.Error = &jrpcErr{Code: CodeInvalidParams, Message: "reward label must be 1-64 characters of A-Z a-z 0-9 . _ -"}
			return
		}
		rewardTo = l
	}
	if s.DaemonContext == nil {
		resp.Error = &jrpcErr{Code: CodeUnavailable, Message: "daemon context unavailable"}
		return
	}
	if err := s.Miner.Start(s.DaemonContext, threads, rewardTo); err != nil {
		if errors.Is(err, miner.ErrAlreadyMining) {
			resp.Error = &jrpcErr{Code: CodeConflict, Message: "miner already running"}
			return
		}
		resp.Error = s.internal("startmining", err)
		return
	}
	resp.Result = "mining"
}

// genesisInfo reports the chain's own genesis (its real network magic), falling
// back to the configured genesis when no chain is attached.
func (s *Service) genesisInfo(resp *jrpcResp) {
	if s.Chain != nil {
		if g, ok := s.Chain.HeaderByHeight(0); ok {
			resp.Result = map[string]any{
				"genesis_hash": types.HeaderID(&g).String(),
				"difficulty":   g.Difficulty,
				"network":      g.NetworkMagic,
			}
			return
		}
	}
	stats, err := genesis.Summarize(s.genesisCfgOrDefault())
	if err != nil {
		resp.Error = s.internal("genesisinfo", err)
		return
	}
	resp.Result = map[string]any{
		"genesis_hash": stats.GenesisHash.String(),
		"difficulty":   stats.Difficulty,
		"network":      stats.NetworkMagic,
	}
}

// HeightFromParam decodes a JSON-RPC param into a uint64.
func HeightFromParam(p interface{}) (uint64, error) {
	switch v := p.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v >= math.Exp2(64) || math.Trunc(v) != v {
			return 0, fmt.Errorf("rpc: invalid height")
		}
		return uint64(v), nil
	case json.Number:
		return strconv.ParseUint(string(v), 10, 64)
	case string:
		return strconv.ParseUint(v, 10, 64)
	default:
		return 0, fmt.Errorf("rpc: bad height param type %T", p)
	}
}
