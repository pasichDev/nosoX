// Package rpc exposes a JSON-RPC 2.0 HTTP API for v2. Same JSON-RPC
// shape as v1's mprpc.pas so old explorers can be retargeted with
// minimal changes.
package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/noso-project/noso-go/v2/chain"
	"github.com/noso-project/noso-go/v2/genesis"
	"github.com/noso-project/noso-go/v2/mempool"
	"github.com/noso-project/noso-go/v2/miner"
	"github.com/noso-project/noso-go/v2/types"
)

// Service bundles the dependencies for the RPC handlers.
//
// DaemonContext MUST be a long-lived context owned by the daemon, NOT a
// per-request context. The miner uses it as the parent for its workers;
// using the HTTP request's context would cancel mining as soon as the
// RPC response is sent.
type Service struct {
	Chain         *chain.Chain
	Mempool       *mempool.Pool
	Miner         *miner.Miner
	Version       string
	DaemonContext context.Context
	// GenesisConfig is captured at daemon boot so RPC endpoints can
	// recompute the GVT list deterministically with the same paths the
	// chain itself used. nil → genesis.Default() (empty inheritance).
	GenesisConfig *genesis.Config

	// Token enables Bearer auth on every endpoint except /health.
	// Empty token means "no auth" — only safe when bound to 127.0.0.1.
	// The daemon logs a loud warning when starting without a token on
	// a non-loopback bind.
	Token string

	// PublicMethods is the set of JSON-RPC method names that bypass the
	// auth check even when Token is set. Useful for letting an explorer
	// hit read-only endpoints without sharing the admin token.
	PublicMethods map[string]bool
}

// HTTPHandler returns an http.Handler that dispatches JSON-RPC 2.0 calls.
func (s *Service) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.jsonRPC)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	return cors(mux)
}

// DefaultPublicMethods is the read-only allow-list shipped with the
// daemon. Methods here can be called without the auth token. Anything
// that mutates state (startmining, restart, submitorder) is excluded.
var DefaultPublicMethods = map[string]bool{
	"tip":               true,
	"getmainnetinfo":    true,
	"getblock":          true,
	"legacybalance":     true,
	"pending":           true,
	"minerstats":        true,
	"genesisinfo":       true,
	"version":           true,
}

// authorize returns true if the request carries a valid token or the
// requested method is on the public allow-list. Constant-time compare
// so a probing attacker can't time the token.
func (s *Service) authorize(r *http.Request, method string) bool {
	if s.Token == "" {
		return true // dev mode
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
	got := authz[len(prefix):]
	return subtleConstantTimeEq(got, s.Token)
}

func subtleConstantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// gvtCfgOrDefault returns the captured genesis config, or Default() if
// the daemon didn't set one (rare; happens in test scaffolds).
func (s *Service) gvtCfgOrDefault() genesis.Config {
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

type jrpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Service) jsonRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, jrpcResp{JSONRPC: "2.0",
			Error: &jrpcErr{Code: 400, Message: "POST required"}})
		return
	}
	var req jrpcReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, jrpcResp{JSONRPC: "2.0", ID: req.ID,
			Error: &jrpcErr{Code: 401, Message: "Invalid JSON request"}})
		return
	}
	if !s.authorize(r, req.Method) {
		writeJSON(w, http.StatusUnauthorized, jrpcResp{JSONRPC: "2.0", ID: req.ID,
			Error: &jrpcErr{Code: 498, Message: "Not authorized"}})
		return
	}
	resp := jrpcResp{JSONRPC: "2.0", ID: req.ID}
	switch strings.ToLower(req.Method) {
	case "version":
		resp.Result = s.Version
	case "tip", "getmainnetinfo":
		t, ok := s.Chain.Tip()
		resp.Result = map[string]any{
			"valid":       ok,
			"height":      t.Height,
			"hash":        types.HeaderID(&t).String(),
			"difficulty":  t.Difficulty,
			"timestamp":   t.Timestamp,
			"pending":     s.Mempool.Len(),
		}
	case "getblock":
		if len(req.Params) < 1 {
			resp.Error = &jrpcErr{Code: 400, Message: "missing param"}
			break
		}
		h, _ := req.Params[0].(float64)
		hdr, ok := s.Chain.HeaderByHeight(uint64(h))
		if !ok {
			resp.Error = &jrpcErr{Code: 404, Message: "block not found"}
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
	case "legacybalance":
		if len(req.Params) < 1 {
			resp.Error = &jrpcErr{Code: 400, Message: "missing address"}
			break
		}
		addr, _ := req.Params[0].(string)
		bal, ok := s.Chain.LookupLegacyBalance(addr)
		resp.Result = map[string]any{
			"address":  addr,
			"balance":  bal,
			"claimed":  !ok && bal == 0,
			"unspent":  ok,
		}
	case "pending":
		resp.Result = s.Mempool.Len()
	case "startmining":
		if s.Miner == nil {
			resp.Error = &jrpcErr{Code: 500, Message: "miner not configured"}
			break
		}
		threads := 1
		rewardTo := "noso"
		if len(req.Params) >= 1 {
			if n, ok := req.Params[0].(float64); ok {
				threads = int(n)
			}
		}
		if len(req.Params) >= 2 {
			if r, ok := req.Params[1].(string); ok {
				rewardTo = r
			}
		}
		minerCtx := s.DaemonContext
		if minerCtx == nil {
			minerCtx = context.Background() // safe fallback; never the HTTP request ctx
		}
		if err := s.Miner.Start(minerCtx, threads, rewardTo); err != nil {
			resp.Error = &jrpcErr{Code: 500, Message: err.Error()}
			break
		}
		resp.Result = "mining"
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
		resp.Result = map[string]any{
			"state":     int(st.State),
			"hashes":    st.Hashes,
			"elapsed":   st.Elapsed.Seconds(),
			"hashesps":  st.HashesPS,
		}
	case "genesisinfo":
		// Quick read of canonical genesis stats (re-derived from cfg).
		stats, err := genesis.Summarize(genesis.Default())
		if err != nil {
			resp.Error = &jrpcErr{Code: 500, Message: err.Error()}
			break
		}
		resp.Result = map[string]any{
			"legacy_accounts": stats.LegacyAccounts,
			"legacy_gvts":     stats.LegacyGVTs,
			"total_carried":   stats.TotalCarried,
			"gvt_value":       stats.GVTValue,
			"genesis_hash":    stats.GenesisHash.String(),
			"difficulty":      stats.Difficulty,
		}
	case "gvtlist":
		// Iterate genesis-bundler output and return list of all 100 GVTs
		// with their owners. UTXOs that have been spent are flagged.
		stats, err := genesis.Summarize(s.gvtCfgOrDefault())
		if err != nil {
			resp.Error = &jrpcErr{Code: 500, Message: err.Error()}
			break
		}
		_ = stats
		_, _, gvts, err := genesis.Build(s.gvtCfgOrDefault())
		if err != nil {
			resp.Error = &jrpcErr{Code: 500, Message: err.Error()}
			break
		}
		out := make([]map[string]any, 0, len(gvts))
		for _, g := range gvts {
			// Check whether this GVT is still in the UTXO set.
			unspent := s.Chain.HasUTXOByCommitWrap(g.Commit)
			out = append(out, map[string]any{
				"slot":    g.GVTNumber,
				"owner":   g.LegacyAddress,
				"unspent": unspent,
			})
		}
		resp.Result = out
	case "gvtowner":
		if len(req.Params) < 1 {
			resp.Error = &jrpcErr{Code: 400, Message: "missing slot"}
			break
		}
		slot := 0
		if v, ok := req.Params[0].(float64); ok {
			slot = int(v)
		}
		_, _, gvts, err := genesis.Build(s.gvtCfgOrDefault())
		if err != nil {
			resp.Error = &jrpcErr{Code: 500, Message: err.Error()}
			break
		}
		for _, g := range gvts {
			if int(g.GVTNumber) == slot {
				resp.Result = map[string]any{
					"slot":    slot,
					"address": g.LegacyAddress,
					"unspent": s.Chain.HasUTXOByCommitWrap(g.Commit),
				}
				break
			}
		}
		if resp.Result == nil {
			resp.Error = &jrpcErr{Code: 404, Message: "GVT slot not found in genesis"}
		}
	default:
		resp.Error = &jrpcErr{Code: 402, Message: fmt.Sprintf("unknown method %q", req.Method)}
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// cors adds permissive headers so a browser-based explorer or remote wallet
// can call the API cross-origin. Authorization MUST be in Allow-Headers,
// otherwise a browser's preflight rejects authenticated (Bearer-token) calls
// to a remote node — the exact "connect from outside over RPC" case.
func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// HeightFromParam decodes a JSON-RPC param into a uint64.
func HeightFromParam(p interface{}) (uint64, error) {
	switch v := p.(type) {
	case float64:
		return uint64(v), nil
	case string:
		return strconv.ParseUint(v, 10, 64)
	default:
		return 0, fmt.Errorf("rpc: bad height param type %T", p)
	}
}
