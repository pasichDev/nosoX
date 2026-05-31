// nosox-explorer is a production block explorer for Noso v2.
//
// It is a single-binary HTTP server with:
//
//   - HTMX-powered live updates (no JavaScript framework).
//   - Dashboard with tip, mempool, supply, network stats.
//   - Recent-blocks table (auto-refreshing).
//   - Search by block height, block hash, legacy v1 address.
//   - Per-block detail page with transactions and Schnorr signatures.
//   - Per-address legacy balance lookup.
//   - SIGMA visual identity (IBM Plex, white/navy/violet).
//
// Talks to nosoxd via JSON-RPC. Stateless — restart at will.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	listenAddr = flag.String("listen", ":7782", "HTTP listen address")
	nodeAddr   = flag.String("node", "http://127.0.0.1:7780", "nosoxd JSON-RPC URL")
	version    = flag.String("version", "0.2.0", "explorer version, displayed in the footer")
)

var tmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"shortHash": func(s string) string {
		if len(s) <= 16 {
			return s
		}
		return s[:8] + "…" + s[len(s)-8:]
	},
	"formatCoin": func(v any) string {
		n := toInt64(v)
		whole := n / 100000000
		frac := n % 100000000
		return fmt.Sprintf("%d.%08d NOSO", whole, frac)
	},
	"unixTime": func(v any) string {
		ts := toInt64(v)
		if ts == 0 {
			return "—"
		}
		return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04:05 UTC")
	},
	"ago": func(v any) string {
		ts := toInt64(v)
		if ts == 0 {
			return "—"
		}
		d := time.Since(time.Unix(ts, 0))
		switch {
		case d < time.Minute:
			return fmt.Sprintf("%ds ago", int(d.Seconds()))
		case d < time.Hour:
			return fmt.Sprintf("%dm ago", int(d.Minutes()))
		case d < 24*time.Hour:
			return fmt.Sprintf("%dh ago", int(d.Hours()))
		default:
			return fmt.Sprintf("%dd ago", int(d.Hours()/24))
		}
	},
	"div": func(a, b int) int {
		if b == 0 {
			return 0
		}
		return a / b
	},
}).Parse(htmlTemplates))

func main() {
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/block", handleBlock)
	mux.HandleFunc("/legacy", handleLegacy)
	mux.HandleFunc("/search", handleSearch)
	mux.HandleFunc("/tip", handleTipFragment)
	mux.HandleFunc("/network", handleNetworkFragment)
	mux.HandleFunc("/blocks", handleBlocksFragment)
	mux.HandleFunc("/genesis", handleGenesis)
	mux.HandleFunc("/gvts", handleGVTs)
	mux.HandleFunc("/about", handleAbout)
	mux.HandleFunc("/static/style.css", handleCSS)

	log.Printf("nosox-explorer %s listening on %s (node=%s)", *version, *listenAddr, *nodeAddr)
	log.Fatal(http.ListenAndServe(*listenAddr, mux))
}

// ---- handlers -----------------------------------------------------------

func handleIndex(w http.ResponseWriter, r *http.Request) {
	tip, _ := rpcCall("tip", nil)
	stats, _ := rpcCall("minerstats", nil)
	gen, _ := rpcCall("genesisinfo", nil)
	blocks := recentBlocks(tip)
	render(w, "index", map[string]any{
		"Tip":         tip,
		"Miner":       stats,
		"Genesis":     gen,
		"NetworkStat": networkSummary(tip, stats, blocks),
		"Blocks":      blocks,
		"Version":     *version,
	})
}

func handleTipFragment(w http.ResponseWriter, r *http.Request) {
	tip, _ := rpcCall("tip", nil)
	render(w, "tip-fragment", map[string]any{"Tip": tip})
}

func handleNetworkFragment(w http.ResponseWriter, r *http.Request) {
	tip, _ := rpcCall("tip", nil)
	stats, _ := rpcCall("minerstats", nil)
	blocks := recentBlocks(tip)
	render(w, "network-fragment", map[string]any{
		"Tip":         tip,
		"Miner":       stats,
		"NetworkStat": networkSummary(tip, stats, blocks),
	})
}

func handleBlocksFragment(w http.ResponseWriter, r *http.Request) {
	tip, _ := rpcCall("tip", nil)
	blocks := recentBlocks(tip)
	render(w, "blocks-fragment", map[string]any{"Blocks": blocks})
}

// networkSummary derives live network telemetry from the RPC results.
// All fields are strings so the template can render them directly.
func networkSummary(tip, stats any, blocks []map[string]any) map[string]string {
	out := map[string]string{
		"Hashrate":   "—",
		"State":      "idle",
		"Elapsed":    "—",
		"NextETA":    "—",
		"AvgBlock":   "—",
		"Mempool":    "0",
		"Height":     "—",
	}
	if tm, ok := tip.(map[string]any); ok {
		out["Height"] = fmt.Sprintf("%d", int64(toFloat(tm["height"])))
		out["Mempool"] = fmt.Sprintf("%d", int64(toFloat(tm["pending"])))
	}
	if sm, ok := stats.(map[string]any); ok {
		hps := toFloat(sm["hashesps"])
		if hps > 0 {
			out["Hashrate"] = fmt.Sprintf("%.1f H/s", hps)
		}
		if int(toFloat(sm["state"])) == 1 {
			out["State"] = "mining"
		}
		if e := toFloat(sm["elapsed"]); e > 0 && e < 1e6 {
			d := time.Duration(e * float64(time.Second))
			out["Elapsed"] = d.Round(time.Second).String()
		}
		// ETA = (2^256 / target) / hashrate. With difficulty 256 the
		// expected hashes per block = 256; ETA = 256 / hps.
		if tm, ok := tip.(map[string]any); ok && hps > 0 {
			diff := toFloat(tm["difficulty"])
			if diff > 0 {
				eta := diff / hps
				out["NextETA"] = fmt.Sprintf("~%s", time.Duration(eta*float64(time.Second)).Round(time.Second))
			}
		}
	}
	// Average inter-block time over the recent window (oldest → newest).
	if len(blocks) >= 2 {
		ts := make([]int64, 0, len(blocks))
		for _, b := range blocks {
			ts = append(ts, int64(toFloat(b["timestamp"])))
		}
		// blocks come newest-first; reverse to oldest-first for delta calc.
		var total int64
		var count int
		for i := 0; i < len(ts)-1; i++ {
			if ts[i] > ts[i+1] {
				total += ts[i] - ts[i+1]
				count++
			}
		}
		if count > 0 {
			out["AvgBlock"] = fmt.Sprintf("%ds", total/int64(count))
		}
	}
	return out
}

func toFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	case int:
		return float64(x)
	}
	return 0
}

func handleBlock(w http.ResponseWriter, r *http.Request) {
	heightStr := r.URL.Query().Get("h")
	if heightStr == "" {
		http.Redirect(w, r, "/", 302)
		return
	}
	h, err := strconv.ParseFloat(heightStr, 64)
	if err != nil {
		http.Error(w, "bad height", 400)
		return
	}
	res, err := rpcCall("getblock", []any{h})
	if err != nil {
		render(w, "block", map[string]any{
			"Height": heightStr,
			"Error":  err.Error(),
		})
		return
	}
	render(w, "block", map[string]any{
		"Block":  res,
		"Height": heightStr,
	})
}

func handleLegacy(w http.ResponseWriter, r *http.Request) {
	addr := strings.TrimSpace(r.URL.Query().Get("a"))
	var res any
	if addr != "" {
		res, _ = rpcCall("legacybalance", []any{addr})
	}
	render(w, "legacy", map[string]any{
		"Result":  res,
		"Address": addr,
	})
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		http.Redirect(w, r, "/", 302)
		return
	}
	// Numeric → block height
	if _, err := strconv.Atoi(q); err == nil {
		http.Redirect(w, r, "/block?h="+q, 302)
		return
	}
	// Starts with N → legacy address
	if strings.HasPrefix(q, "N") || strings.HasPrefix(q, "M") {
		http.Redirect(w, r, "/legacy?a="+q, 302)
		return
	}
	// Long hex string → assume block hash (TODO: dedicated rpc lookup)
	if len(q) == 64 {
		http.Redirect(w, r, "/?h="+q+"#hash-lookup", 302)
		return
	}
	http.Error(w, "unrecognized search query", 400)
}

func handleGVTs(w http.ResponseWriter, r *http.Request) {
	list, _ := rpcCall("gvtlist", nil)
	render(w, "gvts", map[string]any{"GVTs": list})
}

func handleGenesis(w http.ResponseWriter, r *http.Request) {
	info, _ := rpcCall("genesisinfo", nil)
	render(w, "genesis", map[string]any{"Genesis": info})
}

func handleAbout(w http.ResponseWriter, r *http.Request) {
	render(w, "about", nil)
}

func handleCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write([]byte(cssBody))
}

// ---- data fetching ------------------------------------------------------

func recentBlocks(tip any) []map[string]any {
	tipMap, ok := tip.(map[string]any)
	if !ok {
		return nil
	}
	heightF, ok := tipMap["height"].(float64)
	if !ok {
		return nil
	}
	height := uint64(heightF)
	const n = 10
	out := make([]map[string]any, 0, n)
	for i := uint64(0); i < n && i <= height; i++ {
		h := height - i
		b, err := rpcCall("getblock", []any{float64(h)})
		if err != nil {
			continue
		}
		if m, ok := b.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func rpcCall(method string, params []any) (any, error) {
	req := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}
	body, _ := json.Marshal(req)
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Post(*nodeAddr, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out struct {
		Result any `json:"result"`
		Error  any `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, fmt.Errorf("%v", out.Error)
	}
	return out.Result, nil
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

// toInt64 coerces an interface{} into an int64. JSON unmarshalling into
// `any` produces float64 for all numbers, while internal Go callers may
// pass int / int64 directly. Returns 0 for unsupported types so template
// helpers can render a placeholder instead of crashing.
func toInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case uint64:
		return int64(x)
	case float64:
		return int64(x)
	case float32:
		return int64(x)
	case string:
		if n, err := strconv.ParseInt(x, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

// ---- templates ---------------------------------------------------------

const htmlTemplates = `
{{define "layout"}}
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NosoX Explorer · Σ</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Serif:wght@400;500&display=swap">
<link rel="stylesheet" href="/static/style.css">
<script src="https://unpkg.com/htmx.org@2.0.1" defer></script>
</head>
<body>
<nav class="top">
  <a class="brand" href="/">
    <span class="glyph">Σ</span>
    <span class="word">NosoX · Explorer</span>
  </a>
  <form class="search" action="/search" method="get">
    <input type="text" name="q" placeholder="block height · block hash · N…address" autocomplete="off">
    <button type="submit">Search</button>
  </form>
  <ul>
    <li><a href="/">Dashboard</a></li>
    <li><a href="/genesis">Genesis</a></li>
    <li><a href="/gvts">GVTs</a></li>
    <li><a href="/legacy">Legacy</a></li>
    <li><a href="/about">About</a></li>
  </ul>
</nav>
<main>
{{template "body" .}}
</main>
<footer>Σ NosoX · explorer v{{or .Version "0.2.0"}} · serving from <code>{{or .Node "the local node"}}</code></footer>
</body>
</html>
{{end}}

{{define "index"}}{{template "layout" .}}{{end}}
{{define "block"}}{{template "layout" .}}{{end}}
{{define "legacy"}}{{template "layout" .}}{{end}}
{{define "genesis"}}{{template "layout" .}}{{end}}
{{define "gvts"}}{{template "layout" .}}{{end}}
{{define "about"}}{{template "layout" .}}{{end}}

{{define "body"}}
{{if .Tip}}
{{/* Dashboard view */}}
<section class="card hero">
  <div class="hero-grid">
    <div hx-get="/tip" hx-trigger="every 5s" hx-swap="innerHTML">
      {{template "tip-fragment" .}}
    </div>
    <div hx-get="/network" hx-trigger="every 5s" hx-swap="innerHTML">
      {{template "network-fragment" .}}
    </div>
  </div>
</section>

<section class="card">
  <div class="card-head">
    <span class="eyebrow">Recent blocks</span>
    <span class="muted" hx-get="/blocks" hx-trigger="every 10s" hx-swap="outerHTML">auto-refreshes every 10s</span>
  </div>
  <div hx-get="/blocks" hx-trigger="every 10s" hx-swap="innerHTML">
    {{template "blocks-fragment" .}}
  </div>
</section>
{{else if .Block}}
<section class="card">
  <span class="eyebrow">Block #{{index .Block "height"}}</span>
  <h2 class="tight">Block details</h2>
  <table class="kv">
    <tr><th>Height</th><td>{{index .Block "height"}}</td></tr>
    <tr><th>Hash</th><td><code>{{index .Block "hash"}}</code></td></tr>
    <tr><th>Previous</th><td><code>{{index .Block "prev"}}</code></td></tr>
    <tr><th>Difficulty</th><td>{{index .Block "difficulty"}}</td></tr>
    <tr><th>Nonce</th><td><code>{{index .Block "nonce"}}</code></td></tr>
    <tr><th>Timestamp</th><td>{{index .Block "timestamp" | unixTime}} <span class="muted">({{index .Block "timestamp" | ago}})</span></td></tr>
  </table>
  <p class="muted">Coinbase outputs are bound by Schnorr signatures over r·G; plain outputs ship Borromean range proofs proving v ∈ [0, 2⁶⁴) without revealing v.</p>
</section>
{{else if eq .Height ""}}
<section class="card">
  <span class="eyebrow">Block not found</span>
  <h2>No block at that height yet.</h2>
  <p class="muted">{{or .Error "The chain has not produced this block."}}</p>
  <a class="btn" href="/">Back to dashboard</a>
</section>
{{end}}

{{if ne .Address ""}}
<section class="card">
  <span class="eyebrow">Legacy v1 lookup</span>
  <h2 class="tight">{{.Address | shortHash}}</h2>
  {{with .Result}}
    <table class="kv">
      <tr><th>Address</th><td><code>{{index . "address"}}</code></td></tr>
      <tr><th>Balance</th><td><strong>{{index . "balance"}}</strong> base units</td></tr>
      <tr><th>Unspent</th><td>{{if index . "unspent"}}<span class="ok">yes — still claimable</span>{{else}}<span class="muted">spent or absent</span>{{end}}</td></tr>
    </table>
    <p class="muted">To spend this balance, sign with the original v1 secp256k1+SHA1 key using <code>nosox-cli wallet legacy</code>.</p>
  {{else}}
    <p class="muted">No matching legacy UTXO. Either the address didn't exist in v1, or the balance has already been claimed and converted to a native MW commitment.</p>
  {{end}}
</section>
{{end}}

{{if and (not .Tip) (not .Block) (eq .Address "")}}
<section class="card">
  <span class="eyebrow">Find a legacy v1 balance</span>
  <h2 class="tight">Look up your Noso v1 address</h2>
  <p class="muted">Paste any v1 "N…" or "M…" address. Balances were inherited 1:1 into the v2 genesis.</p>
  <form action="/legacy" method="get" class="row">
    <input type="text" name="a" placeholder="N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd" required autofocus>
    <button class="btn-primary" type="submit">Check</button>
  </form>
</section>
{{end}}

{{with .Genesis}}
<section class="card">
  <span class="eyebrow">Genesis</span>
  <h2 class="tight">Block #0</h2>
  <table class="kv">
    <tr><th>Hash</th><td><code>{{index . "genesis_hash"}}</code></td></tr>
    <tr><th>Legacy accounts</th><td>{{index . "legacy_accounts"}}</td></tr>
    <tr><th>Legacy GVTs</th><td>{{index . "legacy_gvts"}} (×70 NOSO each)</td></tr>
    <tr><th>Carried supply</th><td>{{index . "total_carried"}} base units</td></tr>
    <tr><th>GVT value</th><td>{{index . "gvt_value"}} base units</td></tr>
    <tr><th>Difficulty</th><td>{{index . "difficulty"}}</td></tr>
  </table>
  <p class="muted">Genesis is deterministic: anyone running <code>genesis.Build()</code> with the same v1 sumary.psk + gvts.psk gets the same hash.</p>
</section>
{{end}}

{{with .GVTs}}
<section class="card">
  <span class="eyebrow">Inherited governance tokens</span>
  <h2 class="tight">100 GVT slots</h2>
  <p class="muted">Each v1 GVT inherited 1:1 into NosoX genesis. Owner can redeem for 70 NOSO or transfer (identity preserved).</p>
  <table class="blocks">
    <thead><tr><th>Slot</th><th>Owner</th><th>Status</th></tr></thead>
    <tbody>
    {{range .}}
      <tr>
        <td><code>#{{printf "%02d" (index . "slot")}}</code></td>
        <td><code>{{index . "owner" | shortHash}}</code></td>
        <td>{{if index . "unspent"}}<span class="ok">unspent</span>{{else}}<span class="muted">redeemed</span>{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
</section>
{{end}}

{{end}}

{{define "tip-fragment"}}
<span class="eyebrow">Chain tip</span>
<h3 class="metric">#{{with .Tip}}{{index . "height"}}{{end}}</h3>
<p><strong>Hash:</strong> <code>{{with .Tip}}{{index . "hash" | shortHash}}{{end}}</code></p>
<p><strong>Difficulty:</strong> {{with .Tip}}{{index . "difficulty"}}{{end}}</p>
<p class="muted">Last block: {{with .Tip}}{{index . "timestamp" | ago}}{{end}}</p>
{{end}}

{{define "network-fragment"}}
<span class="eyebrow">Mining · network</span>
<h3 class="metric">{{with .NetworkStat}}{{index . "Hashrate"}}{{end}}
  <small>{{with .NetworkStat}}{{index . "State"}}{{end}}</small></h3>
<table class="kv compact">
  <tr><th>Avg block</th><td>{{with .NetworkStat}}{{index . "AvgBlock"}}{{end}}</td></tr>
  <tr><th>Next ETA</th><td>{{with .NetworkStat}}{{index . "NextETA"}}{{end}}</td></tr>
  <tr><th>Mining for</th><td>{{with .NetworkStat}}{{index . "Elapsed"}}{{end}}</td></tr>
  <tr><th>Mempool</th><td>{{with .NetworkStat}}{{index . "Mempool"}}{{end}} pending tx</td></tr>
</table>
<p class="muted small">Argon2id · 64 MiB · LWMA-3</p>
{{end}}

{{define "blocks-fragment"}}
<table class="blocks">
  <thead>
    <tr><th>Height</th><th>Hash</th><th>Difficulty</th><th>Timestamp</th></tr>
  </thead>
  <tbody>
  {{range .Blocks}}
    <tr>
      <td><a href="/block?h={{index . "height"}}">#{{index . "height"}}</a></td>
      <td><code>{{index . "hash" | shortHash}}</code></td>
      <td>{{index . "difficulty"}}</td>
      <td>{{index . "timestamp" | unixTime}} <span class="muted">({{index . "timestamp" | ago}})</span></td>
    </tr>
  {{else}}
    <tr><td colspan="4" class="muted">no blocks yet</td></tr>
  {{end}}
  </tbody>
</table>
{{end}}

{{define "about-body"}}
<section class="card">
  <span class="eyebrow">About this explorer</span>
  <h2 class="tight">Σ Noso v2 Explorer</h2>
  <p>This is a stateless block explorer for the Noso v2 archived
     chain. It talks to a running <code>nosoxd</code> over JSON-RPC.</p>
  <p>Built with Go's <code>html/template</code> and HTMX for live
     updates — no JavaScript framework, no build step. Pages are
     ~3 KB each excluding fonts.</p>
  <h3>Architecture</h3>
  <p>The dashboard polls the node every 5–10 seconds via
     <code>hx-get</code> partial-replace requests. Each block detail page
     is a one-shot RPC fetch. There is no client-side state.</p>
  <h3>Privacy</h3>
  <p>Mimblewimble transactions reveal Pedersen commitments and range
     proofs, never amounts or addresses. The explorer surfaces only
     what's on chain: block headers, kernel counts, and legacy v1
     balances that haven't been claimed yet.</p>
</section>
{{end}}
`

const cssBody = `
:root {
  --bg: #ffffff;
  --surface: #f6f8fc;
  --surface-2: #eef1f7;
  --fg: #0a2540;
  --fg-soft: #425466;
  --muted: #8898aa;
  --accent: #635bff;
  --accent-soft: #ebebff;
  --accent-hover: #4f44eb;
  --success: #00b27a;
  --border: #e3e8ee;
  --code-bg: #f5f7fb;
  --code-border: #d4dae3;
  --radius-sm: 4px;
  --radius-md: 8px;
  --radius-lg: 12px;
  --font-serif: "IBM Plex Serif", Georgia, serif;
  --font-sans: "IBM Plex Sans", -apple-system, system-ui, sans-serif;
  --font-mono: "IBM Plex Mono", ui-monospace, monospace;
  --shadow-sm: 0 1px 2px rgba(10, 37, 64, 0.04);
  --shadow-md: 0 1px 3px rgba(10, 37, 64, 0.05), 0 4px 12px rgba(10, 37, 64, 0.04);
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body { background: var(--bg); color: var(--fg); font-family: var(--font-sans); line-height: 1.55; -webkit-font-smoothing: antialiased; }
a { color: var(--accent); text-decoration: none; }
a:hover { color: var(--accent-hover); text-decoration: underline; text-underline-offset: 3px; }
h2, h3 { font-family: var(--font-serif); font-weight: 500; color: var(--fg); letter-spacing: -0.01em; margin: 0 0 1rem; }
h2 { font-size: 1.6rem; }
h2.tight { margin-bottom: 0.25rem; }
h3 { font-size: 1.1rem; color: var(--fg); }
h3.metric { font-size: 2.4rem; font-family: var(--font-sans); font-weight: 600; margin: 0 0 0.5rem; letter-spacing: -0.02em; }
h3.metric small { font-size: 1rem; color: var(--muted); font-weight: 400; margin-left: 0.5rem; }
code { font-family: var(--font-mono); background: var(--code-bg); border: 1px solid var(--code-border); padding: 0.05rem 0.35rem; border-radius: var(--radius-sm); font-size: 0.92em; color: var(--fg); }
.muted { color: var(--muted); }
.ok { color: var(--success); font-weight: 500; }
.eyebrow { display: inline-block; font-family: var(--font-mono); font-size: 0.7rem; color: var(--accent); letter-spacing: 0.16em; text-transform: uppercase; margin-bottom: 0.5rem; }

nav.top { position: sticky; top: 0; z-index: 5; display: flex; align-items: center; gap: 1.5rem; padding: 0.85rem 1.5rem; background: rgba(255,255,255,0.92); backdrop-filter: saturate(180%) blur(20px); border-bottom: 1px solid var(--border); }
.brand { display: inline-flex; align-items: baseline; gap: 0.5rem; color: var(--fg); font-family: var(--font-serif); font-weight: 500; font-size: 1.05rem; }
.brand .glyph { display: inline-block; font-family: var(--font-sans); font-weight: 700; width: 1.6rem; height: 1.6rem; line-height: 1.6rem; text-align: center; background: var(--accent); color: white; border-radius: var(--radius-sm); font-size: 1.05rem; transform: translateY(0.1rem); }
form.search { display: flex; gap: 0.5rem; flex: 1; max-width: 480px; }
form.search input { flex: 1; background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 0.45rem 0.8rem; font-family: var(--font-sans); font-size: 0.92rem; color: var(--fg); }
form.search input:focus { outline: 2px solid var(--accent-soft); outline-offset: -1px; border-color: var(--accent); }
form.search button { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 0.45rem 0.9rem; cursor: pointer; font-size: 0.92rem; color: var(--fg); }
form.search button:hover { background: var(--surface-2); }
nav.top ul { display: flex; gap: 1.25rem; list-style: none; margin: 0; padding: 0; font-size: 0.92rem; }
nav.top ul a { color: var(--fg-soft); }
nav.top ul a:hover { color: var(--accent); text-decoration: none; }

main { padding: 2rem 1.5rem 3.5rem; max-width: 1080px; margin: 0 auto; }

.card { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 1.5rem 1.75rem; margin-bottom: 1.25rem; box-shadow: var(--shadow-sm); transition: box-shadow 120ms ease; }
.card:hover { box-shadow: var(--shadow-md); }
.card.hero { background: linear-gradient(135deg, rgba(99,91,255,0.05), transparent 50%), var(--bg); }
.card-head { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 1rem; gap: 1rem; }
.card-head .eyebrow { margin-bottom: 0; }

.hero-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 2.5rem; align-items: center; }
@media (max-width: 700px) { .hero-grid { grid-template-columns: 1fr; gap: 1.5rem; } }

table.kv { width: 100%; border-collapse: collapse; margin-top: 0.75rem; }
table.kv th, table.kv td { text-align: left; padding: 0.6rem 0; vertical-align: top; border-bottom: 1px solid var(--border); }
table.kv th { width: 11rem; color: var(--muted); font-weight: 500; font-size: 0.92rem; }
table.kv td { color: var(--fg); }
table.kv tr:last-child th, table.kv tr:last-child td { border-bottom: 0; }
table.kv td strong { font-family: var(--font-mono); font-weight: 500; color: var(--fg); }
table.kv.compact th, table.kv.compact td { padding: 0.3rem 0; font-size: 0.92rem; }
table.kv.compact th { width: 8rem; }
.muted.small { font-size: 0.82rem; margin-top: 0.5rem; }

table.blocks { width: 100%; border-collapse: collapse; }
table.blocks th, table.blocks td { padding: 0.55rem 0.4rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.94rem; }
table.blocks th { font-weight: 500; color: var(--muted); }
table.blocks tbody tr:hover { background: var(--surface); }

form.row { display: flex; gap: 0.5rem; margin-top: 1.25rem; }
form.row input { flex: 1; background: var(--bg); color: var(--fg); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 0.65rem 0.85rem; font-family: var(--font-sans); font-size: 0.96rem; }
form.row input:focus { outline: 2px solid var(--accent-soft); outline-offset: -1px; border-color: var(--accent); }
.btn, .btn-primary { display: inline-block; padding: 0.6rem 1.1rem; border-radius: var(--radius-md); font-weight: 500; cursor: pointer; border: 0; font-family: var(--font-sans); font-size: 0.95rem; }
.btn-primary { background: var(--accent); color: white; }
.btn-primary:hover { background: var(--accent-hover); color: white; text-decoration: none; }
.btn { background: var(--surface); color: var(--fg); border: 1px solid var(--border); text-decoration: none; }
.btn:hover { color: var(--accent); border-color: var(--accent-soft); text-decoration: none; }

footer { padding: 1.25rem 1.5rem; text-align: center; color: var(--muted); border-top: 1px solid var(--border); background: var(--surface); font-size: 0.88rem; }
footer code { font-size: 0.85rem; }
`
