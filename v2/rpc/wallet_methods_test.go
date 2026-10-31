package rpc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pasichDev/noso-go/v2/chain"
	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/genesis"
	"github.com/pasichDev/noso-go/v2/mempool"
	"github.com/pasichDev/noso-go/v2/pow"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

func call(t *testing.T, h http.Handler, body, token string) (int, jrpcResp) {
	t.Helper()
	resp := post(t, h, body, token)
	defer resp.Body.Close()
	var out jrpcResp
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestErrorCodesAndHTTPStatuses(t *testing.T) {
	h := (&Service{Token: "tok"}).HTTPHandler()
	huge := `{"jsonrpc":"2.0","method":"version","params":["` + strings.Repeat("a", maxRequestBytes) + `"],"id":1}`
	cases := []struct {
		name, body, token string
		status, code      int
	}{
		{"syntax error", `{not json`, "", 400, CodeParseError},
		{"truncated", `{"jsonrpc":"2.0","met`, "", 400, CodeParseError},
		{"empty body", ``, "", 400, CodeParseError},
		{"trailing json", `{"jsonrpc":"2.0","method":"version","id":1} {}`, "", 400, CodeParseError},
		{"array body", `[1,2,3]`, "", 400, CodeInvalidRequest},
		{"string body", `"x"`, "", 400, CodeInvalidRequest},
		{"params object", `{"jsonrpc":"2.0","method":"version","params":{"a":1},"id":1}`, "", 400, CodeInvalidRequest},
		{"wrong version", `{"jsonrpc":"1.0","method":"version","id":1}`, "", 400, CodeInvalidRequest},
		{"no method", `{"jsonrpc":"2.0","id":1}`, "", 400, CodeInvalidRequest},
		{"oversized", huge, "", 413, CodeInvalidRequest},
		{"unauthorized", `{"jsonrpc":"2.0","method":"startmining","id":1}`, "", 401, CodeUnauthorized},
		{"bad token", `{"jsonrpc":"2.0","method":"startmining","id":1}`, "nope", 401, CodeUnauthorized},
		{"unknown method", `{"jsonrpc":"2.0","method":"nope","id":1}`, "tok", 200, CodeMethodNotFound},
		{"missing param", `{"jsonrpc":"2.0","method":"getblock","params":[],"id":1}`, "", 400, CodeInvalidParams},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, resp := call(t, h, c.body, c.token)
			if status != c.status || resp.Error == nil || resp.Error.Code != c.code {
				t.Fatalf("status=%d error=%+v, want status %d code %d", status, resp.Error, c.status, c.code)
			}
			if c.code == CodeParseError || c.code == CodeInvalidRequest {
				if !strings.Contains(resp.Error.Message, "Invalid JSON") {
					t.Fatalf("message: %q", resp.Error.Message)
				}
			}
		})
	}
	// The legacy "401 inside HTTP 200" form must be gone.
	for _, c := range cases[:4] {
		if status, resp := call(t, h, c.body, ""); status == 200 || (resp.Error != nil && resp.Error.Code == 401) {
			t.Fatalf("%s: legacy error form", c.name)
		}
	}
}

func TestWalletMethodsAreNotPublic(t *testing.T) {
	for _, m := range []string{"submittransaction", "hasutxo", "startmining", "stopmining"} {
		if DefaultPublicMethods[m] {
			t.Errorf("%s must not be a public method", m)
		}
	}
	for _, token := range []string{"secret", ""} {
		s := &Service{Token: token}
		h := s.HTTPHandler()
		for _, m := range []string{"submittransaction", "hasutxo"} {
			body := `{"jsonrpc":"2.0","method":"` + m + `","params":["x"],"id":1}`
			if token != "" {
				if st, r := call(t, h, body, ""); st != 401 || r.Error.Code != CodeUnauthorized {
					t.Errorf("%s without token: %d %+v", m, st, r.Error)
				}
				if st, r := call(t, h, body, "wrong"); st != 401 {
					t.Errorf("%s with wrong token: %d %+v", m, st, r.Error)
				}
				if st, r := call(t, h, body, token); st == 401 {
					t.Errorf("%s with token refused: %+v", m, r.Error)
				}
			} else {
				// No token: loopback callers may use it, browsers (Origin) may not.
				req := httptest.NewRequest("POST", "/", strings.NewReader(body))
				req.Host = "127.0.0.1:7780"
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", "https://evil.example")
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != 401 {
					t.Errorf("%s from a browser origin without token: %d", m, rec.Code)
				}
			}
		}
	}
}

func TestSubmitTransactionRejectsMalformedInput(t *testing.T) {
	c := chain.NewMemory()
	g, _ := genesis.Build(genesis.Config{NetworkMagic: types.NetworkMagicTestnet, Timestamp: time.Now().Unix() - 600, InitialDifficulty: 1})
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	s := &Service{Chain: c, Mempool: mempool.NewValidated(16, c.ValidateTransaction)}
	h := s.HTTPHandler()
	valid := base64.StdEncoding.EncodeToString([]byte{1, 0, 0, 0})
	for name, params := range map[string]string{
		"no params":        `[]`,
		"two params":       `["a","b"]`,
		"not a string":     `[5]`,
		"object":           `[{"tx":"x"}]`,
		"empty":            `[""]`,
		"not base64":       `["!!!"]`,
		"padding trick":    `["AAAA\n"]`,
		"url alphabet":     `["__-_"]`,
		"truncated tx":     `["` + base64.StdEncoding.EncodeToString([]byte{1, 2}) + `"]`,
		"oversized string": `["` + strings.Repeat("A", base64.StdEncoding.EncodedLen(wallet.MaxEncodedTxBytes)+8) + `"]`,
	} {
		t.Run(name, func(t *testing.T) {
			status, resp := call(t, h, `{"jsonrpc":"2.0","method":"submittransaction","params":`+params+`,"id":1}`, "")
			if status != 400 || resp.Error == nil || resp.Error.Code != CodeInvalidParams {
				t.Fatalf("status=%d error=%+v", status, resp.Error)
			}
		})
	}
	// Well-formed encoding, invalid transaction: rejected by pool validation.
	st, resp := call(t, h, `{"jsonrpc":"2.0","method":"submittransaction","params":["`+valid+`"],"id":1}`, "")
	if st != 200 || resp.Error == nil || resp.Error.Code != CodeTxRejected {
		t.Fatalf("empty tx: %d %+v", st, resp.Error)
	}
	if s.Mempool.Len() != 0 {
		t.Fatal("malformed submission reached the mempool")
	}
	// Unavailable mempool.
	st, resp = call(t, (&Service{}).HTTPHandler(), `{"jsonrpc":"2.0","method":"submittransaction","params":["AAAA"],"id":1}`, "")
	if st != 503 || resp.Error.Code != CodeUnavailable {
		t.Fatalf("no mempool: %d %+v", st, resp.Error)
	}
}

// grindEmpty builds a coinbase-only block on parent at difficulty 1.
func grindEmpty(t *testing.T, parent types.BlockHeader, salt byte) *types.Block {
	t.Helper()
	h := types.BlockHeader{Version: types.BlockVersion, NetworkMagic: parent.NetworkMagic, Height: parent.Height + 1,
		Timestamp: parent.Timestamp + 1, PrevHash: types.HeaderID(&parent), Difficulty: parent.Difficulty}
	seed := append([]byte("rpc test coinbase"), h.PrevHash[:]...)
	seed = binary.BigEndian.AppendUint64(seed, h.Height)
	seed = append(seed, salt)
	blind := sha256.Sum256(seed)
	reward := types.BlockReward(h.Height)
	commit, err := v2crypto.PedersenCommit(reward, blind[:])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wallet.SignCoinbase(h.NetworkMagic, wallet.CoinbaseRecord{Height: h.Height, Amount: reward, Blinding: blind, Commit: commit})
	if err != nil {
		t.Fatal(err)
	}
	b := &types.Block{Header: h,
		Outputs: []types.Output{{Features: types.OutputFeaturesCoinbase, Commit: commit}},
		Kernels: []types.Kernel{{Features: types.KernelFeaturesCoinbase, LockHeight: h.Height + types.CoinbaseLock, Excess: commit, ExcessSig: sig}}}
	types.SetBlockRoots(b)
	for n := uint64(0); ; n++ {
		b.Header.Nonce = n
		if pow.Verify(&b.Header) {
			return b
		}
	}
}

func hasUTXOCall(t *testing.T, h http.Handler, commit types.Commitment) map[string]any {
	t.Helper()
	body := `{"jsonrpc":"2.0","method":"hasutxo","params":["` + hex.EncodeToString(commit[:]) + `"],"id":1}`
	status, resp := call(t, h, body, "")
	if status != 200 || resp.Error != nil {
		t.Fatalf("hasutxo: %d %+v", status, resp.Error)
	}
	return resp.Result.(map[string]any)
}

func TestHasUTXOReportsPresenceAndExactMaturity(t *testing.T) {
	c := chain.NewMemory()
	g, _ := genesis.Build(genesis.Config{NetworkMagic: types.NetworkMagicTestnet, Timestamp: time.Now().Unix() - 3600, InitialDifficulty: 1})
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	s := &Service{Chain: c, Mempool: mempool.NewValidated(16, c.ValidateTransaction), DaemonContext: context.Background()}
	h := s.HTTPHandler()

	tip, _ := c.Tip()
	first := grindEmpty(t, tip, 0)
	if err := c.AddBlock(first); err != nil {
		t.Fatal(err)
	}
	cb := first.Outputs[0].Commit
	created := first.Header.Height // 1

	check := func(wantMature bool) {
		t.Helper()
		got := hasUTXOCall(t, h, cb)
		if got["present"] != true || got["features"].(float64) != float64(types.OutputFeaturesCoinbase) ||
			got["height"].(float64) != float64(created) || got["block_hash"] != types.HeaderID(&first.Header).String() {
			t.Fatalf("details: %+v", got)
		}
		if got["matures_at"].(float64) != float64(created+types.CoinbaseLock) {
			t.Fatalf("matures_at: %+v", got)
		}
		if got["mature"] != wantMature {
			t.Fatalf("tip=%v mature=%v want %v", got["tip"], got["mature"], wantMature)
		}
	}
	// A block at height H may spend a coinbase created at b iff H >= b+60, i.e. the
	// chain tip must be at least b+59. Test the exact boundary.
	for c.Height() < created+types.CoinbaseLock-2 { // tip = b+58: next block is b+59
		cur, _ := c.Tip()
		if err := c.AddBlock(grindEmpty(t, cur, 0)); err != nil {
			t.Fatal(err)
		}
	}
	check(false)
	cur, _ := c.Tip()
	if err := c.AddBlock(grindEmpty(t, cur, 0)); err != nil { // tip = b+59: next block is b+60
		t.Fatal(err)
	}
	check(true)

	// Unknown commitment and bad parameters.
	var unknown types.Commitment
	unknown[0] = 2
	unknown[32] = 1
	k := [32]byte{31: 9}
	unknown, _ = v2crypto.PublicFromScalar(k[:])
	if got := hasUTXOCall(t, h, unknown); got["present"] != false {
		t.Fatalf("unknown present: %+v", got)
	}
	for _, p := range []string{`[]`, `[5]`, `["zz"]`, `["` + strings.Repeat("0", 66) + `"]`, `["` + strings.Repeat("ab", 33) + `"]`, `["` + strings.Repeat("0", 64) + `"]`} {
		st, r := call(t, h, `{"jsonrpc":"2.0","method":"hasutxo","params":`+p+`,"id":1}`, "")
		if st != 400 || r.Error == nil || r.Error.Code != CodeInvalidParams {
			t.Errorf("params %s: %d %+v", p, st, r.Error)
		}
	}

	// A longer fork replaces the block that created the output: the index must
	// follow the reorg and forget it.
	anc, _ := c.HeaderByHeight(0)
	var fork []*types.Block
	parent := anc
	for i := uint64(0); i <= c.Height(); i++ {
		b := grindEmpty(t, parent, 1)
		fork = append(fork, b)
		parent = b.Header
	}
	if err := c.ReorgTo(fork); err != nil {
		t.Fatalf("reorg: %v", err)
	}
	if got := hasUTXOCall(t, h, cb); got["present"] != false {
		t.Fatalf("reorged-out output still reported present: %+v", got)
	}
	if got := hasUTXOCall(t, h, fork[0].Outputs[0].Commit); got["present"] != true {
		t.Fatalf("fork output missing: %+v", got)
	}
}
