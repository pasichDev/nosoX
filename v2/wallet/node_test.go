package wallet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pasichDev/nosoX/v2/types"
)

func TestRPCNodeSendsBearerAndNeverFollowsRedirects(t *testing.T) {
	var leaked string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
		w.Write([]byte(`{"jsonrpc":"2.0","result":"evil","id":1}`))
	}))
	defer target.Close()
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
			return
		}
		w.Write([]byte(`{"jsonrpc":"2.0","result":{"ok":true},"id":1}`))
	}))
	defer srv.Close()

	n, err := NewRPCNode(srv.URL, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Call("version", nil); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer s3cret" {
		t.Fatalf("Authorization = %q", got)
	}
	n2, _ := NewRPCNode(srv.URL+"/redir", "s3cret")
	if _, err := n2.Call("version", nil); err == nil {
		t.Fatal("a redirect response was treated as success")
	}
	if leaked != "" {
		t.Fatalf("token followed a redirect: %q", leaked)
	}
	n3, _ := NewRPCNode(srv.URL, "")
	got = "unset"
	n3.Call("version", nil)
	if got != "" {
		t.Fatalf("Authorization header sent without a token: %q", got)
	}
}

func TestRPCNodeRefusesTokenOverCleartextToRemoteHosts(t *testing.T) {
	for _, addr := range []string{"example.com:7780", "http://10.1.2.3:7780", "192.168.1.5:7780"} {
		if _, err := NewRPCNode(addr, "tok"); err == nil {
			t.Errorf("token allowed over cleartext to %s", addr)
		}
		if _, err := NewRPCNode(addr, ""); err == nil {
			t.Errorf("plain http to %s allowed without a token: answers could be forged", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:7780", "localhost:7780", "http://[::1]:7780", "https://example.com"} {
		if _, err := NewRPCNode(addr, "tok"); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
	for _, bad := range []string{"", "ftp://x", "http://", "://"} {
		if _, err := NewRPCNode(bad, ""); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestRPCNodeErrorMappingAndBounds(t *testing.T) {
	reply := ""
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(reply))
	}))
	defer srv.Close()
	n, _ := NewRPCNode(srv.URL, "")
	tx := &types.Transaction{}
	// Validation rejection -> ErrRejected.
	reply, status = `{"jsonrpc":"2.0","error":{"code":-32010,"message":"double spend"},"id":1}`, 200
	raw, _ := EncodeTx(&types.Transaction{})
	_ = raw
	if err := n.Submit(tx); !errorsIs(err, ErrRejected) || !strings.Contains(err.Error(), "double spend") {
		t.Fatalf("rejection: %v", err)
	}
	// Auth failure and transport trouble are NOT a rejection of the transaction.
	reply, status = `{"jsonrpc":"2.0","error":{"code":-32001,"message":"Not authorized"},"id":1}`, 401
	if err := n.Submit(tx); err == nil || errorsIs(err, ErrRejected) {
		t.Fatalf("auth failure reported as rejection: %v", err)
	}
	reply, status = `<html>bad gateway</html>`, 502
	if err := n.Submit(tx); err == nil || errorsIs(err, ErrRejected) {
		t.Fatalf("gateway error: %v", err)
	}
	// Oversized body.
	reply, status = `{"jsonrpc":"2.0","result":"`+strings.Repeat("a", maxRPCResponse)+`","id":1}`, 200
	if _, err := n.Call("version", nil); err == nil {
		t.Fatal("oversized response accepted")
	}
	// hasutxo decoding is strict about shape.
	reply = `{"jsonrpc":"2.0","result":{"present":true,"bogus":1},"id":1}`
	if _, err := n.UTXO(types.Commitment{}); err == nil {
		t.Fatal("unknown hasutxo field accepted")
	}
	reply = `{"jsonrpc":"2.0","result":{"present":true,"features":1,"mature":false,"matures_at":61,"height":1,"block_hash":"ab","tip":5},"id":1}`
	info, err := n.UTXO(types.Commitment{})
	if err != nil || !info.Present || info.MaturesAt != 61 || info.Mature {
		t.Fatalf("%+v %v", info, err)
	}
	// getblock not-found maps to ok=false.
	reply = `{"jsonrpc":"2.0","error":{"code":-32004,"message":"block not found"},"id":1}`
	if _, ok, err := n.BlockHash(5); ok || err != nil {
		t.Fatalf("not found: %v %v", ok, err)
	}
	var env map[string]any
	json.Unmarshal([]byte(reply), &env)
}
