package rpc

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A browser wallet/explorer on another origin must be able to send a
// Bearer token to a remote node. That requires Authorization in the CORS
// preflight allow-list — this guards the "connect from outside over RPC" path.
func TestCORSPreflightAllowsAuthorization(t *testing.T) {
	s := newSvcWithToken("tok")
	h := s.HTTPHandler()
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://wallet.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("allow-origin = %q, want *", got)
	}
	allow := rec.Header().Get("Access-Control-Allow-Headers")
	if !strings.Contains(strings.ToLower(allow), "authorization") {
		t.Fatalf("allow-headers %q must include Authorization for remote auth", allow)
	}
}

func TestCORSHeadersOnPost(t *testing.T) {
	s := newSvcWithToken("")
	h := s.HTTPHandler()
	resp := post(t, h, `{"jsonrpc":"2.0","method":"version","id":1}`, "")
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("missing CORS header on POST response")
	}
}

func TestNonPostRejected(t *testing.T) {
	s := newSvcWithToken("")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.HTTPHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET to JSON-RPC = %d, want 405", rec.Code)
	}
}

func TestInvalidJSON(t *testing.T) {
	s := newSvcWithToken("")
	resp := post(t, s.HTTPHandler(), `{not json`, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 with JSON-RPC error", resp.StatusCode)
	}
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	if !strings.Contains(body.String(), "Invalid JSON") {
		t.Fatalf("expected Invalid JSON error, got %s", body.String())
	}
}

func TestUnknownMethod(t *testing.T) {
	s := newSvcWithToken("")
	resp := post(t, s.HTTPHandler(), `{"jsonrpc":"2.0","method":"nope","id":1}`, "")
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	if !strings.Contains(body.String(), "unknown method") {
		t.Fatalf("expected unknown method error, got %s", body.String())
	}
}

func TestVersionMethod(t *testing.T) {
	s := &Service{Version: "test-1.2.3"}
	resp := post(t, s.HTTPHandler(), `{"jsonrpc":"2.0","method":"version","id":7}`, "")
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	if !strings.Contains(body.String(), "test-1.2.3") {
		t.Fatalf("version not echoed: %s", body.String())
	}
}

func TestHealthEndpoint(t *testing.T) {
	s := newSvcWithToken("")
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	s.HTTPHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("health = %d %q", rec.Code, rec.Body.String())
	}
}

func TestHeightFromParam(t *testing.T) {
	if v, err := HeightFromParam(float64(42)); err != nil || v != 42 {
		t.Fatalf("float param: %v %v", v, err)
	}
	if v, err := HeightFromParam("99"); err != nil || v != 99 {
		t.Fatalf("string param: %v %v", v, err)
	}
	if _, err := HeightFromParam([]int{1}); err == nil {
		t.Fatal("expected error on bad param type")
	}
}
