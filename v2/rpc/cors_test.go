package rpc

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// By default no CORS headers are sent at all, so no web page can read a
// response from the node.
func TestNoCORSHeadersByDefault(t *testing.T) {
	h := newSvcWithToken("tok").HTTPHandler()
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "https://wallet.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	for k := range rec.Header() {
		if strings.HasPrefix(k, "Access-Control") {
			t.Fatalf("unexpected CORS header %s on preflight", k)
		}
	}
	resp := post(t, h, `{"jsonrpc":"2.0","method":"version","id":1}`, "")
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS header on POST response by default")
	}
}

// An explicitly configured origin gets exactly that origin back, with the
// Authorization header allowed so a remote browser wallet can authenticate.
func TestConfiguredCORSOrigin(t *testing.T) {
	s := &Service{Token: "tok", CORSOrigin: "https://wallet.example"}
	h := s.HTTPHandler()
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://wallet.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "https://wallet.example" {
		t.Fatalf("preflight: %d %v", rec.Code, rec.Header())
	}
	if !strings.Contains(strings.ToLower(rec.Header().Get("Access-Control-Allow-Headers")), "authorization") {
		t.Fatal("Authorization not allowed")
	}
	req = httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("foreign origin allowed")
	}
}

func TestNonPostRejected(t *testing.T) {
	s := newSvcWithToken("")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.HTTPHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET to JSON-RPC = %d, want 405", rec.Code)
	}
}

func TestInvalidJSON(t *testing.T) {
	s := newSvcWithToken("")
	resp := post(t, s.HTTPHandler(), `{not json`, "")
	// A malformed request is a transport-level failure: HTTP 400 with the
	// JSON-RPC parse-error code (it used to be HTTP 200 carrying code 401).
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 with JSON-RPC error", resp.StatusCode)
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
	req.Host = "127.0.0.1"
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
