package rpc

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSvcWithToken(tok string) *Service {
	return &Service{Token: tok}
}

func post(t *testing.T, h http.Handler, body string, withToken string) *http.Response {
	t.Helper()
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if withToken != "" {
		req.Header.Set("Authorization", "Bearer "+withToken)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func TestAuthRequiredForMutating(t *testing.T) {
	s := newSvcWithToken("supersecret")
	h := s.HTTPHandler()
	// startmining is NOT in DefaultPublicMethods → must require auth.
	resp := post(t, h, `{"jsonrpc":"2.0","method":"startmining","params":[1,"r"],"id":1}`, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth call → status %d, want 401", resp.StatusCode)
	}
}

func TestAuthAcceptsValidToken(t *testing.T) {
	s := newSvcWithToken("supersecret")
	h := s.HTTPHandler()
	// Method is unknown but auth should pass first; we expect 402 unknown,
	// not 498 unauthorized.
	resp := post(t, h, `{"jsonrpc":"2.0","method":"adminonly","id":1}`, "supersecret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized call → status %d, want 200 (with method error)", resp.StatusCode)
	}
}

func TestPublicMethodsBypassAuth(t *testing.T) {
	s := newSvcWithToken("supersecret")
	h := s.HTTPHandler()
	// tip is in DefaultPublicMethods — should pass without token even
	// though the chain is nil (error will come back, but it's not 498).
	resp := post(t, h, `{"jsonrpc":"2.0","method":"version","id":1}`, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public method without token → status %d, want 200", resp.StatusCode)
	}
}

func TestAuthRejectsBadToken(t *testing.T) {
	s := newSvcWithToken("supersecret")
	h := s.HTTPHandler()
	resp := post(t, h, `{"jsonrpc":"2.0","method":"startmining","id":1}`, "wrongtoken")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token → status %d, want 401", resp.StatusCode)
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !subtleConstantTimeEq("abc", "abc") {
		t.Error("equal strings not equal")
	}
	if subtleConstantTimeEq("abc", "abd") {
		t.Error("different strings reported equal")
	}
	if subtleConstantTimeEq("abc", "ab") {
		t.Error("different lengths reported equal")
	}
}
