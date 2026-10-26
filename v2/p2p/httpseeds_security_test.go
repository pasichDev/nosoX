package p2p

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type seedRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn seedRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestHTTPSeedRejectsCleartextBeforeRequest(t *testing.T) {
	called := false
	client := &http.Client{Transport: seedRoundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("must not attempt network request")
	})}
	_, err := fetchSeedURL(context.Background(), client, "http://example.invalid/seeds")
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("insecure URL accepted: %v", err)
	}
	if called {
		t.Fatal("transport contacted for an insecure seed URL")
	}
}

func TestHTTPSeedRejectsHTTPSDowngradeRedirect(t *testing.T) {
	// All traffic stays on httptest loopback listeners.
	cleartext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("/ip4/127.0.0.1/tcp/7781/p2p/12D3KooWFake\n"))
	}))
	defer cleartext.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cleartext.URL, http.StatusFound)
	}))
	defer secure.Close()

	_, err := fetchSeedURL(context.Background(), secure.Client(), secure.URL)
	if err == nil || !strings.Contains(err.Error(), "insecure transport") {
		t.Fatalf("downgraded HTTPS seed response accepted: %v", err)
	}
}

func TestHTTPSeedAcceptsDirectHTTPS(t *testing.T) {
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("/ip4/127.0.0.1/tcp/7781\n"))
	}))
	defer secure.Close()

	got, err := fetchSeedURL(context.Background(), secure.Client(), secure.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "/ip4/127.0.0.1/tcp/7781" {
		t.Fatalf("valid HTTPS seed response = %v", got)
	}
}
