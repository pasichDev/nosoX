package p2p

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestRateLimiterAllowsBurst(t *testing.T) {
	r := newRateLimiter()
	pid := peer.ID("test-peer")
	// First `burst` calls succeed.
	for i := 0; i < 3; i++ {
		if !r.allow(pid) {
			t.Fatalf("call %d should be allowed within burst", i+1)
		}
	}
	// The 4th call within the same instant must be denied.
	if r.allow(pid) {
		t.Fatal("4th call without refill should be denied")
	}
}

func TestRateLimiterPerPeer(t *testing.T) {
	r := newRateLimiter()
	a := peer.ID("peer-a")
	b := peer.ID("peer-b")
	for i := 0; i < 3; i++ {
		r.allow(a)
	}
	// Peer A is exhausted; peer B's bucket is untouched.
	if r.allow(a) {
		t.Fatal("peer A should be limited")
	}
	if !r.allow(b) {
		t.Fatal("peer B should still be free")
	}
}

func TestRateLimiterRefills(t *testing.T) {
	r := newRateLimiter()
	r.rate = 100 // tokens/sec for the test
	pid := peer.ID("test")
	for i := 0; i < 3; i++ {
		r.allow(pid)
	}
	if r.allow(pid) {
		t.Fatal("should be rate-limited immediately")
	}
	time.Sleep(50 * time.Millisecond)
	// After 50 ms at 100 tokens/s we've earned ~5 tokens, capped at 3.
	if !r.allow(pid) {
		t.Fatal("should be refilled after wait")
	}
}

func TestRateLimiterGC(t *testing.T) {
	r := newRateLimiter()
	r.allow("peer-a")
	r.allow("peer-b")
	if len(r.buckets) != 2 {
		t.Fatal("expected 2 buckets")
	}
	r.gc(0)
	if len(r.buckets) != 0 {
		t.Fatal("gc with ttl=0 should clear all buckets")
	}
}
