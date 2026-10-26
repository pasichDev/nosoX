package p2p

import (
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// rateLimiter is a per-peer leaky-bucket throttle. Each peer gets a
// budget that refills at `rate` units per second up to `burst`. The
// /noso/sync/1 stream handler asks for 1 unit per batch.
//
// Defaults: 1 batch / 5 s with a burst of 3 — enough for a fresh node
// to catch up via concurrent requests, slow enough that a malicious
// peer cannot saturate bandwidth.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[peer.ID]*bucket

	rate  float64
	burst float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newRateLimiter returns a fresh limiter. Defaults: 0.2 tokens/sec, burst 3.
func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		buckets: map[peer.ID]*bucket{},
		rate:    0.2,
		burst:   3,
	}
}

// allow reports whether the peer may consume one token now. If yes, it
// also decrements the budget. The bucket is created lazily on first
// sighting.
func (r *rateLimiter) allow(p peer.ID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	b, ok := r.buckets[p]
	if !ok {
		if len(r.buckets) >= 4096 {
			for id, b := range r.buckets {
				if now.Sub(b.last) > time.Minute {
					delete(r.buckets, id)
				}
			}
			if len(r.buckets) >= 4096 {
				return false
			}
		}
		r.buckets[p] = &bucket{tokens: r.burst, last: now}
		b = r.buckets[p]
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * r.rate
	if b.tokens > r.burst {
		b.tokens = r.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// gc drops bucket records for peers that haven't been seen in `ttl`.
// Called occasionally from the libp2p host to bound map size.
func (r *rateLimiter) gc(ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cut := time.Now().Add(-ttl)
	for k, b := range r.buckets {
		if b.last.Before(cut) {
			delete(r.buckets, k)
		}
	}
}
