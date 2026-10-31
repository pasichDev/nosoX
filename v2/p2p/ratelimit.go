package p2p

import (
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// rateLimiter is a per-peer leaky-bucket throttle. Each peer gets a
// budget that refills at `rate` units per second up to `burst`. The
// /NosoX/sync/v5 stream handler asks for 1 unit per batch.
//
// The node serves sync at 2 requests / s with a burst of 16 (a 64-block batch
// each, so a fresh node catches up at over 100 blocks/s). The global byte
// budget below bounds what many peers together can pull.
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

// newRateLimiter returns a strict limiter: 0.2 tokens/sec, burst 3. The node
// uses newRateLimiterRate with its own sync budget.
func newRateLimiter() *rateLimiter { return newRateLimiterRate(0.2, 3) }

func newRateLimiterRate(rate, burst float64) *rateLimiter {
	return &rateLimiter{buckets: map[peer.ID]*bucket{}, rate: rate, burst: burst}
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

// byteBudget is a global token bucket of response bytes. It may go negative, so
// one large response is always served but the next requests wait.
type byteBudget struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64
	burst  float64
}

func newByteBudget(rate, burst float64) *byteBudget {
	return &byteBudget{tokens: burst, last: time.Now(), rate: rate, burst: burst}
}

// available reports whether a response may be built now.
func (b *byteBudget) available() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	return b.tokens > 0
}

func (b *byteBudget) spend(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	b.tokens -= float64(n)
}

func (b *byteBudget) refill() {
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
}
