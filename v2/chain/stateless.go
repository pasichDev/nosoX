package chain

import (
	"sync"
	"sync/atomic"

	"github.com/pasichDev/nosoX/v2/pow"
	"github.com/pasichDev/nosoX/v2/types"
)

// Proof-of-work and signature/range-proof checks are pure functions of the
// block bytes: they need no chain state, so they run with no lock held and
// their results are cached by header hash (the header commits to the body
// through its roots, which callers check first).

// powSlots bounds concurrent Argon2 evaluations process-wide. Each needs 64 MiB,
// so unauthenticated gossip cannot drive memory beyond a fixed ceiling.
var powSlots = make(chan struct{}, 2)

// powEvaluations counts real Argon2 evaluations (tests assert accepted blocks
// are hashed once).
var powEvaluations atomic.Uint64

var (
	powChecked      = newHashSet(256)
	statelessPassed = newHashSet(256)
)

// hashSet is a small thread-safe FIFO-bounded set of hashes.
type hashSet struct {
	mu   sync.Mutex
	cap  int
	set  map[types.Hash]struct{}
	ring []types.Hash
	next int
}

func newHashSet(capacity int) *hashSet {
	return &hashSet{cap: capacity, set: make(map[types.Hash]struct{}, capacity)}
}

func (s *hashSet) has(h types.Hash) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.set[h]
	return ok
}

func (s *hashSet) add(h types.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.set == nil {
		s.set = map[types.Hash]struct{}{}
		if s.cap == 0 {
			s.cap = 64
		}
	}
	if _, ok := s.set[h]; ok {
		return
	}
	if len(s.ring) < s.cap {
		s.ring = append(s.ring, h)
	} else {
		delete(s.set, s.ring[s.next])
		s.ring[s.next] = h
		s.next = (s.next + 1) % s.cap
	}
	s.set[h] = struct{}{}
}

// rejectedForks remembers heads of forks that failed for a permanent reason,
// so a peer cannot make us redo the validation by resending them.
type rejectedForks struct{ hashSet }

func (r *rejectedForks) has(h types.Hash) bool { return r.hashSet.has(h) }
func (r *rejectedForks) add(h types.Hash)      { r.hashSet.add(h) }

// verifyPoW checks the header's Argon2id proof of work against its declared
// difficulty, once per distinct header.
func verifyPoW(h *types.BlockHeader) error {
	id := types.HeaderID(h)
	if powChecked.has(id) {
		return nil
	}
	powSlots <- struct{}{}
	powEvaluations.Add(1)
	ok := pow.Verify(h)
	<-powSlots
	if !ok {
		return ErrBadPoW
	}
	powChecked.add(id)
	return nil
}

// verifyStateless runs proof of work, then signatures and range proofs. The
// order puts the check an attacker must pay for first.
func verifyStateless(b *types.Block) error {
	id := types.HeaderID(&b.Header)
	if statelessPassed.has(id) {
		return nil
	}
	if err := verifyPoW(&b.Header); err != nil {
		return err
	}
	if err := verifyCrypto(b); err != nil {
		return err
	}
	statelessPassed.add(id)
	return nil
}
