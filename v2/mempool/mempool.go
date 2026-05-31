// Package mempool keeps unconfirmed Noso v2 transactions.
//
// Snapshot() returns entries sorted by fee descending so the miner
// drains the highest-paying transactions first. This is a simple
// first-price model — without it a flood of zero-fee transactions
// would starve fee-payers.
package mempool

import (
	"crypto/sha256"
	"errors"
	"sort"
	"sync"

	"github.com/noso-project/noso-go/v2/types"
)

// Pool is the unconfirmed-tx queue.
type Pool struct {
	mu      sync.RWMutex
	entries map[[32]byte]*types.Transaction
	maxSize int
}

// New returns a pool with the given maximum size (transactions).
func New(maxSize int) *Pool {
	if maxSize <= 0 {
		maxSize = 2048
	}
	return &Pool{entries: map[[32]byte]*types.Transaction{}, maxSize: maxSize}
}

// Add inserts tx into the pool. Returns the tx ID and an error if the
// pool is full or the tx is already present.
func (p *Pool) Add(tx *types.Transaction) ([32]byte, error) {
	id := TxID(tx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.entries) >= p.maxSize {
		return id, errors.New("mempool: full")
	}
	if _, ok := p.entries[id]; ok {
		return id, errors.New("mempool: duplicate")
	}
	p.entries[id] = tx
	return id, nil
}

// Remove drops tx from the pool (e.g. after confirmation).
func (p *Pool) Remove(id [32]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.entries, id)
}

// Len returns the number of pending transactions.
func (p *Pool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.entries)
}

// Snapshot returns a copy of all entries sorted by total kernel fee
// descending. Ties are broken by transaction ID for determinism.
//
// "Total fee" is the sum of fees across all kernels in the transaction
// — multi-kernel txs are aggregated by the sender.
func (p *Pool) Snapshot() []*types.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ids := make([][32]byte, 0, len(p.entries))
	for id := range p.entries {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		fi := txTotalFee(p.entries[ids[i]])
		fj := txTotalFee(p.entries[ids[j]])
		if fi != fj {
			return fi > fj // higher fee first
		}
		for k := 0; k < 32; k++ {
			if ids[i][k] != ids[j][k] {
				return ids[i][k] < ids[j][k]
			}
		}
		return false
	})
	out := make([]*types.Transaction, 0, len(ids))
	for _, id := range ids {
		out = append(out, p.entries[id])
	}
	return out
}

func txTotalFee(tx *types.Transaction) uint64 {
	var total uint64
	for i := range tx.Kernels {
		total += tx.Kernels[i].Fee
	}
	return total
}

// TxID hashes the kernel set; for MW that uniquely identifies a tx.
func TxID(tx *types.Transaction) [32]byte {
	h := sha256.New()
	for i := range tx.Kernels {
		k := types.KernelID(&tx.Kernels[i])
		h.Write(k[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
