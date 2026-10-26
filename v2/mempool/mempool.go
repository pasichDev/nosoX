// Package mempool keeps unconfirmed Noso v2 transactions.
//
// Snapshot() returns entries sorted by fee descending so the miner
// drains the highest-paying transactions first. This is a simple
// first-price model — without it a flood of zero-fee transactions
// would starve fee-payers.
package mempool

import (
	"errors"
	"math"
	"sort"
	"sync"

	"github.com/pasichDev/noso-go/v2/types"
)

// Pool is the unconfirmed-tx queue.
type Pool struct {
	mu       sync.RWMutex
	entries  map[[32]byte]*types.Transaction
	maxSize  int
	bytes    int
	spent    map[types.Commitment][32]byte
	kernels  map[types.Hash][32]byte
	validate func(*types.Transaction) error
}

// New returns a pool with the given maximum size (transactions).
func New(maxSize int) *Pool {
	if maxSize <= 0 {
		maxSize = 2048
	}
	return &Pool{entries: map[[32]byte]*types.Transaction{}, maxSize: maxSize, spent: make(map[types.Commitment][32]byte), kernels: make(map[types.Hash][32]byte)}
}

// NewValidated installs the chain's full transaction admission checks. New alone
// intentionally fails closed until validation is available.
func NewValidated(maxSize int, validate func(*types.Transaction) error) *Pool {
	p := New(maxSize)
	p.validate = validate
	return p
}

// Add inserts tx into the pool. Returns the tx ID and an error if the
// pool is full or the tx is already present.
func (p *Pool) Add(tx *types.Transaction) ([32]byte, error) {
	var id [32]byte
	bodyBytes, err := transactionBounds(tx)
	if err != nil {
		return id, err
	}
	if p.validate == nil {
		return id, errors.New("mempool: transaction validation unavailable")
	}
	tx = cloneTx(tx)
	id = TxID(tx)
	p.mu.RLock()
	_, exists := p.entries[id]
	full := len(p.entries) >= p.maxSize || p.bytes+bodyBytes > 64<<20
	p.mu.RUnlock()
	if exists {
		return id, ErrDuplicate
	}
	if full {
		return id, errors.New("mempool: full")
	}
	if err := p.validate(tx); err != nil {
		return id, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.entries) >= p.maxSize || p.bytes+bodyBytes > 64<<20 {
		return id, errors.New("mempool: full")
	}
	if _, ok := p.entries[id]; ok {
		return id, ErrDuplicate
	}
	for _, a := range tx.Inputs {
		if _, ok := p.spent[a.Commit]; ok {
			return id, errors.New("mempool: conflicting input")
		}
	}
	for _, k := range tx.Kernels {
		if _, ok := p.kernels[types.KernelID(&k)]; ok {
			return id, errors.New("mempool: duplicate kernel")
		}
	}
	for _, a := range tx.Inputs {
		p.spent[a.Commit] = id
	}
	for _, k := range tx.Kernels {
		p.kernels[types.KernelID(&k)] = id
	}
	p.entries[id] = tx
	p.bytes += bodyBytes
	return id, nil
}

// Remove drops tx from the pool (e.g. after confirmation).
func (p *Pool) Remove(id [32]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if tx := p.entries[id]; tx != nil {
		p.bytes -= transactionSize(tx)
		for _, a := range tx.Inputs {
			delete(p.spent, a.Commit)
		}
		for _, k := range tx.Kernels {
			delete(p.kernels, types.KernelID(&k))
		}
	}
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
		out = append(out, cloneTx(p.entries[id]))
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

// TxID commits to the complete transaction, including signatures and proofs.
func TxID(tx *types.Transaction) [32]byte {
	return types.TransactionID(tx)
}

func cloneTx(tx *types.Transaction) *types.Transaction {
	out := *tx
	out.Inputs = append([]types.Input(nil), tx.Inputs...)
	out.Outputs = append([]types.Output(nil), tx.Outputs...)
	for i := range out.Outputs {
		out.Outputs[i].RangeProof = append([]byte(nil), out.Outputs[i].RangeProof...)
	}
	out.Kernels = append([]types.Kernel(nil), tx.Kernels...)
	for i := range out.Kernels {
		out.Kernels[i].ExcessSig = append([]byte(nil), out.Kernels[i].ExcessSig...)
	}
	return &out
}

func transactionSize(tx *types.Transaction) int {
	n := 128 * (len(tx.Inputs) + len(tx.Outputs) + len(tx.Kernels))
	for _, i := range tx.Inputs {
		n += len(i.LegacySig) + len(i.LegacyAddr)
	}
	for _, o := range tx.Outputs {
		n += len(o.RangeProof) + len(o.LegacyAddress)
	}
	for _, k := range tx.Kernels {
		n += len(k.ExcessSig)
	}
	return n
}

// ErrDuplicate means the exact canonical transaction is already retained.
// Kernel overlaps and input conflicts have distinct errors.
var ErrDuplicate = errors.New("mempool: duplicate")

// Validate rechecks a transaction against current chain state without changing
// pool membership. Publishers use this before forwarding pre-admitted entries.
func (p *Pool) Validate(tx *types.Transaction) error {
	if _, err := transactionBounds(tx); err != nil {
		return err
	}
	if p.validate == nil {
		return errors.New("mempool: transaction validation unavailable")
	}
	return p.validate(cloneTx(tx))
}

func transactionBounds(tx *types.Transaction) (int, error) {
	if tx == nil {
		return 0, errors.New("mempool: nil transaction")
	}
	if len(tx.Inputs) > 4096 || len(tx.Outputs) > 4096 || len(tx.Kernels) == 0 || len(tx.Kernels) > 4096 {
		return 0, errors.New("mempool: transaction bounds")
	}
	bodyBytes := 128 * (len(tx.Inputs) + len(tx.Outputs) + len(tx.Kernels))
	for _, o := range tx.Outputs {
		bodyBytes += len(o.RangeProof) + len(o.LegacyAddress)
		if len(o.RangeProof) > 16384 || len(o.LegacyAddress) > 128 {
			return 0, errors.New("mempool: output bounds")
		}
	}
	for _, i := range tx.Inputs {
		bodyBytes += len(i.LegacySig) + len(i.LegacyAddr)
		if len(i.LegacySig) > 1024 || len(i.LegacyAddr) > 128 {
			return 0, errors.New("mempool: input bounds")
		}
	}
	var fee uint64
	for _, k := range tx.Kernels {
		bodyBytes += len(k.ExcessSig)
		if len(k.ExcessSig) > 65 {
			return 0, errors.New("mempool: signature bounds")
		}
		if k.Fee > math.MaxUint64-fee {
			return 0, errors.New("mempool: fee overflow")
		}
		fee += k.Fee
	}

	if bodyBytes > 1<<20 {
		return 0, errors.New("mempool: transaction too large")
	}
	return bodyBytes, nil
}
