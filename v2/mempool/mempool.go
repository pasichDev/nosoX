// Package mempool keeps unconfirmed Noso v2 transactions.
//
// Snapshot() returns entries sorted by fee descending so the miner
// drains the highest-paying transactions first. This is a simple
// first-price model — without it a flood of zero-fee transactions
// would starve fee-payers.
package mempool

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sort"
	"sync"
	"time"

	"github.com/pasichDev/noso-go/v2/types"
)

// Policy is the relay policy of a pool. The zero value admits everything and
// never expires, which is what tests of unrelated packages rely on; the daemon
// installs DefaultPolicy.
type Policy struct {
	// MinFeeRate is the minimum fee, in base units per 1000 bytes of the
	// transaction's accounted size. Below it a transaction is not relayed.
	MinFeeRate uint64
	// TTL is how long an entry stays pending. Zero means no expiry.
	TTL time.Duration
}

// DefaultPolicy is the production relay policy.
var DefaultPolicy = Policy{MinFeeRate: types.DefaultRelayFeeRate, TTL: 24 * time.Hour}

// Policy rejections. They describe local relay preferences, not consensus
// invalidity, so a network layer should ignore rather than punish a peer that
// forwards one (see IsPolicy).
var (
	ErrFull        = errors.New("mempool: full")
	ErrFeeTooLow   = errors.New("mempool: fee below minimum relay rate")
	ErrConflict    = errors.New("mempool: conflicting input")
	ErrKernelDup   = errors.New("mempool: duplicate kernel")
	ErrReplaceFee  = errors.New("mempool: replacement does not pay enough")
	errMaxPoolSize = 64 << 20
)

// ErrUnavailable means the pool has no chain validation installed yet. It is a
// local, transient condition: never the sender's fault.
var ErrUnavailable = errors.New("mempool: transaction validation unavailable")

// IsPolicy reports whether err is a relay-policy rejection rather than a
// statement that the transaction is invalid.
func IsPolicy(err error) bool {
	for _, e := range []error{ErrFull, ErrFeeTooLow, ErrConflict, ErrKernelDup, ErrReplaceFee, ErrDuplicate} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

type entryMeta struct {
	fee   uint64
	size  int
	added time.Time
}

// Pool is the unconfirmed-tx queue.
type Pool struct {
	mu       sync.RWMutex
	entries  map[[32]byte]*types.Transaction
	meta     map[[32]byte]entryMeta
	maxSize  int
	bytes    int
	spent    map[types.Commitment][32]byte
	kernels  map[types.Hash][32]byte
	validate func(*types.Transaction) error
	policy   Policy
	now      func() time.Time

	// epoch counts chain transitions seen by ApplyChange. A transaction validated
	// at one epoch and inserted at another is validated again: a block may have
	// confirmed or conflicted it in between.
	epoch uint64
	// confirmed keeps the original transactions that left the pool because a block
	// included them, by kernel ID, for as long as a reorg could still undo that
	// block. Re-admission after a reorg then restores each transaction as the
	// sender built it, instead of guessing at boundaries inside an aggregate.
	confirmed      map[types.Hash]*types.Transaction
	confirmedOrder []types.Hash
}

// maxConfirmedCache bounds the reorg re-admission cache.
const maxConfirmedCache = 4096

// New returns a pool with the given maximum size (transactions).
func New(maxSize int) *Pool {
	if maxSize <= 0 {
		maxSize = 2048
	}
	return &Pool{entries: map[[32]byte]*types.Transaction{}, meta: map[[32]byte]entryMeta{}, maxSize: maxSize,
		spent: make(map[types.Commitment][32]byte), kernels: make(map[types.Hash][32]byte), now: time.Now}
}

// NewValidated installs the chain's full transaction admission checks. New alone
// intentionally fails closed until validation is available.
func NewValidated(maxSize int, validate func(*types.Transaction) error) *Pool {
	p := New(maxSize)
	p.validate = validate
	return p
}

// SetPolicy installs the relay policy.
func (p *Pool) SetPolicy(pol Policy) {
	p.mu.Lock()
	p.policy = pol
	p.mu.Unlock()
}

// feeRateLess reports whether (fa,sa) pays a strictly lower rate than (fb,sb),
// comparing fa/sa < fb/sb by cross-multiplication in 128 bits.
func feeRateLess(fa uint64, sa int, fb uint64, sb int) bool {
	l1, l0 := bits.Mul64(fa, uint64(sb))
	r1, r0 := bits.Mul64(fb, uint64(sa))
	return l1 < r1 || (l1 == r1 && l0 < r0)
}

// Add inserts tx into the pool. Returns the tx ID and an error if the
// pool is full or the tx is already present.
//
// A full pool evicts its lowest fee-rate entries to admit a transaction that
// pays a strictly higher rate. A transaction spending an input or reusing a
// kernel of pending ones replaces them only when it pays a higher rate and more
// absolute fee than everything it displaces.
func (p *Pool) Add(tx *types.Transaction) ([32]byte, error) {
	return p.add(tx, true)
}

func (p *Pool) add(tx *types.Transaction, relay bool) ([32]byte, error) {
	var id [32]byte
	bodyBytes, err := transactionBounds(tx)
	if err != nil {
		return id, err
	}
	if p.validate == nil {
		return id, ErrUnavailable
	}
	tx = cloneTx(tx)
	id = TxID(tx)
	fee, size := txTotalFee(tx), transactionSize(tx)
	p.mu.Lock()
	p.expireLocked()
	_, exists := p.entries[id]
	pol := p.policy
	p.mu.Unlock()
	if exists {
		return id, ErrDuplicate
	}
	if relay && pol.MinFeeRate > 0 && feeRateLess(fee, size, pol.MinFeeRate, 1000) {
		return id, fmt.Errorf("%w: pays %d for %d bytes, the relay minimum is %d (%d per 1000 bytes)",
			ErrFeeTooLow, fee, size, MinFee(pol.MinFeeRate, size), pol.MinFeeRate)
	}
	// Full chain validation happens outside the pool lock; policy checks that
	// need the pool's current contents are repeated under the lock below. If the
	// chain moved while we validated (ApplyChange ran), validate again against
	// the new state instead of inserting a transaction a block just confirmed.
	var epoch uint64
	for attempt := 0; ; attempt++ {
		p.mu.RLock()
		epoch = p.epoch
		p.mu.RUnlock()
		if err := p.validate(tx); err != nil {
			return id, err
		}
		p.mu.Lock()
		if p.epoch == epoch {
			break // still holding p.mu
		}
		p.mu.Unlock()
		if attempt >= 3 {
			return id, ErrUnavailable // the chain keeps moving: try again later
		}
	}
	defer p.mu.Unlock()
	if _, ok := p.entries[id]; ok {
		return id, ErrDuplicate
	}
	conflicts := map[[32]byte]struct{}{}
	for _, a := range tx.Inputs {
		if other, ok := p.spent[a.Commit]; ok {
			conflicts[other] = struct{}{}
		}
	}
	for _, k := range tx.Kernels {
		if other, ok := p.kernels[types.KernelID(&k)]; ok {
			conflicts[other] = struct{}{}
		}
	}
	if len(conflicts) > 0 {
		var displaced uint64
		for other := range conflicts {
			m := p.meta[other]
			if !feeRateLess(m.fee, m.size, fee, size) {
				return id, ErrConflict
			}
			displaced += m.fee
		}
		// Every replacement makes the network re-verify a transaction, so it
		// must pay for that: strictly more than it displaces, plus the relay
		// rate for its own size.
		if fee <= displaced || fee-displaced < pol.MinFeeRate*uint64(size)/1000 {
			return id, ErrReplaceFee
		}
	}
	// Decide everything that must go BEFORE changing anything: a transaction that
	// ends up refused (pool full) must not have evicted a single entry.
	evict := map[[32]byte]struct{}{}
	count, bytesUsed := len(p.entries), p.bytes
	for other := range conflicts {
		evict[other] = struct{}{}
		count--
		bytesUsed -= transactionSize(p.entries[other])
	}
	for count >= p.maxSize || bytesUsed+bodyBytes > errMaxPoolSize {
		worst, ok := p.lowestExcludingLocked(evict)
		if !ok {
			return id, ErrFull
		}
		m := p.meta[worst]
		if !feeRateLess(m.fee, m.size, fee, size) {
			return id, ErrFull
		}
		evict[worst] = struct{}{}
		count--
		bytesUsed -= transactionSize(p.entries[worst])
	}
	for other := range evict {
		p.removeLocked(other)
	}
	for _, a := range tx.Inputs {
		p.spent[a.Commit] = id
	}
	for _, k := range tx.Kernels {
		p.kernels[types.KernelID(&k)] = id
	}
	p.entries[id] = tx
	p.meta[id] = entryMeta{fee: fee, size: size, added: p.now()}
	p.bytes += bodyBytes
	return id, nil
}

// lowestExcludingLocked returns the entry with the lowest fee rate (ties: oldest,
// then ID), ignoring the entries in skip.
func (p *Pool) lowestExcludingLocked(skip map[[32]byte]struct{}) ([32]byte, bool) {
	var worst [32]byte
	found := false
	for id, m := range p.meta {
		if _, s := skip[id]; s {
			continue
		}
		if !found {
			worst, found = id, true
			continue
		}
		w := p.meta[worst]
		switch {
		case feeRateLess(m.fee, m.size, w.fee, w.size):
			worst = id
		case feeRateLess(w.fee, w.size, m.fee, m.size):
		case m.added.Before(w.added), m.added.Equal(w.added) && string(id[:]) < string(worst[:]):
			worst = id
		}
	}
	return worst, found
}

func (p *Pool) removeLocked(id [32]byte) {
	if tx := p.entries[id]; tx != nil {
		p.bytes -= transactionSize(tx)
		for _, a := range tx.Inputs {
			if p.spent[a.Commit] == id {
				delete(p.spent, a.Commit)
			}
		}
		for _, k := range tx.Kernels {
			kid := types.KernelID(&k)
			if p.kernels[kid] == id {
				delete(p.kernels, kid)
			}
		}
	}
	delete(p.entries, id)
	delete(p.meta, id)
}

// expireLocked drops entries older than the policy TTL.
func (p *Pool) expireLocked() {
	if p.policy.TTL <= 0 {
		return
	}
	cutoff := p.now().Add(-p.policy.TTL)
	for id, m := range p.meta {
		if m.added.Before(cutoff) {
			p.removeLocked(id)
		}
	}
}

// Expire removes entries older than the policy TTL and returns how many went.
func (p *Pool) Expire() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.entries)
	p.expireLocked()
	return n - len(p.entries)
}

// Remove drops tx from the pool (e.g. after confirmation).
func (p *Pool) Remove(id [32]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeLocked(id)
}

// Confirmed records that tx was included in a block this node accepted and drops
// it from the pool. Unlike Remove it first stashes the transaction (indexed by its
// kernels) so that a reorg of that block restores it as the sender built it. It
// is idempotent with ApplyChange: stashing dedups by kernel ID, so the order
// between this call and the chain subscription applying the same block does not
// matter, and the transaction is stashed even if it already left the pool.
func (p *Pool) Confirmed(tx *types.Transaction) {
	if tx == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stashConfirmedLocked(cloneTx(tx))
	p.removeLocked(TxID(tx))
}

// ApplyChange brings the pool in line with a canonical-chain transition. It is
// called after the chain state has changed.
//
// Connected blocks: every pending transaction that shares a kernel with the
// block (confirmed) or spends an input the block spent (conflicting) is
// removed. Disconnected blocks: their user transactions are re-admitted, as one
// aggregate per block (a block does not record how its transactions were
// grouped), if still valid on the new chain, and pending transactions that
// relied on outputs of the disconnected blocks are revalidated.
func (p *Pool) ApplyChange(disconnected, connected []*types.Block) {
	p.mu.Lock()
	p.epoch++
	for _, b := range connected {
		p.dropIncludedLocked(b)
	}
	// Outputs that existed only on the abandoned branch.
	orphaned := map[types.Commitment]struct{}{}
	for _, b := range disconnected {
		for i := range b.Outputs {
			orphaned[b.Outputs[i].Commit] = struct{}{}
		}
	}
	var recheck [][32]byte
	if len(orphaned) > 0 {
		for id, tx := range p.entries {
			for _, in := range tx.Inputs {
				if _, ok := orphaned[in.Commit]; ok {
					recheck = append(recheck, id)
					break
				}
			}
		}
	}
	p.expireLocked()
	p.mu.Unlock()

	const maxRecheck = 4096
	if len(recheck) > maxRecheck {
		recheck = recheck[:maxRecheck]
	}
	for _, id := range recheck {
		p.mu.RLock()
		tx := p.entries[id]
		p.mu.RUnlock()
		if tx == nil {
			continue
		}
		if p.validate != nil && p.validate(cloneTx(tx)) != nil {
			p.Remove(id)
		}
	}
	// Oldest disconnected block first, so dependent transactions re-enter in order.
	for i := len(disconnected) - 1; i >= 0; i-- {
		p.readmit(disconnected[i])
	}
}

// readmit puts the transactions of a disconnected block back. A block does not
// record where one transaction ends and the next begins, so the aggregate of a
// block is not a transaction: if the replacing branch kept only part of it, the
// aggregate fails as a whole and the rest would vanish from every pool. So:
//
//  1. every transaction this pool saw before the block confirmed it is restored
//     as the sender built it, one at a time (each is still validated, so the
//     ones the new branch already includes simply fail);
//  2. what is left over (transactions this node never saw) is tried as one
//     aggregate and, failing that, as every combination of its inputs, outputs
//     and kernels that balances, which is small at the consensus limits.
func (p *Pool) readmit(b *types.Block) {
	covered := map[types.Hash]bool{}
	seen := map[[32]byte]bool{}
	p.mu.Lock()
	var originals []*types.Transaction
	for i := range b.Kernels {
		kid := types.KernelID(&b.Kernels[i])
		if tx, ok := p.confirmed[kid]; ok {
			covered[kid] = true
			if id := TxID(tx); !seen[id] {
				seen[id] = true
				originals = append(originals, tx)
			}
		}
	}
	p.mu.Unlock()
	for _, tx := range originals {
		_, _ = p.add(tx, false)
	}
	rest := userTransaction(b)
	if rest == nil {
		return
	}
	// Remove what the restored originals already account for.
	if len(originals) > 0 {
		inUsed, outUsed := map[types.Commitment]bool{}, map[types.Commitment]bool{}
		for _, tx := range originals {
			for _, in := range tx.Inputs {
				inUsed[in.Commit] = true
			}
			for _, o := range tx.Outputs {
				outUsed[o.Commit] = true
			}
		}
		left := &types.Transaction{}
		for _, in := range rest.Inputs {
			if !inUsed[in.Commit] {
				left.Inputs = append(left.Inputs, in)
			}
		}
		for _, o := range rest.Outputs {
			if !outUsed[o.Commit] {
				left.Outputs = append(left.Outputs, o)
			}
		}
		for _, k := range rest.Kernels {
			if !covered[types.KernelID(&k)] {
				left.Kernels = append(left.Kernels, k)
			}
		}
		if len(left.Inputs) == 0 || len(left.Outputs) == 0 || len(left.Kernels) == 0 {
			return
		}
		rest = left
	}
	if _, err := p.add(rest, false); err == nil || !isSplittable(err) {
		return
	}
	p.readmitSubsets(rest)
}

// isSplittable reports whether a failed aggregate is worth splitting: anything
// that is not a duplicate, pool policy, or the pool being unavailable.
func isSplittable(err error) bool {
	return !errors.Is(err, ErrDuplicate) && !errors.Is(err, ErrUnavailable) && !IsPolicy(err)
}

// readmitSubsets tries sub-transactions of an aggregate in order of size,
// largest first, admitting each one that validates and skipping what it uses.
func (p *Pool) readmitSubsets(agg *types.Transaction) {
	ni, no, nk := len(agg.Inputs), len(agg.Outputs), len(agg.Kernels)
	if ni > 4 || no > 4 || nk > 4 {
		return
	}
	type cand struct{ in, out, ker uint }
	var cands []cand
	for in := uint(1); in < 1<<ni; in++ {
		for out := uint(1); out < 1<<no; out++ {
			for ker := uint(1); ker < 1<<nk; ker++ {
				cands = append(cands, cand{in, out, ker})
			}
		}
	}
	size := func(c cand) int { return bits.OnesCount(c.in) + bits.OnesCount(c.out) + bits.OnesCount(c.ker) }
	sort.SliceStable(cands, func(i, j int) bool { return size(cands[i]) > size(cands[j]) })
	usedIn, usedOut, usedKer := uint(0), uint(0), uint(0)
	for _, c := range cands {
		if c.in&usedIn != 0 || c.out&usedOut != 0 || c.ker&usedKer != 0 {
			continue
		}
		tx := &types.Transaction{}
		for i := 0; i < ni; i++ {
			if c.in&(1<<i) != 0 {
				tx.Inputs = append(tx.Inputs, agg.Inputs[i])
			}
		}
		for i := 0; i < no; i++ {
			if c.out&(1<<i) != 0 {
				tx.Outputs = append(tx.Outputs, agg.Outputs[i])
			}
		}
		for i := 0; i < nk; i++ {
			if c.ker&(1<<i) != 0 {
				tx.Kernels = append(tx.Kernels, agg.Kernels[i])
			}
		}
		if _, err := p.add(tx, false); err == nil {
			usedIn, usedOut, usedKer = usedIn|c.in, usedOut|c.out, usedKer|c.ker
		}
	}
}

// dropIncludedLocked removes pending transactions that b confirmed or conflicts with.
func (p *Pool) dropIncludedLocked(b *types.Block) {
	drop := map[[32]byte]struct{}{}
	for i := range b.Kernels {
		if id, ok := p.kernels[types.KernelID(&b.Kernels[i])]; ok {
			drop[id] = struct{}{}
			p.stashConfirmedLocked(p.entries[id])
		}
	}
	for i := range b.Inputs {
		if id, ok := p.spent[b.Inputs[i].Commit]; ok {
			drop[id] = struct{}{}
		}
	}
	for id := range drop {
		p.removeLocked(id)
	}
}

// stashConfirmedLocked remembers a transaction a block just confirmed, indexed by
// each of its kernels, so a reorg of that block can restore it intact.
func (p *Pool) stashConfirmedLocked(tx *types.Transaction) {
	if tx == nil {
		return
	}
	if p.confirmed == nil {
		p.confirmed = map[types.Hash]*types.Transaction{}
	}
	for i := range tx.Kernels {
		kid := types.KernelID(&tx.Kernels[i])
		if _, dup := p.confirmed[kid]; !dup {
			p.confirmedOrder = append(p.confirmedOrder, kid)
		}
		p.confirmed[kid] = tx
	}
	for len(p.confirmedOrder) > maxConfirmedCache {
		delete(p.confirmed, p.confirmedOrder[0])
		p.confirmedOrder = p.confirmedOrder[1:]
	}
}

// userTransaction extracts the non-coinbase part of b as one
// transaction, or nil if b carries none.
func userTransaction(b *types.Block) *types.Transaction {
	tx := &types.Transaction{Inputs: append([]types.Input(nil), b.Inputs...)}
	for i := range b.Outputs {
		if b.Outputs[i].Features == types.OutputFeaturesPlain {
			tx.Outputs = append(tx.Outputs, b.Outputs[i])
		}
	}
	for i := range b.Kernels {
		if b.Kernels[i].Features == types.KernelFeaturesPlain {
			tx.Kernels = append(tx.Kernels, b.Kernels[i])
		}
	}
	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 || len(tx.Kernels) == 0 {
		return nil
	}
	return cloneTx(tx)
}

// Len returns the number of pending transactions.
func (p *Pool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.entries)
}

// Snapshot returns a copy of all entries sorted by fee rate (total kernel fee
// per accounted byte) descending. Ties are broken by transaction ID for determinism.
//
// "Total fee" is the sum of fees across all kernels in the transaction
// — multi-kernel txs are aggregated by the sender.
func (p *Pool) Snapshot() []*types.Transaction {
	p.Expire()
	p.mu.RLock()
	defer p.mu.RUnlock()
	ids := make([][32]byte, 0, len(p.entries))
	for id := range p.entries {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		mi, mj := p.meta[ids[i]], p.meta[ids[j]]
		if feeRateLess(mj.fee, mj.size, mi.fee, mi.size) {
			return true // higher fee rate first
		}
		if feeRateLess(mi.fee, mi.size, mj.fee, mj.size) {
			return false
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
	n += 64 * len(tx.Inputs)
	for _, o := range tx.Outputs {
		n += len(o.RangeProof)
	}
	for _, k := range tx.Kernels {
		n += len(k.ExcessSig)
	}
	return n
}

// MinFee is the smallest fee that clears a relay rate for a transaction of the
// given accounted size: ceil(rate*size/1000).
func MinFee(rate uint64, size int) uint64 { return types.MinRelayFee(rate, size) }

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
		return ErrUnavailable
	}
	return p.validate(cloneTx(tx))
}

func transactionBounds(tx *types.Transaction) (int, error) {
	if tx == nil {
		return 0, errors.New("mempool: nil transaction")
	}
	if len(tx.Inputs) > types.MaxBlockInputs || len(tx.Outputs) > types.MaxBlockOutputs || len(tx.Kernels) == 0 || len(tx.Kernels) > types.MaxBlockKernels {
		return 0, errors.New("mempool: transaction bounds")
	}
	bodyBytes := 128 * (len(tx.Inputs) + len(tx.Outputs) + len(tx.Kernels))
	for _, o := range tx.Outputs {
		bodyBytes += len(o.RangeProof)
		if len(o.RangeProof) > types.MaxRangeProofBytes {
			return 0, errors.New("mempool: output bounds")
		}
	}
	bodyBytes += 64 * len(tx.Inputs)
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

	if bodyBytes > types.MaxBlockBodyBytes {
		return 0, errors.New("mempool: transaction too large")
	}
	return bodyBytes, nil
}
