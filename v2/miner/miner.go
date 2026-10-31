// Package miner runs the NosoX PoW grind. CPU-only, multi-goroutine,
// designed to peak on a Raspberry Pi 4 at 5–15 H/s and on a modern
// laptop at 50–200 H/s — comfortable scale for solo mining.
package miner

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pasichDev/noso-go/v2/chain"
	"github.com/pasichDev/noso-go/v2/mempool"
	"github.com/pasichDev/noso-go/v2/pow"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

// MaxThreads is the most worker goroutines Start accepts (each holds a 64 MiB
// Argon2 working set).
const MaxThreads = 16

// Miner produces blocks from mempool + current tip.
type Miner struct {
	chain    *chain.Chain
	pool     *mempool.Pool
	cbStore  *wallet.CoinbaseStore // where fresh blinds + commits get persisted
	rewardTo string                // free-form operator label; informational only, in no block, kernel or signature

	// listeners receive a copy of every successfully-applied block. The
	// daemon registers p2p.BroadcastBlock here so freshly mined blocks
	// reach the network. Without a listener mined blocks are still added
	// to the local chain but never gossip.
	listenersMu sync.RWMutex
	listeners   []func(*types.Block)

	mu     sync.Mutex
	state  State
	cancel context.CancelFunc
	done   chan struct{}

	// Counters for stats.
	hashCount atomic.Uint64
	startedAt time.Time

	// Operator-visible failure state. The grind loop retries after errors but
	// never does so silently: each distinct failure is logged and the latest
	// is reported by Stats (and so by minerstats).
	logf        func(format string, args ...any)
	gateMu      sync.Mutex
	gate        func() bool
	errMu       sync.Mutex
	lastErr     string
	lastErrAt   time.Time
	lastLogged  string
	lastLogTime time.Time
	errCount    uint64
	blocksFound atomic.Uint64
}

// SetLogger installs the sink for miner failures. Without one, failures are
// still counted and reported through Stats.
func (m *Miner) SetLogger(logf func(format string, args ...any)) {
	m.errMu.Lock()
	m.logf = logf
	m.errMu.Unlock()
}

// noteError records a failure of the mining loop and logs it, repeating an
// identical message at most once every 30 seconds.
func (m *Miner) noteError(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	m.errMu.Lock()
	m.errCount++
	m.lastErr, m.lastErrAt = msg, time.Now()
	logf := m.logf
	emit := msg != m.lastLogged || time.Since(m.lastLogTime) > 30*time.Second
	if emit {
		m.lastLogged, m.lastLogTime = msg, time.Now()
	}
	m.errMu.Unlock()
	if emit && logf != nil {
		logf("miner: %s", msg)
	}
}

// State describes the miner's current activity.
type State int

const (
	StateIdle State = iota
	StateMining
)

// New constructs an unstarted miner. A coinbase keystore is required whenever
// the block's coinbase amount (reward plus selected fees) is positive; candidate construction fails if reward keys cannot persist.
func New(c *chain.Chain, p *mempool.Pool, cb *wallet.CoinbaseStore) *Miner {
	return &Miner{chain: c, pool: p, cbStore: cb}
}

// OnNewBlock registers a callback the miner invokes after a block has
// been validated and applied. The daemon uses this to gossip mined
// blocks via libp2p. Callbacks must be cheap; for slow work spawn a
// goroutine inside the callback.
func (m *Miner) OnNewBlock(fn func(*types.Block)) {
	m.listenersMu.Lock()
	defer m.listenersMu.Unlock()
	m.listeners = append(m.listeners, fn)
}

func (m *Miner) emit(b *types.Block) {
	m.listenersMu.RLock()
	listeners := append([]func(*types.Block){}, m.listeners...)
	m.listenersMu.RUnlock()
	// Invoke user callbacks outside the registration lock. A listener may
	// register another listener, and callbacks must not block future registration.
	for _, fn := range listeners {
		fn(b)
	}
}

// Start begins mining with the given thread count and reward address.
// Calls return ErrAlreadyMining if a previous Start hasn't been stopped.
func (m *Miner) Start(ctx context.Context, threads int, rewardTo string) error {
	if threads < 1 {
		threads = 1
	}
	if threads > MaxThreads {
		return errors.New("miner: thread limit exceeded")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == StateMining {
		return ErrAlreadyMining
	}
	if m.done != nil {
		select {
		case <-m.done:
		default:
			return ErrAlreadyMining
		}
	}
	innerCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.state = StateMining
	m.rewardTo = rewardTo
	m.hashCount.Store(0)
	m.startedAt = time.Now()
	done := make(chan struct{})
	m.done = done
	go func() {
		defer close(done)
		defer func() {
			m.mu.Lock()
			if m.done == done {
				m.state = StateIdle
				m.cancel = nil
			}
			m.mu.Unlock()
		}()
		m.run(innerCtx, threads)
	}()
	return nil
}

// Stop halts mining.
func (m *Miner) Stop() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	done := m.done
	m.mu.Unlock()
	if done != nil {
		<-done
	}
	m.mu.Lock()
	if m.done == done {
		m.state = StateIdle
	}
	m.mu.Unlock()
}

// Stats returns hashes-per-second since Start was last called.
type Stats struct {
	State    State
	Hashes   uint64
	Elapsed  time.Duration
	HashesPS float64
	// BlocksFound counts solved blocks the chain accepted.
	BlocksFound uint64
	// Errors counts failures of the mining loop since the process started;
	// LastError is the latest one (empty if none) and LastErrorAt its time.
	Errors      uint64
	LastError   string
	LastErrorAt time.Time
}

// Stats returns a snapshot of the current activity.
func (m *Miner) Stats() Stats {
	m.mu.Lock()
	state := m.state
	startedAt := m.startedAt
	m.mu.Unlock()
	elapsed := time.Since(startedAt)
	h := m.hashCount.Load()
	hps := 0.0
	if elapsed > 0 {
		hps = float64(h) / elapsed.Seconds()
	}
	m.errMu.Lock()
	st := Stats{State: state, Hashes: h, Elapsed: elapsed, HashesPS: hps, BlocksFound: m.blocksFound.Load(),
		Errors: m.errCount, LastError: m.lastErr, LastErrorAt: m.lastErrAt}
	m.errMu.Unlock()
	return st
}

// ErrAlreadyMining is returned when Start is called twice without a
// Stop in between.
var ErrAlreadyMining = errors.New("miner: already mining")

// SetSyncGate installs a condition mining must satisfy before EVERY candidate:
// while it reports false the miner idles instead of building on a tip the
// network may have left behind. Unlike a one-time wait at startup it also stops
// a miner whose node falls behind later, and it applies to every way mining can
// be started (the daemon flag and the RPC). nil removes the gate.
func (m *Miner) SetSyncGate(gate func() bool) {
	m.gateMu.Lock()
	m.gate = gate
	m.gateMu.Unlock()
}

// gateOpen reports whether mining may proceed; with no gate it always may.
func (m *Miner) gateOpen() bool {
	m.gateMu.Lock()
	g := m.gate
	m.gateMu.Unlock()
	return g == nil || g()
}

func (m *Miner) run(ctx context.Context, threads int) {
	warned := false
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !m.gateOpen() {
			if !warned {
				m.noteError("mining paused: node is not synced with its peers")
				warned = true
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		warned = false
		// Build a fresh candidate from the current tip.
		candidate, err := m.makeCandidate()
		if err != nil {
			// A missing tip or reward store may persist; avoid a busy loop,
			// but let parent cancellation stop the miner immediately.
			m.noteError("cannot build candidate: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		// Race threads to find a nonce.
		found := m.grindBlock(ctx, candidate, threads)
		if found == nil {
			continue // context cancelled
		}
		// The reward key must be durable BEFORE the block can exist anywhere:
		// a block that lands without its key would lose the reward.
		if candidate.reward != nil {
			if err := m.cbStore.Persist(*candidate.reward); err != nil {
				m.noteError("cannot persist reward key for height %d, block withheld: %v", found.Header.Height, err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
				continue
			}
		}
		// Attempt to add. On error (e.g. someone else got it first), loop.
		if err := m.chain.AddBlock(found); err != nil {
			if !errors.Is(err, chain.ErrStale) {
				m.noteError("solved block at height %d rejected: %v", found.Header.Height, err)
			}
			continue
		}
		m.blocksFound.Add(1)
		m.confirmMined(candidate.txs)
		// Notify listeners — the daemon broadcasts via libp2p here.
		m.emit(found)
	}
}

// confirmMined clears the transactions of a block this node just mined from the
// pool. It goes through Pool.Confirmed, never Pool.Remove: the pool's own chain
// subscription may not have applied the block yet, and a removal that wins the
// race would leave nothing to stash, so a reorg of this very block could only
// re-admit the transactions as a lumped aggregate. Confirmed stashes the
// transaction itself, so it also holds for one that already left the pool while
// the block was being ground (expiry, eviction, replacement).
func (m *Miner) confirmMined(txs []*types.Transaction) {
	for _, tx := range txs {
		m.pool.Confirmed(tx)
	}
}

// candidate carries everything needed to grind one block.
type candidate struct {
	block       *types.Block
	kernelsByTx [][32]byte // mempool IDs of the included transactions
	txs         []*types.Transaction
	difficulty  uint64
	reward      *wallet.CoinbaseRecord // held in memory until the block is solved
}

func (m *Miner) makeCandidate() (*candidate, error) {
	tip, ok := m.chain.Tip()
	if !ok {
		return nil, errors.New("miner: no tip (genesis missing?)")
	}
	if tip.Height == math.MaxUint64 || tip.Timestamp == math.MaxInt64 {
		return nil, errors.New("miner: exhausted height or timestamp")
	}
	height := tip.Height + 1
	timestamp := time.Now().Unix()
	if timestamp <= tip.Timestamp {
		timestamp = tip.Timestamp + 1
	}
	difficulty := nextDifficulty(m.chain, tip)
	prevHash := types.HeaderID(&tip)

	// Bundle mempool txs.
	sel := selectTransactions(height, m.pool.Snapshot(), m.chain.ValidateTransaction, m.pool.Remove)
	inputs, outputs, kernels := sel.inputs, sel.outputs, sel.kernels
	kernelTx, selectedFees := sel.ids, sel.fees
	// Coinbase, built after transaction selection because it pays the subsidy
	// plus every selected fee: a real Pedersen commitment to reward+F bound to a
	// fresh random blinding factor persisted to the miner's coinbase store
	// (the record holds the full amount). The kernel's excess equals the commit,
	// signed with Schnorr by the blinding scalar so other nodes can verify the
	// miner owned the key. Required when reward+F > 0, forbidden when it is 0.
	reward := types.BlockReward(height)
	if selectedFees > math.MaxInt64 || int64(selectedFees) > math.MaxInt64-reward {
		return nil, errors.New("miner: coinbase amount overflow")
	}
	amount := reward + int64(selectedFees)
	var rewardRec *wallet.CoinbaseRecord
	if amount > 0 {
		if m.cbStore == nil {
			return nil, errors.New("miner: reward keystore required")
		}
		rec, err := m.cbStore.NewRecord(height, amount)
		if err != nil {
			return nil, err
		}
		sig, err := wallet.SignCoinbase(tip.NetworkMagic, rec)
		if err != nil {
			return nil, err
		}
		rewardRec = &rec
		commit := rec.Commit
		outputs = append(outputs, types.Output{Features: types.OutputFeaturesCoinbase, Commit: commit})
		kernels = append(kernels, types.Kernel{
			Features:   types.KernelFeaturesCoinbase,
			Fee:        0,
			LockHeight: height + types.CoinbaseLock,
			Excess:     commit,
			ExcessSig:  sig,
		})
	}

	hdr := types.BlockHeader{
		Version:      types.BlockVersion,
		Height:       height,
		Timestamp:    timestamp,
		PrevHash:     prevHash,
		NetworkMagic: tip.NetworkMagic,
		Difficulty:   difficulty,
	}
	block := &types.Block{Header: hdr, Inputs: inputs, Outputs: outputs, Kernels: kernels}
	types.SetBlockRoots(block)
	return &candidate{
		block:       block,
		kernelsByTx: kernelTx,
		txs:         sel.txs,
		difficulty:  difficulty,
		reward:      rewardRec,
	}, nil
}

// selection is the transaction part of a candidate block.
type selection struct {
	inputs  []types.Input
	outputs []types.Output
	kernels []types.Kernel
	txs     []*types.Transaction
	ids     [][32]byte
	fees    uint64
}

// selectTransactions packs pending transactions into a block at height while
// keeping room for the block's mandatory coinbase (chain.CoinbaseReserve). The
// reserve is re-decided on the cumulative fees, so a zero-fee transaction that
// fills a post-emission block cannot displace a coinbase a later paying
// transaction would require: that later transaction is skipped. drop discards
// transactions that turned out to be invalid or conflicting.
func selectTransactions(height uint64, txs []*types.Transaction, validate func(*types.Transaction) error, drop func([32]byte)) selection {
	var sel selection
	bodyBytes := 0
	seenOutputs := map[types.Commitment]bool{}
	for _, tx := range txs {
		size := len(types.EncodeTransaction(tx)) + 128*(len(tx.Inputs)+len(tx.Outputs)+len(tx.Kernels))
		proposedFees := sel.fees
		for _, k := range tx.Kernels {
			if k.Fee > math.MaxInt64-proposedFees {
				proposedFees = math.MaxUint64
				break
			}
			proposedFees += k.Fee
		}
		if proposedFees > math.MaxInt64 {
			continue
		}
		reserveOutputs, reserveKernels, reserveBytes := chain.CoinbaseReserve(height, proposedFees)
		if uint64(bodyBytes+size)+reserveBytes > types.MaxBlockBodyBytes || len(sel.inputs)+len(tx.Inputs) > types.MaxBlockInputs || len(sel.outputs)+len(tx.Outputs)+reserveOutputs > types.MaxBlockOutputs || len(sel.kernels)+len(tx.Kernels)+reserveKernels > types.MaxBlockKernels {
			continue
		}
		if err := validate(tx); err != nil {
			drop(mempool.TxID(tx))
			continue
		}
		txFees := proposedFees - sel.fees
		conflict := false
		for _, out := range tx.Outputs {
			if seenOutputs[out.Commit] {
				conflict = true
				break
			}
		}
		if conflict {
			drop(mempool.TxID(tx))
			continue
		}
		for _, out := range tx.Outputs {
			seenOutputs[out.Commit] = true
		}
		bodyBytes += size
		sel.fees += txFees
		sel.inputs = append(sel.inputs, tx.Inputs...)
		sel.outputs = append(sel.outputs, tx.Outputs...)
		sel.kernels = append(sel.kernels, tx.Kernels...)
		sel.txs = append(sel.txs, tx)
		sel.ids = append(sel.ids, mempool.TxID(tx))
	}
	return sel
}

func nextDifficulty(c *chain.Chain, tip types.BlockHeader) uint64 {
	return c.NextDifficulty()
}

// grindBlock spawns `threads` goroutines, each scanning a nonce stride.
// The first valid nonce wins; the rest are cancelled.
func (m *Miner) grindBlock(ctx context.Context, c *candidate, threads int) *types.Block {
	type result struct {
		header types.BlockHeader
		stale  bool
		ok     bool
	}
	out := make(chan result, threads)
	mineCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	headerTemplate := c.block.Header
	var workers sync.WaitGroup
	defer workers.Wait()
	defer cancel()
	for t := 0; t < threads; t++ {
		workers.Add(1)
		go func(start uint64) {
			defer workers.Done()
			hdr := headerTemplate
			for n := start; ; n += uint64(threads) {
				select {
				case <-mineCtx.Done():
					return
				default:
				}
				tip, ok := m.chain.Tip()
				if !ok || types.HeaderID(&tip) != hdr.PrevHash {
					out <- result{stale: true}
					return
				}
				hdr.Nonce = n
				m.hashCount.Add(1)
				if pow.Verify(&hdr) {
					out <- result{header: hdr, ok: true}
					return
				}
				// Refresh timestamp every 1024 attempts so block isn't
				// stamped at start-of-grind.
				if n%1024 == 0 {
					if now := time.Now().Unix(); now > hdr.Timestamp {
						hdr.Timestamp = now
					}
				}
			}
		}(uint64(t))
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case r := <-out:
			if r.stale {
				return nil
			}
			if r.ok {
				c.block.Header = r.header
				return c.block
			}
		}
	}
}
