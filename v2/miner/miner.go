// Package miner runs the NosoX PoW grind. CPU-only, multi-goroutine,
// designed to peak on a Raspberry Pi 4 at 5–15 H/s and on a modern
// laptop at 50–200 H/s — comfortable scale for solo mining.
package miner

import (
	"context"
	"errors"
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

// Miner produces blocks from mempool + current tip.
type Miner struct {
	chain    *chain.Chain
	pool     *mempool.Pool
	cbStore  *wallet.CoinbaseStore // where fresh blinds + commits get persisted
	rewardTo string                // human-readable label stamped into the kernel preimage

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
}

// State describes the miner's current activity.
type State int

const (
	StateIdle State = iota
	StateMining
)

// New constructs an unstarted miner. A coinbase keystore is required whenever
// subsidy is positive; candidate construction fails if reward keys cannot persist.
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
	if threads > 16 {
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
	return Stats{State: state, Hashes: h, Elapsed: elapsed, HashesPS: hps}
}

// ErrAlreadyMining is returned when Start is called twice without a
// Stop in between.
var ErrAlreadyMining = errors.New("miner: already mining")

func (m *Miner) run(ctx context.Context, threads int) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Build a fresh candidate from the current tip.
		candidate, err := m.makeCandidate()
		if err != nil {
			// A missing tip or reward store may persist; avoid a busy loop,
			// but let parent cancellation stop the miner immediately.
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
		// Attempt to add. On error (e.g. someone else got it first), loop.
		if err := m.chain.AddBlock(found); err != nil {
			continue
		}
		// Clear confirmed transactions from the mempool.
		for _, tx := range candidate.kernelsByTx {
			m.pool.Remove(tx)
		}
		// Notify listeners — the daemon broadcasts via libp2p here.
		m.emit(found)
	}
}

// candidate carries everything needed to grind one block.
type candidate struct {
	block       *types.Block
	kernelsByTx [][32]byte // mempool IDs of the included transactions
	difficulty  uint64
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
	txs := m.pool.Snapshot()
	var (
		inputs   []types.Input
		outputs  []types.Output
		kernels  []types.Kernel
		kernelTx [][32]byte
	)
	bodyBytes := 0
	var selectedFees uint64
	seenOutputs := map[types.Commitment]bool{}
	for _, tx := range txs {
		size := len(types.EncodeTransaction(tx)) + 128*(len(tx.Inputs)+len(tx.Outputs)+len(tx.Kernels))
		reserveOutputs, reserveKernels := 0, 0
		if types.BlockReward(height) > 0 {
			reserveOutputs++
			reserveKernels++
		}
		proposedFees := selectedFees
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
		if proposedFees > 0 {
			reserveOutputs++
		}
		if bodyBytes+size+reserveOutputs*128+reserveKernels*(128+65) > types.MaxBlockBodyBytes || len(inputs)+len(tx.Inputs) > types.MaxBlockInputs || len(outputs)+len(tx.Outputs)+reserveOutputs > types.MaxBlockOutputs || len(kernels)+len(tx.Kernels)+reserveKernels > types.MaxBlockKernels {
			continue
		}
		if err := m.chain.ValidateTransaction(tx); err != nil {
			m.pool.Remove(mempool.TxID(tx))
			continue
		}
		var txFees uint64
		for _, k := range tx.Kernels {
			txFees += k.Fee
		}
		if txFees > math.MaxInt64-selectedFees {
			continue
		}
		conflict := false
		for _, out := range tx.Outputs {
			if seenOutputs[out.Commit] {
				conflict = true
				break
			}
		}
		if conflict {
			m.pool.Remove(mempool.TxID(tx))
			continue
		}
		for _, out := range tx.Outputs {
			seenOutputs[out.Commit] = true
		}
		bodyBytes += size
		selectedFees += txFees
		inputs = append(inputs, tx.Inputs...)
		outputs = append(outputs, tx.Outputs...)
		kernels = append(kernels, tx.Kernels...)
		kernelTx = append(kernelTx, mempool.TxID(tx))
	}
	// Coinbase output: a real Pedersen commitment bound to a fresh
	// random blinding factor persisted to the miner's coinbase store.
	// The kernel's excess equals the commit, signed with Schnorr by the
	// blinding scalar so other nodes can verify the miner owned the key.
	reward := types.BlockReward(height)
	if reward > 0 {
		if m.cbStore == nil {
			return nil, errors.New("miner: reward keystore required")
		}
		rec, err := m.cbStore.Allocate(height, reward)
		if err != nil {
			return nil, err
		}
		sig, err := wallet.SignCoinbase(rec)
		if err != nil {
			return nil, err
		}
		commit := rec.Commit
		coinbase := types.Output{
			Features: types.OutputFeaturesCoinbase,
			Commit:   commit,
		}
		outputs = append(outputs, coinbase)
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
	// Route exactly the public fees to the fixed developer recipient, with a
	// version-3 public blinding tweak bound to this parent and height.
	totalFee := selectedFees
	if totalFee > 0 {
		dc, err := chain.ExpectedDevFundCommit(&hdr, totalFee)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, types.Output{Features: types.OutputFeaturesDevFund, Commit: dc})
	}

	block := &types.Block{Header: hdr, Inputs: inputs, Outputs: outputs, Kernels: kernels}
	types.SetBlockRoots(block)
	return &candidate{
		block:       block,
		kernelsByTx: kernelTx,
		difficulty:  difficulty,
	}, nil
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
