// Package miner runs the NosoX PoW grind. CPU-only, multi-goroutine,
// designed to peak on a Raspberry Pi 4 at 5–15 H/s and on a modern
// laptop at 50–200 H/s — comfortable scale for solo mining.
package miner

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/noso-project/noso-go/v2/chain"
	"github.com/noso-project/noso-go/v2/mempool"
	"github.com/noso-project/noso-go/v2/pow"
	"github.com/noso-project/noso-go/v2/types"
	"github.com/noso-project/noso-go/v2/wallet"
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

// New constructs an unstarted miner. cb may be nil, in which case the
// miner still mines but does NOT persist its coinbase blinding factors
// — meaning it cannot later spend its own rewards. Production callers
// must pass a non-nil CoinbaseStore.
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
	defer m.listenersMu.RUnlock()
	for _, fn := range m.listeners {
		fn(b)
	}
}

// Start begins mining with the given thread count and reward address.
// Calls return ErrAlreadyMining if a previous Start hasn't been stopped.
func (m *Miner) Start(ctx context.Context, threads int, rewardTo string) error {
	if threads < 1 {
		threads = 1
	}
	m.mu.Lock()
	if m.state == StateMining {
		m.mu.Unlock()
		return ErrAlreadyMining
	}
	innerCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.state = StateMining
	m.rewardTo = rewardTo
	m.hashCount.Store(0)
	m.startedAt = time.Now()
	m.mu.Unlock()

	go m.run(innerCtx, threads)
	return nil
}

// Stop halts mining.
func (m *Miner) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
	m.state = StateIdle
}

// Stats returns hashes-per-second since Start was last called.
type Stats struct {
	State     State
	Hashes    uint64
	Elapsed   time.Duration
	HashesPS  float64
}

// Stats returns a snapshot of the current activity.
func (m *Miner) Stats() Stats {
	m.mu.Lock()
	state := m.state
	m.mu.Unlock()
	elapsed := time.Since(m.startedAt)
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
			time.Sleep(2 * time.Second)
			continue
		}
		// Race threads to find a nonce.
		found := m.grindBlock(ctx, candidate, threads)
		if found == nil {
			continue // ctx cancelled or new tip arrived
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
	height := tip.Height + 1
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
	for _, tx := range txs {
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
		var (
			commit [33]byte
			sig    []byte
			cbRec  wallet.CoinbaseRecord
		)
		if m.cbStore != nil {
			r, err := m.cbStore.Allocate(height, reward)
			if err == nil {
				cbRec = r
				commit = r.Commit
				if s, err := wallet.SignCoinbase(r); err == nil {
					sig = s
				}
			} else {
				commit = coinbaseCommit(m.rewardTo, height) // fallback (cannot be spent)
			}
		} else {
			commit = coinbaseCommit(m.rewardTo, height)
		}
		_ = cbRec
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
		Version:    types.BlockVersion,
		Height:     height,
		Timestamp:  time.Now().Unix(),
		PrevHash:   prevHash,
		OutputRoot: merkleOutputs(outputs),
		KernelRoot: merkleKernels(kernels),
		Difficulty: difficulty,
	}
	return &candidate{
		block:       &types.Block{Header: hdr, Inputs: inputs, Outputs: outputs, Kernels: kernels},
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
		nonce uint64
		ok    bool
	}
	out := make(chan result, threads)
	mineCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for t := 0; t < threads; t++ {
		go func(start uint64) {
			hdr := c.block.Header
			for n := start; ; n += uint64(threads) {
				select {
				case <-mineCtx.Done():
					return
				default:
				}
				hdr.Nonce = n
				m.hashCount.Add(1)
				if pow.Verify(&hdr) {
					out <- result{nonce: n, ok: true}
					return
				}
				// Refresh timestamp every 1024 attempts so block isn't
				// stamped at start-of-grind.
				if n%1024 == 0 {
					hdr.Timestamp = time.Now().Unix()
				}
			}
		}(uint64(t))
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case r := <-out:
			if r.ok {
				c.block.Header.Nonce = r.nonce
				return c.block
			}
		}
	}
}

func coinbaseCommit(rewardTo string, height uint64) types.Commitment {
	h := sha256.Sum256([]byte("coinbase:" + rewardTo + ":" + uint64ToStr(height)))
	var c types.Commitment
	c[0] = 0x02
	copy(c[1:], h[:32])
	return c
}

func uint64ToStr(n uint64) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	return string(buf[i:])
}

func merkleOutputs(outs []types.Output) types.Hash {
	leaves := make([]types.Hash, len(outs))
	for i := range outs {
		leaves[i] = types.OutputID(&outs[i])
	}
	return merkle(leaves)
}

func merkleKernels(kernels []types.Kernel) types.Hash {
	leaves := make([]types.Hash, len(kernels))
	for i := range kernels {
		leaves[i] = types.KernelID(&kernels[i])
	}
	return merkle(leaves)
}

func merkle(leaves []types.Hash) types.Hash {
	if len(leaves) == 0 {
		return types.Hash{}
	}
	level := make([]types.Hash, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([]types.Hash, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			var buf [64]byte
			copy(buf[:32], level[i][:])
			copy(buf[32:], level[i+1][:])
			next[i/2] = sha256.Sum256(buf[:])
		}
		level = next
	}
	return level[0]
}
