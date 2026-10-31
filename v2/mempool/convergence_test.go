package mempool

import (
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/pasichDev/noso-go/v2/chain"
	"github.com/pasichDev/noso-go/v2/types"
)

// matureChain builds a chain with CoinbaseLock blocks and returns the first two
// blocks with their coinbase blindings (spendable by spendCoinbase).
func matureChain(t *testing.T) (c *chain.Chain, forkPoint types.Hash, srcs [2]*types.Block, blinds [2][32]byte) {
	t.Helper()
	g := attachGenesis()
	c = chain.NewMemory()
	if err := c.LoadOrInit(filepath.Join(t.TempDir(), "chain"), g); err != nil {
		t.Fatal(err)
	}
	parent := types.HeaderID(&g.Header)
	for h := uint64(1); h <= types.CoinbaseLock+1; h++ { // the second coinbase matures at height 62
		b := attachBlock(t, parent, h, 0, nil)
		if h <= 2 {
			srcs[h-1], blinds[h-1] = b, cbBlind(parent, h, 0)
		}
		if err := c.AddBlock(b); err != nil {
			t.Fatalf("block %d: %v", h, err)
		}
		parent = types.HeaderID(&b.Header)
	}
	return c, parent, srcs, blinds
}

// withTxs returns b carrying txs (b must be at difficulty 1).
func withTxs(b *types.Block, txs ...*types.Transaction) *types.Block {
	for _, tx := range txs {
		b.Inputs = append(b.Inputs, tx.Inputs...)
		b.Outputs = append(b.Outputs, tx.Outputs...)
		b.Kernels = append(b.Kernels, tx.Kernels...)
	}
	types.SetBlockRoots(b)
	return b
}

func poolIDs(p *Pool) map[[32]byte]bool {
	out := map[[32]byte]bool{}
	for _, tx := range p.Snapshot() {
		out[TxID(tx)] = true
	}
	return out
}

// One block held A and B; the branch that replaces it keeps only A. B must come
// back to the pool: re-admission used to be one aggregate for the whole block,
// which fails as a unit as soon as A is already on the new branch (R1).
func TestReorgPartialInclusionRestoresTheRest(t *testing.T) {
	for _, seen := range []bool{true, false} {
		name := map[bool]string{true: "pool saw both transactions", false: "pool never saw them"}[seen]
		t.Run(name, func(t *testing.T) {
			c, fork, srcs, blinds := matureChain(t)
			pool := NewValidated(0, c.ValidateTransaction)
			att := Attach(c, pool)
			defer att.Stop()
			a := spendCoinbase(t, srcs[0], blinds[0])
			b := spendCoinbase(t, srcs[1], blinds[1])
			if seen {
				for _, tx := range []*types.Transaction{a, b} {
					if _, err := pool.Add(tx); err != nil {
						t.Fatal(err)
					}
				}
			}
			x := withTxs(attachBlock(t, fork, types.CoinbaseLock+2, 0, nil), a, b)
			if err := c.AddBlock(x); err != nil {
				t.Fatalf("block with A and B: %v", err)
			}
			att.Wait()
			if pool.Len() != 0 {
				t.Fatalf("confirmed transactions still pooled: %d", pool.Len())
			}
			// The replacing branch keeps A only.
			y1 := withTxs(attachBlock(t, fork, types.CoinbaseLock+2, 1, nil), a)
			y2 := attachBlock(t, types.HeaderID(&y1.Header), types.CoinbaseLock+3, 1, nil)
			if err := c.ReorgTo([]*types.Block{y1, y2}); err != nil {
				t.Fatalf("reorg: %v", err)
			}
			att.Wait()
			ids := poolIDs(pool)
			if !ids[TxID(b)] {
				t.Fatalf("B vanished from the pool after a partial-inclusion reorg (pool has %d)", len(ids))
			}
			if ids[TxID(a)] {
				t.Fatal("A is on the new branch and must not be pooled")
			}
		})
	}
}

// A transaction the pool pushed out must not have displaced anything when it is
// refused after all.
func TestRefusedAdmissionEvictsNothing(t *testing.T) {
	old := errMaxPoolSize
	defer func() { errMaxPoolSize = old }()
	mk := func(seed byte, fee uint64, proof int) *types.Transaction {
		return &types.Transaction{
			Inputs:  []types.Input{{Commit: types.Commitment{2, seed}}},
			Outputs: []types.Output{{Commit: types.Commitment{3, seed}, RangeProof: make([]byte, proof)}},
			Kernels: []types.Kernel{{Fee: fee, Excess: types.Commitment{4, seed}, ExcessSig: make([]byte, 65)}},
		}
	}
	p := NewValidated(8, func(*types.Transaction) error { return nil })
	p.SetPolicy(Policy{})
	low, high := mk(1, 1_000, 1000), mk(2, 1_000_000, 1000)
	for _, tx := range []*types.Transaction{low, high} {
		if _, err := p.Add(tx); err != nil {
			t.Fatal(err)
		}
	}
	// newcomer conflicts with `low` (same input), pays more per byte than `low`
	// but is big enough that `high` would also have to go.
	nc := mk(3, 20_000, 2200)
	nc.Inputs[0].Commit = low.Inputs[0].Commit
	errMaxPoolSize = p.bytes + 800
	_, err := p.Add(nc)
	if !errors.Is(err, ErrFull) {
		t.Fatalf("expected ErrFull, got %v", err)
	}
	ids := poolIDs(p)
	if !ids[TxID(low)] || !ids[TxID(high)] {
		t.Fatalf("a refused admission still evicted entries (pool has %d)", len(ids))
	}
}

// The chain may move between validating a transaction and inserting it.
func TestAdmissionRevalidatesWhenTheChainMoved(t *testing.T) {
	var calls atomic.Int32
	var p *Pool
	confirmed := false
	p = NewValidated(8, func(*types.Transaction) error {
		n := calls.Add(1)
		if n == 1 {
			p.ApplyChange(nil, nil) // a block connects while we validate
			confirmed = true        // ...and it confirmed this transaction
			return nil
		}
		if confirmed {
			return errors.New("confirmed")
		}
		return nil
	})
	p.SetPolicy(Policy{})
	tx := &types.Transaction{
		Inputs:  []types.Input{{Commit: types.Commitment{2, 1}}},
		Outputs: []types.Output{{Commit: types.Commitment{3, 1}, RangeProof: make([]byte, 100)}},
		Kernels: []types.Kernel{{Fee: 1000, Excess: types.Commitment{4, 1}, ExcessSig: make([]byte, 65)}},
	}
	if _, err := p.Add(tx); err == nil {
		t.Fatal("a transaction confirmed during validation was pooled")
	}
	if calls.Load() < 2 {
		t.Fatalf("validated %d time(s): the stale verdict was trusted", calls.Load())
	}
	if p.Len() != 0 {
		t.Fatal("stale transaction retained")
	}
}
