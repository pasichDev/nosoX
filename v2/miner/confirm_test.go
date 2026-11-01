package miner

import (
	"errors"
	"math"
	"testing"

	"github.com/pasichDev/nosoX/v2/chain"
	"github.com/pasichDev/nosoX/v2/mempool"
	"github.com/pasichDev/nosoX/v2/types"
)

func minerTx(in byte, fee uint64, outputs int) *types.Transaction {
	tx := &types.Transaction{
		Inputs:  []types.Input{{Commit: types.Commitment{in}}},
		Kernels: []types.Kernel{{Features: types.KernelFeaturesPlain, Fee: fee, Excess: types.Commitment{in, 9}, ExcessSig: make([]byte, 65)}},
	}
	for i := 0; i < outputs; i++ {
		tx.Outputs = append(tx.Outputs, types.Output{Commit: types.Commitment{in, byte(i + 1)}, RangeProof: make([]byte, 100)})
	}
	return tx
}

// A block this node mined must stay restorable as the sender built it. The miner
// clears its transactions through Pool.Confirmed; a plain Remove can win the race
// against the chain subscription and leave a reorg nothing to restore from.
func TestMinedTransactionsAreStashedForReorg(t *testing.T) {
	a, b := minerTx(1, 10, 1), minerTx(2, 10, 1)
	pool := mempool.NewValidated(8, func(*types.Transaction) error { return nil })
	for _, tx := range []*types.Transaction{a, b} {
		if _, err := pool.Add(tx); err != nil {
			t.Fatal(err)
		}
	}
	m := New(chain.NewMemory(), pool, nil)
	m.confirmMined(pool.Snapshot())
	if pool.Len() != 0 {
		t.Fatalf("mined transactions still pooled: %d", pool.Len())
	}
	blk := &types.Block{}
	for _, tx := range []*types.Transaction{a, b} {
		blk.Inputs = append(blk.Inputs, tx.Inputs...)
		blk.Outputs = append(blk.Outputs, tx.Outputs...)
		blk.Kernels = append(blk.Kernels, tx.Kernels...)
	}
	// The subscription applies the block afterwards; then the block is reorged.
	pool.ApplyChange(nil, []*types.Block{blk})
	pool.ApplyChange([]*types.Block{blk}, nil)
	if pool.Len() != 2 {
		t.Fatalf("reorg restored %d entries, want the 2 original transactions", pool.Len())
	}
}

func selectedIDs(sel selection) map[[32]byte]bool {
	ids := map[[32]byte]bool{}
	for _, id := range sel.ids {
		ids[id] = true
	}
	return ids
}

// miner.go: the selection keeps room for the mandatory coinbase, decided by the
// cumulative fees. Heights straddle the end of the subsidy.
func TestSelectionReservesCoinbaseCapacity(t *testing.T) {
	end := types.BlockHalvingInterval * (types.HalvingSteps + 1)
	ok := func(*types.Transaction) error { return nil }
	drop := func([32]byte) {}

	t.Run("subsidy block: 4 outputs leave no room", func(t *testing.T) {
		tx := minerTx(1, 0, 4)
		if sel := selectTransactions(end-1, []*types.Transaction{tx}, ok, drop); len(sel.ids) != 0 {
			t.Fatal("selected a transaction that leaves no room for the coinbase")
		}
		if sel := selectTransactions(end-1, []*types.Transaction{minerTx(1, 0, 3)}, ok, drop); len(sel.ids) != 1 {
			t.Fatal("3 outputs plus the coinbase must fit")
		}
	})
	t.Run("no subsidy, no fee: nothing reserved", func(t *testing.T) {
		tx := minerTx(1, 0, 4)
		sel := selectTransactions(end, []*types.Transaction{tx}, ok, drop)
		if len(sel.ids) != 1 || len(sel.outputs) != 4 {
			t.Fatal("a zero-fee transaction needs no coinbase and may use all 4 outputs")
		}
	})
	t.Run("no subsidy, fee: one slot reserved", func(t *testing.T) {
		tx := minerTx(1, 100, 4)
		if sel := selectTransactions(end, []*types.Transaction{tx}, ok, drop); len(sel.ids) != 0 {
			t.Fatal("selected a fee-paying transaction with no room for its coinbase")
		}
	})
	t.Run("no subsidy: a zero-fee transaction cannot displace a required coinbase", func(t *testing.T) {
		filler, payer := minerTx(1, 0, 3), minerTx(2, 100, 1)
		sel := selectTransactions(end, []*types.Transaction{filler, payer}, ok, drop)
		ids := selectedIDs(sel)
		if !ids[mempool.TxID(filler)] || ids[mempool.TxID(payer)] {
			t.Fatalf("selected %d transactions, want only the zero-fee filler", len(sel.ids))
		}
		if len(sel.outputs)+1 > types.MaxBlockOutputs {
			t.Fatal("no room left for the coinbase")
		}
	})
	t.Run("invalid transactions are dropped", func(t *testing.T) {
		var dropped int
		bad := func(*types.Transaction) error { return errors.New("invalid") }
		sel := selectTransactions(end, []*types.Transaction{minerTx(1, 0, 1)}, bad, func([32]byte) { dropped++ })
		if len(sel.ids) != 0 || dropped != 1 {
			t.Fatal("invalid transaction was kept or not dropped")
		}
	})
	t.Run("fees are summed", func(t *testing.T) {
		sel := selectTransactions(end, []*types.Transaction{minerTx(1, 7, 1), minerTx(2, 5, 1)}, ok, drop)
		if sel.fees != 12 || len(sel.ids) != 2 {
			t.Fatalf("fees = %d, selected %d", sel.fees, len(sel.ids))
		}
		over := selectTransactions(end, []*types.Transaction{minerTx(1, math.MaxInt64, 1), minerTx(2, 1, 1)}, ok, drop)
		if over.fees > math.MaxInt64 {
			t.Fatal("selected fees exceed MaxInt64")
		}
	})
}
