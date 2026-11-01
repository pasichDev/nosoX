package mempool

import (
	"testing"

	"github.com/pasichDev/nosoX/v2/types"
)

// minedBlock is the block a miner builds from txs: their parts, concatenated.
func minedBlock(txs ...*types.Transaction) *types.Block {
	b := &types.Block{}
	for _, tx := range txs {
		b.Inputs = append(b.Inputs, tx.Inputs...)
		b.Outputs = append(b.Outputs, tx.Outputs...)
		b.Kernels = append(b.Kernels, tx.Kernels...)
	}
	return b
}

// wantRestored requires the pool to hold exactly the given transactions, each as
// the sender built it. A block does not record where one transaction ends, so a
// pool that lost the originals can only re-admit one lumped aggregate.
func wantRestored(t *testing.T, p *Pool, txs ...*types.Transaction) {
	t.Helper()
	if p.Len() != len(txs) {
		t.Fatalf("pool holds %d entries, want %d separate transactions", p.Len(), len(txs))
	}
	have := map[[32]byte]bool{}
	for _, tx := range p.Snapshot() {
		have[TxID(tx)] = true
	}
	for _, tx := range txs {
		if !have[TxID(tx)] {
			t.Fatal("original transaction was not restored as built")
		}
	}
}

// A transaction the node mined must be restorable intact after a reorg of its
// own block, whichever way the miner's call and the chain subscription's
// ApplyChange interleave, and even if the transaction left the pool while the
// block was being ground.
func TestConfirmedKeepsMinedTransactionsForReorg(t *testing.T) {
	a, b := spendTx(1, 10, 1), spendTx(2, 10, 2)
	for _, tc := range []struct {
		name string
		run  func(p *Pool, blk *types.Block)
	}{
		{"miner first, subscription later", func(p *Pool, blk *types.Block) {
			p.Confirmed(a)
			p.Confirmed(b)
			p.ApplyChange(nil, []*types.Block{blk})
		}},
		{"subscription first, miner later", func(p *Pool, blk *types.Block) {
			p.ApplyChange(nil, []*types.Block{blk})
			p.Confirmed(a)
			p.Confirmed(b)
		}},
		{"left the pool before the block was solved", func(p *Pool, blk *types.Block) {
			p.Remove(TxID(a))
			p.Remove(TxID(b))
			p.Confirmed(a)
			p.Confirmed(b)
			p.ApplyChange(nil, []*types.Block{blk})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewValidated(8, okValidator)
			for _, tx := range []*types.Transaction{a, b} {
				if _, err := p.Add(tx); err != nil {
					t.Fatal(err)
				}
			}
			blk := minedBlock(a, b)
			tc.run(p, blk)
			if p.Len() != 0 {
				t.Fatalf("mined transactions still pooled: %d", p.Len())
			}
			p.ApplyChange([]*types.Block{blk}, nil)
			wantRestored(t, p, a, b)
		})
	}
}

// The control: dropping a mined transaction with Remove, before the block is
// applied, loses the original boundaries. This is what Confirmed exists to avoid.
func TestRemoveBeforeApplyLosesTransactionBoundaries(t *testing.T) {
	a, b := spendTx(1, 10, 1), spendTx(2, 10, 2)
	p := NewValidated(8, okValidator)
	for _, tx := range []*types.Transaction{a, b} {
		if _, err := p.Add(tx); err != nil {
			t.Fatal(err)
		}
	}
	blk := minedBlock(a, b)
	p.Remove(TxID(a))
	p.Remove(TxID(b))
	p.ApplyChange(nil, []*types.Block{blk})
	p.ApplyChange([]*types.Block{blk}, nil)
	if p.Len() != 1 {
		t.Fatalf("control expected one lumped aggregate, got %d entries", p.Len())
	}
}
