package mempool

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pasichDev/nosoX/v2/types"
)

func okValidator(*types.Transaction) error { return nil }

// spendTx builds a distinguishable transaction spending in with the given fee.
func spendTx(in byte, fee uint64, tag byte) *types.Transaction {
	return &types.Transaction{
		Inputs:  []types.Input{{Commit: types.Commitment{in}}},
		Outputs: []types.Output{{Commit: types.Commitment{tag, 1}, RangeProof: make([]byte, 100)}},
		Kernels: []types.Kernel{{Features: types.KernelFeaturesPlain, Fee: fee, Excess: types.Commitment{tag}}},
	}
}

func TestMinimumRelayFee(t *testing.T) {
	p := NewValidated(8, okValidator)
	p.SetPolicy(Policy{MinFeeRate: 1000})
	tx := spendTx(1, 0, 1)
	_, err := p.Add(tx)
	if !errors.Is(err, ErrFeeTooLow) || !IsPolicy(err) {
		t.Fatalf("zero-fee tx: %v", err)
	}
	if want := fmt.Sprint(MinFee(1000, transactionSize(tx))); !strings.Contains(err.Error(), "relay minimum is "+want) {
		t.Fatalf("error does not name the minimum fee %s: %v", want, err)
	}
	size := uint64(transactionSize(tx))
	paid := spendTx(1, size, 1) // exactly 1000 per 1000 bytes
	if _, err := p.Add(paid); err != nil {
		t.Fatalf("tx at the minimum rate: %v", err)
	}
}

// N13: a zero-fee flood must not lock out higher-paying transactions.
func TestFullPoolEvictsLowestFeeRate(t *testing.T) {
	p := NewValidated(3, okValidator)
	for i := byte(1); i <= 3; i++ {
		if _, err := p.Add(spendTx(i, uint64(i)*10, i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Add(spendTx(9, 5, 9)); !errors.Is(err, ErrFull) {
		t.Fatalf("a lower-paying tx must not displace others: %v", err)
	}
	if _, err := p.Add(spendTx(10, 100, 10)); err != nil {
		t.Fatalf("high-fee tx refused by a full pool: %v", err)
	}
	if p.Len() != 3 {
		t.Fatalf("len %d", p.Len())
	}
	for _, tx := range p.Snapshot() {
		if txTotalFee(tx) == 10 {
			t.Fatal("lowest-fee entry survived eviction")
		}
	}
}

func TestReplacementRequiresHigherFeeRateAndAbsoluteFee(t *testing.T) {
	p := NewValidated(8, okValidator)
	if _, err := p.Add(spendTx(1, 100, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Add(spendTx(1, 100, 2)); !errors.Is(err, ErrConflict) {
		t.Fatalf("equal fee replaced: %v", err)
	}
	if _, err := p.Add(spendTx(1, 500, 3)); err != nil {
		t.Fatalf("higher fee should replace: %v", err)
	}
	snap := p.Snapshot()
	if len(snap) != 1 || txTotalFee(snap[0]) != 500 {
		t.Fatalf("pool after replacement: %d entries", len(snap))
	}
	// The displaced entry no longer pins its input or kernel.
	if len(p.spent) != 1 || len(p.kernels) != 1 {
		t.Fatalf("index leak: spent=%d kernels=%d", len(p.spent), len(p.kernels))
	}
}

func TestExpiry(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	p := NewValidated(8, okValidator)
	p.now = func() time.Time { return now }
	p.SetPolicy(Policy{TTL: time.Hour})
	if _, err := p.Add(spendTx(1, 10, 1)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Minute)
	if _, err := p.Add(spendTx(2, 10, 2)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(45 * time.Minute)
	if got := p.Snapshot(); len(got) != 1 {
		t.Fatalf("after ttl: %d entries, want 1", len(got))
	}
	if len(p.spent) != 1 || p.bytes <= 0 {
		t.Fatalf("expiry leaked index entries: spent=%d bytes=%d", len(p.spent), p.bytes)
	}
}

// N2: confirmed and conflicting transactions leave on every block.
func TestApplyChangeRemovesConfirmedAndConflicting(t *testing.T) {
	p := NewValidated(8, okValidator)
	confirmed, conflicting, other := spendTx(1, 10, 1), spendTx(2, 10, 2), spendTx(3, 10, 3)
	for _, tx := range []*types.Transaction{confirmed, conflicting, other} {
		if _, err := p.Add(tx); err != nil {
			t.Fatal(err)
		}
	}
	block := &types.Block{
		Inputs:  append(append([]types.Input{}, confirmed.Inputs...), conflicting.Inputs...),
		Outputs: append([]types.Output{}, confirmed.Outputs...),
		Kernels: append([]types.Kernel{}, confirmed.Kernels...),
	}
	// The block spends the conflicting tx's input through a different kernel.
	block.Kernels = append(block.Kernels, types.Kernel{Features: types.KernelFeaturesPlain, Fee: 1, Excess: types.Commitment{77}})
	p.ApplyChange(nil, []*types.Block{block})
	if p.Len() != 1 || TxID(p.Snapshot()[0]) != TxID(other) {
		t.Fatalf("pool after block: %d entries", p.Len())
	}
}

// N2: a reorg returns valid orphaned transactions and drops those that lost their inputs.
func TestApplyChangeReadmitsOrphanedAndRevalidates(t *testing.T) {
	valid := map[types.Commitment]bool{{9}: true}
	p := NewValidated(8, func(tx *types.Transaction) error {
		for _, in := range tx.Inputs {
			if !valid[in.Commit] {
				return errors.New("input missing")
			}
		}
		return nil
	})
	// Pending tx spends an output created by the block about to be disconnected.
	dependent := spendTx(0, 10, 5)
	dependent.Inputs = []types.Input{{Commit: types.Commitment{4, 1}}}
	valid[types.Commitment{4, 1}] = true
	if _, err := p.Add(dependent); err != nil {
		t.Fatal(err)
	}
	orphan := spendTx(9, 20, 4) // output commit {4,1}
	disc := &types.Block{
		Inputs:  orphan.Inputs,
		Outputs: orphan.Outputs,
		Kernels: orphan.Kernels,
	}
	// On the new chain the orphan's output does not exist, its input does.
	valid[types.Commitment{4, 1}] = false
	p.ApplyChange([]*types.Block{disc}, nil)
	snap := p.Snapshot()
	if len(snap) != 1 || TxID(snap[0]) != TxID(orphan) {
		t.Fatalf("want only the re-admitted orphan, got %d entries", len(snap))
	}
}
