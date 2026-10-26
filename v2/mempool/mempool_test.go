package mempool

import (
	"testing"

	"github.com/pasichDev/noso-go/v2/types"
)

func mkTx(fee uint64) *types.Transaction {
	return &types.Transaction{
		Kernels: []types.Kernel{{Features: types.KernelFeaturesPlain, Fee: fee, Excess: types.Commitment{byte(fee)}}},
	}
}

func TestSnapshotSortsByFeeDesc(t *testing.T) {
	// Sorting unit test uses a test-only validator, not admission validation.
	p := NewValidated(0, func(*types.Transaction) error { return nil })
	for _, fee := range []uint64{100, 5000, 1, 25, 800} {
		if _, err := p.Add(mkTx(fee)); err != nil {
			t.Fatal(err)
		}
	}
	snap := p.Snapshot()
	if len(snap) != 5 {
		t.Fatalf("want 5 entries, got %d", len(snap))
	}
	// Check descending order.
	for i := 1; i < len(snap); i++ {
		if txTotalFee(snap[i-1]) < txTotalFee(snap[i]) {
			t.Fatalf("not sorted by fee desc: %v then %v",
				txTotalFee(snap[i-1]), txTotalFee(snap[i]))
		}
	}
	if txTotalFee(snap[0]) != 5000 {
		t.Errorf("highest-fee tx not first; got fee %d", txTotalFee(snap[0]))
	}
}
