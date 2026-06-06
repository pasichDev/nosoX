package chain

import (
	"errors"
	"testing"

	"github.com/noso-project/noso-go/v2/types"
)

func blk(fees []uint64, devOuts []types.Commitment) *types.Block {
	b := &types.Block{}
	for _, f := range fees {
		b.Kernels = append(b.Kernels, types.Kernel{Fee: f})
	}
	for _, c := range devOuts {
		b.Outputs = append(b.Outputs, types.Output{Features: types.OutputFeaturesDevFund, Commit: c})
	}
	return b
}

func TestExpectedDevFundCommitDeterministic(t *testing.T) {
	a, err := ExpectedDevFundCommit(12345)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ExpectedDevFundCommit(12345)
	if a != b {
		t.Fatal("dev-fund commit not deterministic")
	}
	if c, _ := ExpectedDevFundCommit(12346); c == a {
		t.Fatal("different fee totals must give different commits")
	}
}

func TestDevFund_ZeroFeeNoOutput(t *testing.T) {
	if err := validateDevFund(blk([]uint64{0, 0}, nil)); err != nil {
		t.Fatalf("zero-fee block with no dev output should pass: %v", err)
	}
}

func TestDevFund_ZeroFeeWithOutputRejected(t *testing.T) {
	bad, _ := ExpectedDevFundCommit(0)
	err := validateDevFund(blk([]uint64{0}, []types.Commitment{bad}))
	if !errors.Is(err, ErrDevFund) {
		t.Fatalf("zero-fee block WITH a dev output must be rejected, got %v", err)
	}
}

func TestDevFund_FeeRequiresOutput(t *testing.T) {
	err := validateDevFund(blk([]uint64{100, 50}, nil))
	if !errors.Is(err, ErrDevFund) {
		t.Fatalf("fee-bearing block with no dev output must be rejected, got %v", err)
	}
}

func TestDevFund_CorrectOutputAccepted(t *testing.T) {
	want, _ := ExpectedDevFundCommit(150)
	if err := validateDevFund(blk([]uint64{100, 50}, []types.Commitment{want})); err != nil {
		t.Fatalf("correct dev output must pass: %v", err)
	}
}

func TestDevFund_WrongValueRejected(t *testing.T) {
	wrong, _ := ExpectedDevFundCommit(149) // off by one
	err := validateDevFund(blk([]uint64{100, 50}, []types.Commitment{wrong}))
	if !errors.Is(err, ErrDevFund) {
		t.Fatalf("wrong-value dev output must be rejected, got %v", err)
	}
}

func TestDevFund_DuplicateRejected(t *testing.T) {
	want, _ := ExpectedDevFundCommit(150)
	err := validateDevFund(blk([]uint64{150}, []types.Commitment{want, want}))
	if !errors.Is(err, ErrDevFund) {
		t.Fatalf("duplicate dev outputs must be rejected, got %v", err)
	}
}

func TestTotalKernelFee(t *testing.T) {
	if got := TotalKernelFee(blk([]uint64{1, 2, 3, 0}, nil)); got != 6 {
		t.Fatalf("TotalKernelFee = %d, want 6", got)
	}
}
