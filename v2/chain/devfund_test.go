package chain

import (
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/pasichDev/noso-go/v2/types"
)

func blk(fees []uint64, devOuts []types.Commitment) *types.Block {
	b := &types.Block{Header: types.BlockHeader{Version: types.BlockVersion}}
	for _, f := range fees {
		b.Kernels = append(b.Kernels, types.Kernel{Fee: f})
	}
	for _, c := range devOuts {
		b.Outputs = append(b.Outputs, types.Output{Features: types.OutputFeaturesDevFund, Commit: c})
	}
	return b
}

func TestExpectedDevFundCommitDeterministic(t *testing.T) {
	a, err := ExpectedDevFundCommit(&types.BlockHeader{Version: types.BlockVersion}, 12345)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ExpectedDevFundCommit(&types.BlockHeader{Version: types.BlockVersion}, 12345)
	if a != b {
		t.Fatal("dev-fund commit not deterministic")
	}
	if c, _ := ExpectedDevFundCommit(&types.BlockHeader{Version: types.BlockVersion}, 12346); c == a {
		t.Fatal("different fee totals must give different commits")
	}
}

func TestDevFund_ZeroFeeNoOutput(t *testing.T) {
	if err := validateDevFund(blk([]uint64{0, 0}, nil)); err != nil {
		t.Fatalf("zero-fee block with no dev output should pass: %v", err)
	}
}

func TestDevFund_ZeroFeeWithOutputRejected(t *testing.T) {
	bad, _ := ExpectedDevFundCommit(&types.BlockHeader{Version: types.BlockVersion}, 0)
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
	want, _ := ExpectedDevFundCommit(&types.BlockHeader{Version: types.BlockVersion}, 150)
	if err := validateDevFund(blk([]uint64{100, 50}, []types.Commitment{want})); err != nil {
		t.Fatalf("correct dev output must pass: %v", err)
	}
}

func TestDevFund_WrongValueRejected(t *testing.T) {
	wrong, _ := ExpectedDevFundCommit(&types.BlockHeader{Version: types.BlockVersion}, 149) // off by one
	err := validateDevFund(blk([]uint64{100, 50}, []types.Commitment{wrong}))
	if !errors.Is(err, ErrDevFund) {
		t.Fatalf("wrong-value dev output must be rejected, got %v", err)
	}
}

func TestDevFund_DuplicateRejected(t *testing.T) {
	want, _ := ExpectedDevFundCommit(&types.BlockHeader{Version: types.BlockVersion}, 150)
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

func TestDevFundContextBinding(t *testing.T) {
	h := types.BlockHeader{Version: types.BlockVersion, NetworkMagic: types.NetworkMagicTestnet, Height: 62}
	for i := range h.PrevHash {
		h.PrevHash[i] = byte(i)
	}
	tweak, err := DevFundBlindingTweak(&h, 100)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", tweak); got != "873dd7d4e70edf94d29a24b7ae9880fa99e3099e95dc2e62a1232614dd39cf75" {
		t.Fatalf("canonical tweak vector: %s", got)
	}
	want, err := ExpectedDevFundCommit(&h, 100)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*types.BlockHeader){
		"height":  func(h *types.BlockHeader) { h.Height++ },
		"parent":  func(h *types.BlockHeader) { h.PrevHash[0] ^= 1 },
		"network": func(h *types.BlockHeader) { h.NetworkMagic ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			other := h
			mutate(&other)
			c, err := ExpectedDevFundCommit(&other, 100)
			if err != nil {
				t.Fatal(err)
			}
			if c == want {
				t.Fatal("context reused commitment")
			}
			b := blk([]uint64{100}, []types.Commitment{c})
			b.Header = h
			if !errors.Is(validateDevFund(b), ErrDevFund) {
				t.Fatal("wrong-context commitment accepted")
			}
		})
	}
	mined := h
	mined.Nonce++
	mined.Timestamp++
	mined.OutputRoot[0] ^= 1
	got, err := ExpectedDevFundCommit(&mined, 100)
	if err != nil || got != want {
		t.Fatalf("mining-variable circular dependency: %v", err)
	}
	old := h
	old.Version = 2
	if _, err := ExpectedDevFundCommit(&old, 100); err == nil {
		t.Fatal("v2 header accepted")
	}
	if _, err := ExpectedDevFundCommit(nil, 100); err == nil {
		t.Fatal("nil header accepted")
	}
	if _, err := ExpectedDevFundCommit(&h, math.MaxUint64); err == nil {
		t.Fatal("overflow accepted")
	}
}
