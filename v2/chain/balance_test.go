package chain

import (
	"crypto/rand"
	"testing"

	v2crypto "github.com/noso-project/noso-go/v2/crypto"
	"github.com/noso-project/noso-go/v2/types"
)

// buildSpend constructs a real, balanced 1-in/1-out transaction with the given
// fee: out value = in value − fee, and kernel excess = (r_out − r_in)·G.
func buildSpend(t *testing.T, inVal, fee int64) *types.Block {
	t.Helper()
	rIn := make([]byte, 32)
	rOut := make([]byte, 32)
	_, _ = rand.Read(rIn)
	_, _ = rand.Read(rOut)

	cIn, err := v2crypto.PedersenCommit(inVal, rIn)
	if err != nil {
		t.Fatal(err)
	}
	cOut, err := v2crypto.PedersenCommit(inVal-fee, rOut)
	if err != nil {
		t.Fatal(err)
	}
	// excess = r_out·G − r_in·G = (r_out − r_in)·G
	rOutG, _ := v2crypto.PedersenCommit(0, rOut)
	rInG, _ := v2crypto.PedersenCommit(0, rIn)
	excess, err := v2crypto.PointSubtract(rOutG, rInG)
	if err != nil {
		t.Fatal(err)
	}
	return &types.Block{
		Header:  types.BlockHeader{Height: 1},
		Inputs:  []types.Input{{Commit: types.Commitment(cIn)}},
		Outputs: []types.Output{{Features: types.OutputFeaturesPlain, Commit: types.Commitment(cOut)}},
		Kernels: []types.Kernel{{Features: types.KernelFeaturesPlain, Fee: uint64(fee), Excess: types.Commitment(excess)}},
	}
}

func TestBalance_ValidSpendPasses(t *testing.T) {
	b := buildSpend(t, 1000, 10)
	if err := (&Chain{}).validateBalance(b); err != nil {
		t.Fatalf("balanced spend rejected: %v", err)
	}
}

func TestBalance_InflationRejected(t *testing.T) {
	b := buildSpend(t, 1000, 10)
	// Tamper: inflate the output to 5000 with a fresh blinding — breaks the sum.
	rOut := make([]byte, 32)
	_, _ = rand.Read(rOut)
	bad, _ := v2crypto.PedersenCommit(5000, rOut)
	b.Outputs[0].Commit = types.Commitment(bad)
	if err := (&Chain{}).validateBalance(b); err == nil {
		t.Fatal("inflated block accepted — no-inflation invariant not enforced")
	}
}

func TestBalance_GenesisSkipped(t *testing.T) {
	// Height 0 with an unbalanced-looking output must be skipped (value-known).
	b := buildSpend(t, 1000, 10)
	b.Header.Height = 0
	b.Outputs[0].Commit = types.Commitment{} // garbage, but genesis is skipped
	if err := (&Chain{}).validateBalance(b); err != nil {
		t.Fatalf("genesis should skip balance check: %v", err)
	}
}

func TestBalance_CoinbaseOnlyPasses(t *testing.T) {
	// No plain outputs, no inputs, no tx kernels → trivially balanced.
	b := &types.Block{Header: types.BlockHeader{Height: 5}}
	if err := (&Chain{}).validateBalance(b); err != nil {
		t.Fatalf("coinbase-only block rejected: %v", err)
	}
}
