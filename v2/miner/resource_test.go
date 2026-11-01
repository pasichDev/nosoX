package miner

import (
	"math/big"
	"path/filepath"
	"testing"

	"github.com/pasichDev/nosoX/v2/chain"
	c "github.com/pasichDev/nosoX/v2/crypto"
	"github.com/pasichDev/nosoX/v2/genesis"
	"github.com/pasichDev/nosoX/v2/mempool"
	"github.com/pasichDev/nosoX/v2/types"
	"github.com/pasichDev/nosoX/v2/wallet"
)

func TestCandidateReservesMandatoryV4Outputs(t *testing.T) {
	cfg := genesis.Default()
	cfg.InitialDifficulty = 1
	g, err := genesis.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ch := chain.NewMemory()
	if err = ch.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	keys, err := wallet.OpenCoinbaseStore(filepath.Join(t.TempDir(), "coinbases.json"))
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.NewValidated(8, ch.ValidateTransaction)
	miner := New(ch, pool, keys)
	for h := 0; h < 62; h++ {
		candidate, err := miner.makeCandidate()
		if err != nil {
			t.Fatal(err)
		}
		if candidate.reward != nil {
			if err = keys.Persist(*candidate.reward); err != nil {
				t.Fatal(err)
			}
		}
		if err = ch.AddBlock(candidate.block); err != nil {
			t.Fatal(err)
		}
	}
	records := keys.All()
	for _, in := range records[:2] {
		first, err := wallet.NewPlainOutput(1000000000)
		if err != nil {
			t.Fatal(err)
		}
		second, err := wallet.NewPlainOutput(in.Amount - 1000000000 - 100)
		if err != nil {
			t.Fatal(err)
		}
		secret := new(big.Int).Add(new(big.Int).SetBytes(first.Blinding[:]), new(big.Int).SetBytes(second.Blinding[:]))
		secret.Sub(secret, new(big.Int).SetBytes(in.Blinding[:]))
		secret.Mod(secret, c.Curve().Params().N)
		scalar := secret.FillBytes(make([]byte, 32))
		excess, err := c.PedersenCommit(0, scalar)
		if err != nil {
			t.Fatal(err)
		}
		kernel := types.Kernel{Fee: 100, Excess: excess}
		kernel.ExcessSig, err = c.SchnorrSign(scalar, types.KernelSigningMessage(g.Header.NetworkMagic, &kernel))
		if err != nil {
			t.Fatal(err)
		}
		tx := &types.Transaction{Inputs: []types.Input{{Features: types.OutputFeaturesCoinbase, Commit: in.Commit}}, Outputs: []types.Output{first.Output, second.Output}, Kernels: []types.Kernel{kernel}}
		if _, err = pool.Add(tx); err != nil {
			t.Fatal(err)
		}
	}
	candidate, err := miner.makeCandidate()
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.kernelsByTx) != 1 || len(candidate.block.Outputs) != 3 {
		// Two 2-output transactions plus the one reserved coinbase would be five
		// outputs; exactly one transaction and the coinbase fit.
		t.Fatal("failed to reserve coinbase output capacity")
	}
	if err = ch.AddBlock(candidate.block); err != nil {
		t.Fatalf("capacity-selected candidate invalid: %v", err)
	}
}
