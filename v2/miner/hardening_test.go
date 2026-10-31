package miner

import (
	"context"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/pasichDev/noso-go/v2/chain"
	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/genesis"
	"github.com/pasichDev/noso-go/v2/mempool"
	"github.com/pasichDev/noso-go/v2/pow"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestCandidateRequiresRewardKeyStore(t *testing.T) {
	g, err := genesis.Build(genesis.Default())
	if err != nil {
		t.Fatal(err)
	}
	c := chain.NewMemory()
	if err = c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	m := New(c, mempool.New(1), nil)
	if _, err = m.makeCandidate(); err == nil {
		t.Fatal("mining must stop when reward key cannot be persisted")
	}
}

func TestCandidateAdvancesTimeAndBindsBody(t *testing.T) {
	cfg := genesis.Default()
	cfg.InitialDifficulty = 1
	cfg.Timestamp = time.Now().Unix() + 60
	g, err := genesis.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := chain.NewMemory()
	if err = c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	keys, err := wallet.OpenCoinbaseStore(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := New(c, mempool.New(1), keys)
	candidate, err := m.makeCandidate()
	if err != nil {
		t.Fatal(err)
	}
	b := candidate.block
	if b.Header.Timestamp != g.Header.Timestamp+1 {
		t.Fatal("candidate failed to advance parent time")
	}
	if err = c.AddBlock(b); err != nil {
		t.Fatalf("producer candidate rejected by real validator: %v", err)
	}
}

func TestGrindAbandonsChangedParent(t *testing.T) {
	cfg := genesis.Default()
	cfg.InitialDifficulty = 1
	g, err := genesis.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := chain.NewMemory()
	if err = c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	keys, err := wallet.OpenCoinbaseStore(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := New(c, mempool.New(1), keys)
	stale, err := m.makeCandidate()
	if err != nil {
		t.Fatal(err)
	}
	winner, err := m.makeCandidate()
	if err != nil {
		t.Fatal(err)
	}
	if err = c.AddBlock(winner.block); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got := m.grindBlock(ctx, stale, 2); got != nil {
		t.Fatal("continued mining a changed parent")
	}
}

// The coinbase is built after transaction selection and pays reward + every
// selected fee: the stored key record holds the full amount and the real
// validator accepts the block.
func TestCandidateCoinbasePaysRewardPlusFees(t *testing.T) {
	cfg := genesis.Default()
	cfg.InitialDifficulty = 1
	cfg.Timestamp = time.Now().Unix() - 1000
	g, err := genesis.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := chain.NewMemory()
	if err = c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	keys, err := wallet.OpenCoinbaseStore(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.NewValidated(8, c.ValidateTransaction)
	m := New(c, pool, keys)
	solve := func(cand *candidate) *types.Block {
		b := cand.block
		for n := uint64(0); n < 4096; n++ {
			b.Header.Nonce = n
			if pow.Verify(&b.Header) {
				return b
			}
		}
		t.Fatal("no nonce at difficulty 1")
		return nil
	}
	var first *types.Block
	var rec wallet.CoinbaseRecord
	for h := 1; h <= 61; h++ {
		cand, err := m.makeCandidate()
		if err != nil {
			t.Fatal(err)
		}
		b := solve(cand)
		if err := c.AddBlock(b); err != nil {
			t.Fatalf("block %d: %v", h, err)
		}
		if first == nil {
			first, rec = b, *cand.reward
		}
	}
	const fee = 1_000_000
	out, err := wallet.NewPlainOutput(rec.Amount - fee)
	if err != nil {
		t.Fatal(err)
	}
	var x secp.ModNScalar
	ob := [32]byte(out.Blinding)
	x.SetBytes(&ob)
	var neg secp.ModNScalar
	neg.SetBytes(&rec.Blinding)
	neg.Negate()
	x.Add(&neg)
	scalar := x.Bytes()
	excess, err := v2crypto.PublicFromScalar(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	k := types.Kernel{Fee: fee, Excess: excess}
	k.ExcessSig, err = v2crypto.SchnorrSign(scalar[:], types.KernelSigningMessage(first.Header.NetworkMagic, &k))
	if err != nil {
		t.Fatal(err)
	}
	tx := &types.Transaction{
		Inputs:  []types.Input{{Features: types.OutputFeaturesCoinbase, Commit: first.Outputs[0].Commit}},
		Outputs: []types.Output{out.Output},
		Kernels: []types.Kernel{k},
	}
	if _, err := pool.Add(tx); err != nil {
		t.Fatalf("pool: %v", err)
	}
	cand, err := m.makeCandidate()
	if err != nil {
		t.Fatal(err)
	}
	if cand.reward == nil || cand.reward.Amount != types.BlockReward(62)+fee {
		t.Fatalf("key record amount = %+v, want reward+%d", cand.reward, fee)
	}
	for _, o := range cand.block.Outputs {
		if o.Features != types.OutputFeaturesCoinbase && o.Features != types.OutputFeaturesPlain {
			t.Fatalf("unexpected output feature %d", o.Features)
		}
	}
	if err := c.AddBlock(solve(cand)); err != nil {
		t.Fatalf("validator rejected the miner's fee block: %v", err)
	}
}

// The gate is consulted before every candidate: mining idles while it is
// closed, resumes when it opens, and stops again if it closes later (it is not a
// one-time wait at startup), whichever way Start was reached.
func TestSyncGateIsRecheckedBeforeEveryBlock(t *testing.T) {
	cfg := genesis.Default()
	cfg.InitialDifficulty = 1
	cfg.Timestamp = time.Now().Unix() - 3000
	g, err := genesis.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := chain.NewMemory()
	if err = c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	keys, err := wallet.OpenCoinbaseStore(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := New(c, mempool.New(0), keys)
	var open atomic.Bool
	m.SetSyncGate(open.Load)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := m.Start(ctx, 1, "gate"); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	time.Sleep(1500 * time.Millisecond)
	if h := c.Height(); h != 0 {
		t.Fatalf("mined %d blocks with the gate closed", h)
	}
	open.Store(true)
	deadline := time.Now().Add(30 * time.Second)
	for c.Height() < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if c.Height() < 2 {
		t.Fatal("no blocks after the gate opened")
	}
	open.Store(false) // the node falls behind later
	time.Sleep(300 * time.Millisecond)
	h := c.Height()
	time.Sleep(1500 * time.Millisecond)
	if c.Height() > h+1 { // at most the block already being ground
		t.Fatalf("kept mining after the gate closed: %d -> %d", h, c.Height())
	}
}
