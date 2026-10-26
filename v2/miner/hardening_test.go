package miner

import (
	"context"
	"github.com/pasichDev/noso-go/v2/chain"
	"github.com/pasichDev/noso-go/v2/genesis"
	"github.com/pasichDev/noso-go/v2/mempool"
	"github.com/pasichDev/noso-go/v2/wallet"
	"path/filepath"
	"testing"
	"time"
)

func TestCandidateRequiresRewardKeyStore(t *testing.T) {
	g, _, _, err := genesis.Build(genesis.Default())
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
	g, _, _, err := genesis.Build(cfg)
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
	g, _, _, err := genesis.Build(cfg)
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
