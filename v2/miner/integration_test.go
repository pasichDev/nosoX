package miner

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/pasichDev/noso-go/v2/chain"
	"github.com/pasichDev/noso-go/v2/genesis"
	"github.com/pasichDev/noso-go/v2/mempool"
	"github.com/pasichDev/noso-go/v2/pow"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

// TestMineAndValidateCoinbase checks local production and validation of signed
// subsidy-only blocks. It is not a production launch gate and does not exercise
// plain output proofs; those have full chain and P2P spend tests separately.
func TestMineAndValidateCoinbase(t *testing.T) {
	dir := t.TempDir()
	c := chain.NewMemory()
	gCfg := genesis.Config{
		NetworkMagic:      types.NetworkMagicTestnet,
		Timestamp:         time.Now().Unix() - 600,
		InitialDifficulty: 1, // any hash wins; PoW is exercised but quick
	}
	gBlock, _, _, err := genesis.Build(gCfg)
	if err != nil {
		t.Fatal(err)
	}
	// Find a nonce that satisfies PoW at difficulty=1 (the first one does).
	for n := uint64(0); n < 32; n++ {
		gBlock.Header.Nonce = n
		if pow.Verify(&gBlock.Header) {
			break
		}
	}
	if err := c.LoadOrInit(dir, gBlock); err != nil {
		t.Fatal(err)
	}

	cbStore, err := wallet.OpenCoinbaseStore(filepath.Join(dir, "coinbases.json"))
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.New(0)
	m := New(c, pool, cbStore)

	emitted := make(chan *types.Block, 16)
	m.OnNewBlock(func(b *types.Block) {
		emitted <- b
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := m.Start(ctx, 2, "test-reward"); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	const want = 3
	for got := 0; got < want; {
		select {
		case b := <-emitted:
			got++
			if b.Header.Height == 0 {
				t.Fatalf("emit returned genesis (should not happen)")
			}
			if b.Header.Height != uint64(got) {
				t.Fatalf("expected height %d, got %d", got, b.Header.Height)
			}
			// At least one Coinbase output and matching kernel must exist
			// for blocks at height > 0 where reward > 0.
			reward := types.BlockReward(b.Header.Height)
			if reward > 0 {
				var hasCB bool
				for i := range b.Outputs {
					if b.Outputs[i].Features == types.OutputFeaturesCoinbase {
						hasCB = true
						break
					}
				}
				if !hasCB {
					t.Fatalf("block %d missing coinbase output", b.Header.Height)
				}
			}
		case <-ctx.Done():
			t.Fatalf("timed out after mining %d/%d blocks", got, want)
		}
	}
	// Stop the miner explicitly before invariant checks. Without this the
	// loop may exit after the 3rd emit while the miner has already
	// allocated the 4th coinbase (Allocate happens before AddBlock+emit).
	m.Stop()
	// Give the in-flight workers a moment to drain.
	time.Sleep(50 * time.Millisecond)

	if c.Height() < want {
		t.Fatalf("chain height = %d, want >= %d", c.Height(), want)
	}
	// Each coinbase blinding factor was persisted, so the miner could
	// later spend its rewards. The count may be >= want if a 4th block
	// was already being prepared when we called Stop — that's fine, the
	// invariant is that we have AT LEAST one per emitted block.
	if got := len(cbStore.All()); got < want {
		t.Fatalf("coinbase store has %d entries, want >= %d", got, want)
	}
}
