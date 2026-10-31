package genesis

import (
	"path/filepath"
	"testing"

	"github.com/pasichDev/noso-go/v2/chain"
	"github.com/pasichDev/noso-go/v2/types"
)

func TestEmptyGenesis(t *testing.T) {
	stats, err := Summarize(Default())
	if err != nil {
		t.Fatal(err)
	}
	if stats.GenesisHash.IsZero() {
		t.Error("genesis hash should be non-zero")
	}
	if stats.Difficulty != Default().InitialDifficulty || stats.NetworkMagic != types.NetworkMagicMainnet {
		t.Errorf("unexpected defaults: %+v", stats)
	}
}

func TestGenesisCarriesNoAllocations(t *testing.T) {
	block, err := Build(Default())
	if err != nil {
		t.Fatal(err)
	}
	if block.Header.Height != 0 || !block.Header.PrevHash.IsZero() {
		t.Errorf("bad genesis position: height=%d prev=%s", block.Header.Height, block.Header.PrevHash)
	}
	if block.Header.Version != types.BlockVersion {
		t.Errorf("genesis version %d, want %d", block.Header.Version, types.BlockVersion)
	}
	if len(block.Inputs) != 0 || len(block.Outputs) != 0 || len(block.Kernels) != 0 {
		t.Errorf("genesis must be empty: %d in, %d out, %d kernels", len(block.Inputs), len(block.Outputs), len(block.Kernels))
	}
	// Determinism: re-running with the same config produces the same hash.
	stats1, _ := Summarize(Default())
	stats2, _ := Summarize(Default())
	if stats1.GenesisHash != stats2.GenesisHash {
		t.Errorf("genesis not deterministic")
	}
}

func TestBuiltGenesisIsAcceptedByChain(t *testing.T) {
	block, err := Build(Default())
	if err != nil {
		t.Fatal(err)
	}
	mem := chain.NewMemory()
	if err := mem.LoadOrInit(t.TempDir(), block); err != nil {
		t.Fatalf("memory: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "badger")
	disk, err := chain.NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	if err := disk.LoadOrInit(dir, block); err != nil {
		t.Fatalf("badger: %v", err)
	}
}
