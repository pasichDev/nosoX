package genesis

import (
	"path/filepath"
	"testing"

	"github.com/pasichDev/noso-go/v2/types"
)

func TestGenesisCarriesGVTs(t *testing.T) {
	sumPath := validSnapshot(t) // original malformed snapshot is tested separately
	gvtPath, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "gvts.psk"))

	cfg := Default()
	cfg.SummaryPath = sumPath
	cfg.GVTsPath = gvtPath
	block, _, gvts, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// gvts.psk ships 100 slots. Even if some are owner-empty in the
	// fixture, we expect non-zero count.
	if len(gvts) == 0 {
		t.Fatal("no GVT outputs in genesis")
	}
	// Every GVT output must have Features=LegacyGVT, amount=GVTBaseValue,
	// and a slot number in [0,99].
	seen := map[uint8]bool{}
	for _, g := range gvts {
		if seen[g.GVTNumber] {
			t.Errorf("duplicate GVT slot %d", g.GVTNumber)
		}
		seen[g.GVTNumber] = true
	}
	// Walk block.Outputs, find the GVT outputs, verify their fields.
	var foundGVT int
	for i := range block.Outputs {
		o := &block.Outputs[i]
		if o.Features != types.OutputFeaturesLegacyGVT {
			continue
		}
		foundGVT++
		if o.LegacyAmount != types.GVTBaseValue {
			t.Errorf("GVT %d amount %d, want %d", o.GVTNumber, o.LegacyAmount, types.GVTBaseValue)
		}
		if o.LegacyAddress == "" {
			t.Errorf("GVT %d has empty owner", o.GVTNumber)
		}
	}
	if foundGVT != len(gvts) {
		t.Errorf("foundGVT=%d but gvts slice has %d", foundGVT, len(gvts))
	}
	// Determinism: re-running the same config gives the same genesis hash.
	stats1, _ := Summarize(cfg)
	stats2, _ := Summarize(cfg)
	if stats1.GenesisHash != stats2.GenesisHash {
		t.Error("genesis with GVTs not deterministic")
	}
	t.Logf("genesis with GVTs: %d accounts (%d NOSO) + %d GVTs (%d NOSO) = %s",
		stats1.LegacyAccounts, stats1.TotalCarried/1e8,
		stats1.LegacyGVTs, stats1.GVTValue/1e8,
		stats1.GenesisHash)
}
