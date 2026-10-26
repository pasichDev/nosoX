package genesis

import (
	"testing"

	"github.com/pasichDev/noso-go/v2/types"
)

func TestEmptyGenesis(t *testing.T) {
	stats, err := Summarize(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if stats.LegacyAccounts != 0 || stats.TotalCarried != 0 || stats.LegacyGVTs != 0 {
		t.Errorf("empty genesis has accounts/total: %+v", stats)
	}
	if stats.GenesisHash.IsZero() {
		t.Error("genesis hash should be non-zero")
	}
}

// The original historical fixture is explicitly rejected by
// TestRejectOriginalMalformedSnapshot. This test uses a named synthetic input.
func TestGenesisFromSyntheticSnapshot(t *testing.T) {
	path := validSnapshot(t)
	cfg := Default()
	cfg.SummaryPath = path
	block, info, gvts, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if block.Header.Height != 0 {
		t.Errorf("genesis height = %d, want 0", block.Header.Height)
	}
	if len(info) != 1 {
		t.Errorf("only %d legacy outputs carried; expected one synthetic account", len(info))
	}
	if len(info)+len(gvts) != len(block.Outputs) {
		t.Errorf("info+gvts/outputs length mismatch: %d+%d vs %d", len(info), len(gvts), len(block.Outputs))
	}
	for i, o := range block.Outputs {
		switch o.Features {
		case types.OutputFeaturesLegacy:
			if o.LegacyAmount <= 0 {
				t.Errorf("output %d amount %d", i, o.LegacyAmount)
			}
		case types.OutputFeaturesLegacyGVT:
			if o.LegacyAmount != types.GVTBaseValue {
				t.Errorf("GVT %d has amount %d, want %d", o.GVTNumber, o.LegacyAmount, types.GVTBaseValue)
			}
		default:
			t.Errorf("output %d unexpected feature %d", i, o.Features)
		}
	}
	// Determinism: re-running with same config produces the same hash.
	stats1, _ := Summarize(cfg)
	stats2, _ := Summarize(cfg)
	if stats1.GenesisHash != stats2.GenesisHash {
		t.Errorf("genesis not deterministic")
	}
	t.Logf("genesis: %d legacy outputs, total carried %d base units (%.4f NOSO), hash %s",
		stats1.LegacyAccounts, stats1.TotalCarried, float64(stats1.TotalCarried)/1e8, stats1.GenesisHash)
}
