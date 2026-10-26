package genesis

import (
	legacytypes "github.com/pasichDev/noso-go/internal/types"
	"github.com/pasichDev/noso-go/v2/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validSnapshot(t *testing.T) string {
	t.Helper()
	r := legacytypes.SummaryRecord{Hash: "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd", Balance: 123456789}
	path := filepath.Join(t.TempDir(), "synthetic-summary.psk")
	if err := os.WriteFile(path, r.Marshal(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRejectOriginalMalformedSnapshot(t *testing.T) {
	cfg := Default()
	cfg.SummaryPath = "../../testdata/sumary_59238.psk"
	_, _, _, err := Build(cfg)
	if err == nil || !strings.Contains(err.Error(), "snapshot record 4749") {
		t.Fatalf("must reject original malformed address at record4749: %v", err)
	}
}
func TestDefaultTimestampPreservesSnapshotAndNetwork(t *testing.T) {
	cfg := Config{SummaryPath: validSnapshot(t), NetworkMagic: types.NetworkMagicTestnet, InitialDifficulty: 1}
	b, info, _, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(info) != 1 || b.Header.NetworkMagic != types.NetworkMagicTestnet || b.Header.Difficulty != 1 {
		t.Fatal("defaulting timestamp discarded explicit config")
	}
	other := cfg
	other.NetworkMagic = types.NetworkMagicMainnet
	c, _, _, err := Build(other)
	if err != nil {
		t.Fatal(err)
	}
	if types.HeaderID(&b.Header) == types.HeaderID(&c.Header) {
		t.Fatal("network domain missing from genesis")
	}
}
func TestRejectMissingSnapshot(t *testing.T) {
	cfg := Default()
	cfg.SummaryPath = filepath.Join(t.TempDir(), "missing")
	if _, _, _, err := Build(cfg); err == nil {
		t.Fatal("missing requested snapshot treated as empty genesis")
	}
}
func TestRejectNegativeAndDuplicateSnapshot(t *testing.T) {
	for _, negative := range []bool{true, false} {
		r := legacytypes.SummaryRecord{Hash: "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd", Balance: 1}
		if negative {
			r.Balance = -1
		}
		raw := r.Marshal()
		if !negative {
			raw = append(raw, r.Marshal()...)
		}
		path := filepath.Join(t.TempDir(), "bad.psk")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		cfg := Default()
		cfg.SummaryPath = path
		if _, _, _, err := Build(cfg); err == nil {
			t.Fatal("invalid snapshot accepted")
		}
	}
}
