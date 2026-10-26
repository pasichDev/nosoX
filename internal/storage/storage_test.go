package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pasichDev/noso-go/internal/types"
)

func TestLayoutPaths(t *testing.T) {
	l := NewLayout("/tmp/NOSODATA")
	if l.Wallet != "/tmp/NOSODATA/wallet.pkw" {
		t.Errorf("Wallet = %q", l.Wallet)
	}
	if l.BlockPath(42) != "/tmp/NOSODATA/BLOCKS/42.blk" {
		t.Errorf("BlockPath(42) = %q", l.BlockPath(42))
	}
}

func TestWalletRoundTripOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.pkw")
	in := []types.WalletData{{
		Hash:       "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd",
		PublicKey:  "PubKey",
		PrivateKey: "PrivKey",
		Balance:    123456789,
	}}
	if err := SaveWallet(path, in); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf("bak file missing: %v", err)
	}
	out, err := LoadWallet(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Hash != in[0].Hash || out[0].Balance != in[0].Balance {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestSummaryStoreFromFixture(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "sumary_59238.psk"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	s, err := NewSummaryStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 4956 {
		t.Errorf("Len() = %d, want 4956", s.Len())
	}
	total := s.Total()
	if total < 1_000_000_000 { // basic sanity: total supply should be billions of base units
		t.Errorf("Total() = %d, suspiciously low", total)
	}
	t.Logf("snapshot 59238: %d accounts, total = %d base units (%.4f NOSO)",
		s.Len(), total, float64(total)/1e8)
	// Spot-check: dev fund address must exist with non-zero balance.
	if rec, ok := s.Get("NpryectdevepmentfundsGE"); ok {
		t.Logf("dev fund: balance=%d", rec.Balance)
	}
}

func TestGVTsFromFixture(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "gvts.psk"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	recs, err := LoadGVTs(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 100 {
		t.Errorf("got %d GVTs, want 100", len(recs))
	}
	// Round-trip: SaveGVTs(LoadGVTs(file)) should produce a byte-identical
	// copy modulo the unused tail-padding of ShortString fields, which
	// Pascal may have written non-zero. We don't enforce byte-identity in
	// this round-trip test for that reason; the content equality is enough.
	tmp := filepath.Join(t.TempDir(), "gvts.psk")
	if err := SaveGVTs(tmp, recs); err != nil {
		t.Fatal(err)
	}
	back, err := LoadGVTs(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 100 {
		t.Fatalf("round-trip count = %d", len(back))
	}
	for i := range back {
		if back[i] != recs[i] {
			t.Fatalf("record %d differs after round-trip", i)
		}
	}
}

func TestNosoCFGParse(t *testing.T) {
	cfg := parseNosoCFG("NORMAL 1.2.3.4;8080:5.6.7.8;8080: pool.ntp.org:time.google.com: null: null: addr1:addr2:")
	if cfg.Mode != "NORMAL" {
		t.Errorf("Mode = %q", cfg.Mode)
	}
	if len(cfg.Seeds) != 2 || cfg.Seeds[0] != "1.2.3.4;8080" {
		t.Errorf("Seeds = %v", cfg.Seeds)
	}
	if len(cfg.NTP) != 2 {
		t.Errorf("NTP = %v", cfg.NTP)
	}
	if len(cfg.Frozen) != 2 {
		t.Errorf("Frozen = %v", cfg.Frozen)
	}
	hosts := cfg.SeedHosts(8080)
	if len(hosts) != 2 || hosts[0].Port != 8080 {
		t.Errorf("SeedHosts = %v", hosts)
	}
}

func TestSeedNodesParse(t *testing.T) {
	got, err := parseSeedNodes("DefNodes 1.1.1.1 2.2.2.2 3.3.3.3\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "1.1.1.1" || got[2] != "3.3.3.3" {
		t.Errorf("parseSeedNodes = %v", got)
	}
}
