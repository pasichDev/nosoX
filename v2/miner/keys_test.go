package miner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pasichDev/noso-go/v2/chain"
	"github.com/pasichDev/noso-go/v2/genesis"
	"github.com/pasichDev/noso-go/v2/mempool"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

func easyChain(t *testing.T) (*chain.Chain, *types.Block) {
	t.Helper()
	cfg := genesis.Config{NetworkMagic: types.NetworkMagicTestnet, Timestamp: time.Now().Unix() - 3600, InitialDifficulty: 1}
	g, err := genesis.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := chain.NewMemory()
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	return c, g
}

// N10/M1/H2: every candidate used to persist a coinbase record, so after 10000
// candidates Allocate failed and the miner stopped for good. Candidates must
// not touch the key file at all.
func TestCandidatesDoNotConsumeKeyRecords(t *testing.T) {
	if testing.Short() {
		t.Skip("10k candidates")
	}
	c, _ := easyChain(t)
	path := filepath.Join(t.TempDir(), "coinbases.json")
	keys, err := wallet.OpenCoinbaseStore(path)
	if err != nil {
		t.Fatal(err)
	}
	m := New(c, mempool.New(1), keys)
	for i := 0; i < 10100; i++ {
		if _, err := m.makeCandidate(); err != nil {
			t.Fatalf("candidate %d: %v", i, err)
		}
	}
	if n := len(keys.All()); n != 0 {
		t.Fatalf("unsolved candidates persisted %d key records", n)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("key file written without a solved block")
	}
}

func fullKeyFile(t *testing.T, path string) {
	t.Helper()
	scratch, err := wallet.OpenCoinbaseStore(filepath.Join(t.TempDir(), "scratch.json"))
	if err != nil {
		t.Fatal(err)
	}
	recs := make([]wallet.CoinbaseRecord, wallet.MaxCoinbaseRecords)
	for i := range recs {
		recs[i], err = scratch.NewRecord(uint64(i+1), 5_000_000_000)
		if err != nil {
			t.Fatal(err)
		}
	}
	body, err := json.Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A file already at the old 10000-record ceiling must open, keep every key,
// and keep accepting records by archiving itself.
func TestFullKeyFileRecoversOnRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("10k records")
	}
	path := filepath.Join(t.TempDir(), "coinbases.json")
	fullKeyFile(t, path)
	keys, err := wallet.OpenCoinbaseStore(path)
	if err != nil {
		t.Fatalf("reopening a full file: %v", err)
	}
	rec, err := keys.Allocate(10001, 5_000_000_000)
	if err != nil {
		t.Fatalf("persist after full: %v", err)
	}
	if got := keys.All(); len(got) != 1 || got[0].Commit != rec.Commit {
		t.Fatalf("live file should hold only the new record, has %d", len(got))
	}
	archives, _ := filepath.Glob(path + ".*")
	if len(archives) != 1 {
		t.Fatalf("want one archive of the old keys, got %v", archives)
	}
	old, err := wallet.OpenCoinbaseStore(archives[0])
	if err != nil || len(old.All()) != wallet.MaxCoinbaseRecords {
		t.Fatalf("archive must stay an intact importable file: %v n=%d", err, len(old.All()))
	}
}

// A key file that cannot be written must be reported, and the solved block
// must not be added (it would be unspendable).
func TestKeyPersistFailureIsSurfacedAndBlockWithheld(t *testing.T) {
	c, _ := easyChain(t)
	dir := t.TempDir()
	keys, err := wallet.OpenCoinbaseStore(filepath.Join(dir, "keys", "coinbases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "keys")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys"), []byte("x"), 0o600); err != nil { // dir replaced by a file
		t.Fatal(err)
	}
	m := New(c, mempool.New(1), keys)
	var mu sync.Mutex
	var logs []string
	m.SetLogger(func(f string, a ...any) { mu.Lock(); logs = append(logs, f); mu.Unlock() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx, 1, "t"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && m.Stats().LastError == "" {
		time.Sleep(50 * time.Millisecond)
	}
	m.Stop()
	st := m.Stats()
	if !strings.Contains(st.LastError, "persist reward key") || st.Errors == 0 {
		t.Fatalf("failure not surfaced in stats: %+v", st)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(logs) == 0 {
		t.Fatal("failure not logged")
	}
	if c.Height() != 0 {
		t.Fatal("block was added without a durable reward key")
	}
}
