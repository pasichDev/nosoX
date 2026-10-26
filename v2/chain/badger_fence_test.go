package chain

import (
	"errors"
	"os"
	"os/exec"
	"reflect"
	"testing"

	"github.com/dgraph-io/badger/v4"
	"github.com/pasichDev/noso-go/v2/types"
)

// This test targets the storage protocol directly. Synthetic outputs exercise
// metadata and tombstone persistence; they do not claim consensus acceptance.
func TestBadgerFenceAbandonedStageDifferentRetry(t *testing.T) {
	for _, phase := range []string{"mid-stage", "before-publish"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			s, err := OpenBadger(dir)
			if err != nil {
				t.Fatal(err)
			}
			g := easyGenesisBlock(t)
			old := types.Output{Commit: storePoint(t, 7), Features: types.OutputFeaturesLegacy, LegacyAddress: "old", LegacyAmount: 7, RangeProof: []byte{7}}
			g.Outputs = []types.Output{old}
			types.SetBlockRoots(g)
			if err := s.WriteBlock(g); err != nil {
				t.Fatal(err)
			}
			baseline := rawBadgerEntries(t, s)
			abandoned := &types.Block{Header: easyHeader(types.HeaderID(&g.Header), 1), Inputs: []types.Input{{Commit: old.Commit, Features: old.Features, LegacyAddr: old.LegacyAddress, LegacyAmount: 7}}, Outputs: []types.Output{{Commit: storePoint(t, 8), RangeProof: []byte{8}}}}
			injected := errors.New("stage interruption")
			s.fault = func(at string) error {
				if at == phase {
					return injected
				}
				return nil
			}
			if err := s.WriteBlock(abandoned); !errors.Is(err, injected) {
				t.Fatalf("stage error: %v", err)
			}
			if !reflect.DeepEqual(baseline, rawBadgerEntries(t, s)) {
				t.Fatal("partial stage visible")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = OpenBadger(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(baseline, rawBadgerEntries(t, s)) {
				t.Fatal("partial stage visible after reopen")
			}
			// A different candidate must not inherit the abandoned spend, output, or hash.
			replacement := &types.Block{Header: easyHeader(types.HeaderID(&g.Header), 1), Outputs: []types.Output{{Commit: storePoint(t, 9), RangeProof: []byte{9}}}}
			replacement.Header.Nonce++
			if err := s.WriteBlock(replacement); err != nil {
				t.Fatal(err)
			}
			if _, ok := s.UTXOByCommit(old.Commit); !ok {
				t.Fatal("abandoned input deletion leaked")
			}
			if s.HasOutput(abandoned.Outputs[0].Commit) || s.HasUTXO(abandoned.Outputs[0].Commit) {
				t.Fatal("abandoned output leaked")
			}
			if _, ok := s.HeightOf(types.HeaderID(&abandoned.Header)); ok {
				t.Fatal("abandoned hash leaked")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = OpenBadger(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := s.verifyState([]*types.Block{g, replacement}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBadgerFenceRejectsUnfencedSchema(t *testing.T) {
	dir := t.TempDir()
	db, err := badger.Open(badger.DefaultOptions(dir).WithLogger(silentBadgerLogger{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(txn *badger.Txn) error { return txn.Set([]byte{kTip}, u64ToBytes(0)) }); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenBadger(dir); err == nil {
		s.Close()
		t.Fatal("silently opened old schema")
	}
}

func TestBadgerFenceMaximumBoundedBodyAppendAndSuffix(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	g := easyGenesisBlock(t)
	if err := s.WriteBlock(g); err != nil {
		t.Fatal(err)
	}
	// Exactly 8 MiB according to bodyBounds, with its maximum output count.
	// Proof bytes are synthetic; cryptographic validity is tested elsewhere.
	b := &types.Block{Header: easyHeader(types.HeaderID(&g.Header), 1), Outputs: make([]types.Output, 10000)}
	remaining := 8 << 20
	for i := range b.Outputs {
		n := (remaining / (len(b.Outputs) - i)) - 128
		b.Outputs[i].Commit[0] = 2
		b.Outputs[i].Commit[1] = byte(i)
		b.Outputs[i].Commit[2] = byte(i >> 8)
		b.Outputs[i].RangeProof = make([]byte, n)
		remaining -= 128 + n
	}
	if err := bodyBounds(b); err != nil {
		t.Fatal(err)
	}
	types.SetBlockRoots(b)
	if err := s.WriteBlock(b); err != nil {
		t.Fatalf("bounded maximum append: %v", err)
	}
	memory := newMemStore()
	if err := memory.WriteBlock(g); err != nil {
		t.Fatal(err)
	}
	if err := memory.WriteBlock(b); err != nil {
		t.Fatal(err)
	}
	if err := s.verifyState(memory.orderedBlocks()); err != nil {
		t.Fatal(err)
	}
	b.Header.Nonce++
	if err := s.ReplaceSuffix(0, []*types.Block{b}); err != nil {
		t.Fatalf("bounded maximum suffix: %v", err)
	}
	if err := s.verifyState([]*types.Block{g, b}); err != nil {
		t.Fatal(err)
	}
}

func TestBadgerFenceAbruptUnpublishedStage(t *testing.T) {
	if dir := os.Getenv("NOSO_FENCE_CRASH_DIR"); dir != "" {
		s, err := OpenBadger(dir)
		if err != nil {
			panic(err)
		}
		g := easyGenesisBlock(t)
		if err := s.WriteBlock(g); err != nil {
			panic(err)
		}
		b := &types.Block{Header: easyHeader(types.HeaderID(&g.Header), 1), Outputs: []types.Output{{Commit: storePoint(t, 25)}}}
		s.fault = func(phase string) error {
			if phase == os.Getenv("NOSO_FENCE_CRASH_PHASE") {
				os.Exit(24)
			}
			return nil
		}
		if err := s.WriteBlock(b); err != nil {
			panic(err)
		}
		panic("crash hook not reached")
	}
	for _, phase := range []string{"mid-stage", "before-publish"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestBadgerFenceAbruptUnpublishedStage$")
			cmd.Env = append(os.Environ(), "NOSO_FENCE_CRASH_DIR="+dir, "NOSO_FENCE_CRASH_PHASE="+phase)
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 24 {
				t.Fatalf("child exit: %v", err)
			}
			s, err := OpenBadger(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			g := easyGenesisBlock(t)
			if err := s.verifyState([]*types.Block{g}); err != nil {
				t.Fatal(err)
			}
			if tip, ok := s.Tip(); !ok || tip.Height != 0 {
				t.Fatal("unpublished tip survived crash")
			}
			different := &types.Block{Header: easyHeader(types.HeaderID(&g.Header), 1), Outputs: []types.Output{{Commit: storePoint(t, 26)}}}
			different.Header.Nonce++
			if err := s.WriteBlock(different); err != nil {
				t.Fatal(err)
			}
			if err := s.verifyState([]*types.Block{g, different}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBadgerFenceAbruptGenesisStage(t *testing.T) {
	if dir := os.Getenv("NOSO_GENESIS_FENCE_CRASH_DIR"); dir != "" {
		s, err := OpenBadger(dir)
		if err != nil {
			panic(err)
		}
		s.fault = func(phase string) error {
			if phase == "before-publish" {
				os.Exit(25)
			}
			return nil
		}
		g := easyGenesisBlock(t)
		g.Outputs = []types.Output{{Commit: storePoint(t, 30)}}
		if err := s.WriteBlock(g); err != nil {
			panic(err)
		}
		panic("crash hook not reached")
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestBadgerFenceAbruptGenesisStage$")
	cmd.Env = append(os.Environ(), "NOSO_GENESIS_FENCE_CRASH_DIR="+dir)
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 25 {
		t.Fatalf("child exit: %v", err)
	}
	s, err := OpenBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	empty, err := s.isEmpty()
	if err != nil || !empty {
		t.Fatalf("unpublished genesis visible: %v", err)
	}
	g := easyGenesisBlock(t)
	g.Outputs = []types.Output{{Commit: storePoint(t, 31)}}
	if err := s.WriteBlock(g); err != nil {
		t.Fatal(err)
	}
	if s.HasOutput(storePoint(t, 30)) {
		t.Fatal("abandoned genesis identity leaked")
	}
	if err := s.verifyState([]*types.Block{g}); err != nil {
		t.Fatal(err)
	}
}
