package chain

import (
	"errors"
	"fmt"
	"github.com/pasichDev/noso-go/v2/types"
	"reflect"
	"testing"
)

type boundedHistoryStore struct {
	Store
	minimum uint64
	reads   int
}

func (s *boundedHistoryStore) BlockAt(h uint64) (*types.Block, error) {
	s.reads++
	if h < s.minimum {
		sFail := "reorg accessed unrelated prefix"
		panic(sFail)
	}
	return s.Store.BlockAt(h)
}
func TestSecurityReorgLateInvalidDoesNotReadPrefix(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	blocks := appendBlocks(t, c, 1, 12)
	// Below the LWMA window, validation requires no prefix reads except ancestor.
	guarded := &boundedHistoryStore{Store: c.store, minimum: 11}
	c.store = guarded
	b := mineEasy(types.HeaderID(&blocks[10].Header), 12)
	b.Kernels[0].ExcessSig = nil
	types.SetBlockRoots(b)
	if err := c.ReorgTo([]*types.Block{b}); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if guarded.reads > 4 {
		t.Fatalf("unbounded reads: %d", guarded.reads)
	}
}

func TestSecuritySuffixOverlayExactUndoAndHistory(t *testing.T) {
	s := newMemStore()
	var a, b, c types.Commitment
	a[0] = 1
	b[0] = 2
	c[0] = 3
	original := types.Output{Commit: a, Features: types.OutputFeaturesLegacy, LegacyAddress: "legacy-owner", LegacyAmount: 123, RangeProof: []byte{4, 5, 6}}
	g := &types.Block{Outputs: []types.Output{original}}
	if err := s.WriteBlock(g); err != nil {
		t.Fatal(err)
	}
	old := &types.Block{Header: types.BlockHeader{Height: 1, PrevHash: types.HeaderID(&g.Header)}, Inputs: []types.Input{{Commit: a, Features: original.Features, LegacyAddr: original.LegacyAddress, LegacyAmount: original.LegacyAmount}}, Outputs: []types.Output{{Commit: b, RangeProof: []byte{7}}}, Kernels: []types.Kernel{{Excess: b}}}
	if err := s.WriteBlock(old); err != nil {
		t.Fatal(err)
	}
	undo, err := s.UndoAt(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(undo) != 1 || !reflect.DeepEqual(undo[0], original) {
		t.Fatalf("incomplete undo: %+v", undo)
	}
	undo[0].RangeProof[0] ^= 255
	again, _ := s.UndoAt(1)
	if !reflect.DeepEqual(again[0], original) {
		t.Fatal("UndoAt exposes stored proof")
	}
	f, err := newForkStore(s, 0)
	if err != nil {
		t.Fatal(err)
	}
	restored, ok := f.UTXOByLegacyAddress(original.LegacyAddress)
	if !ok || !reflect.DeepEqual(*restored, original) {
		t.Fatal("rollback lost legacy metadata")
	}
	if f.HasOutput(b) || f.HasKernel(types.KernelID(&old.Kernels[0])) {
		t.Fatal("orphan identity remains in overlay")
	}
	if _, ok := f.HeightOf(types.HeaderID(&old.Header)); ok {
		t.Fatal("orphan hash remains")
	}
	if !s.HasOutput(b) || s.HasUTXO(a) {
		t.Fatal("staging mutated canonical state")
	}
	replacement := &types.Block{Header: types.BlockHeader{Height: 1, PrevHash: types.HeaderID(&g.Header), Nonce: 1}, Outputs: []types.Output{{Commit: c}}}
	if err := s.ReplaceSuffix(0, []*types.Block{replacement}); err != nil {
		t.Fatal(err)
	}
	restored, ok = s.UTXOByLegacyAddress(original.LegacyAddress)
	if !ok || !reflect.DeepEqual(*restored, original) {
		t.Fatal("commit lost restored metadata")
	}
	if s.HasOutput(b) || s.HasKernel(types.KernelID(&old.Kernels[0])) {
		t.Fatal("orphan history retained")
	}
	if _, ok := s.HeightOf(types.HeaderID(&old.Header)); ok {
		t.Fatal("orphan hash retained")
	}
	if !s.HasUTXO(c) {
		t.Fatal("replacement output missing")
	}
}

func TestSecuritySuffixOverlayFailureLeavesMemoryUnchanged(t *testing.T) {
	s := newMemStore()
	g := &types.Block{}
	if err := s.WriteBlock(g); err != nil {
		t.Fatal(err)
	}
	old := &types.Block{Header: types.BlockHeader{Height: 1, PrevHash: types.HeaderID(&g.Header)}}
	if err := s.WriteBlock(old); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Tip()
	a := &types.Block{Header: types.BlockHeader{Height: 1, PrevHash: types.HeaderID(&g.Header), Nonce: 1}}
	bad := &types.Block{Header: types.BlockHeader{Height: 2, PrevHash: types.HeaderID(&a.Header)}, Inputs: []types.Input{{Commit: types.Commitment{3}}}}
	if err := s.ReplaceSuffix(0, []*types.Block{a, bad}); err == nil {
		t.Fatal("impossible suffix accepted")
	}
	after, _ := s.Tip()
	if before != after {
		t.Fatal("failure mutated tip")
	}
	if _, ok := s.HeightOf(types.HeaderID(&a.Header)); ok {
		t.Fatal("failed suffix hash leaked")
	}
	if _, err := s.UndoAt(1); err != nil {
		t.Fatal("old undo lost")
	}
}

func TestSecurityLargeHistorySuffixHasBoundedReads(t *testing.T) {
	for _, height := range []uint64{100, 10000} {
		t.Run(fmt.Sprint(height), func(t *testing.T) {
			s := newMemStore()
			var parent types.Hash
			for h := uint64(0); h <= height; h++ {
				b := &types.Block{Header: easyHeader(parent, h)}
				if err := s.WriteBlock(b); err != nil {
					t.Fatal(err)
				}
				parent = types.HeaderID(&b.Header)
			}
			guarded := &boundedHistoryStore{Store: s, minimum: height - 1}
			f, err := newForkStore(guarded, height-1)
			if err != nil {
				t.Fatal(err)
			}
			if guarded.reads != 2 {
				t.Fatalf("reads %d", guarded.reads)
			}
			if len(f.delta().Blocks) != 1 || len(f.delta().Undo) != 1 || len(f.delta().Hashes) != 1 {
				t.Fatal("staging size grows with prefix")
			}
			b := &types.Block{Header: types.BlockHeader{Height: height, PrevHash: types.HeaderID(&f.changes.Tip), Nonce: 1}}
			if err := f.WriteBlock(b); err != nil {
				t.Fatal(err)
			}
			if guarded.reads != 2 {
				t.Fatal("staging append read unrelated history")
			}
			// Raw synthetic headers supply a distant difficulty window; this is
			// bounded-history validation evidence, not a mined long-chain replay.
			guarded.minimum = height - uint64(types.DifficultyWindow)
			guarded.reads = 0
			candidate := mineEasy(parent, height+1)
			candidate.Kernels[0].ExcessSig = nil
			types.SetBlockRoots(candidate)
			chain := &Chain{store: guarded}
			if err := chain.ReorgTo([]*types.Block{candidate}); err == nil {
				t.Fatal("invalid signature accepted")
			}
			if guarded.reads != types.DifficultyWindow+2 {
				t.Fatalf("late invalid validation reads %d", guarded.reads)
			}
		})
	}
}

type failedDeltaReadStore struct {
	Store
	err error
}

func (s failedDeltaReadStore) storeDeltaReader() deltaReader {
	return deltaReader{
		output: func(c types.Commitment) (*types.Output, bool, error) {
			o, ok := s.Store.UTXOByCommit(c)
			return o, ok, nil
		},
		seenOutput: func(types.Commitment) (bool, error) { return false, s.err },
		seenKernel: func(types.Hash) (bool, error) { return false, s.err },
	}
}
func TestSecuritySuffixOverlayPreservesRawReadErrors(t *testing.T) {
	s := newMemStore()
	g := &types.Block{}
	if err := s.WriteBlock(g); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("injected historical read failure")
	f, err := newForkStore(failedDeltaReadStore{Store: s, err: sentinel}, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := &types.Block{Header: types.BlockHeader{Height: 1, PrevHash: types.HeaderID(&g.Header)}, Outputs: []types.Output{{Commit: types.Commitment{1}}}}
	if err := f.WriteBlock(b); !errors.Is(err, sentinel) {
		t.Fatalf("read error lost: %v", err)
	}
	if len(f.delta().Blocks) != 0 {
		t.Fatal("failed precondition mutated overlay")
	}
}
