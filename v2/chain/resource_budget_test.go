package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"os"
	"reflect"
	"testing"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

func maximumResourceBody() *types.Block {
	b := &types.Block{Header: types.BlockHeader{Height: 1}, Inputs: make([]types.Input, MaxBlockInputs), Outputs: make([]types.Output, MaxBlockOutputs), Kernels: make([]types.Kernel, MaxBlockKernels)}
	for i := range b.Outputs {
		b.Outputs[i].RangeProof = make([]byte, MaxRangeProofBytes)
	}
	for i := range b.Kernels {
		b.Kernels[i].ExcessSig = make([]byte, 65)
	}
	return b
}

// Opt-in finite storage-shape test: this contains synthetic proof bytes and
// deliberately tests retention/accounting, not cryptographic authorization.
func TestResourceMaximumSuffixSynthetic1024(t *testing.T) {
	if os.Getenv("NOSO_RESOURCE_MAX_SUFFIX") != "1" {
		t.Skip("set NOSO_RESOURCE_MAX_SUFFIX=1 for the 1024-block finite resource run")
	}
	makeBlock := func(height uint64, parent types.Hash, previous []types.Output, branch byte) *types.Block {
		b := maximumResourceBody()
		b.Header = easyHeader(parent, height)
		for i := range b.Outputs {
			b.Outputs[i].Commit[0] = 2
			b.Outputs[i].Commit[1] = branch
			binary.BigEndian.PutUint64(b.Outputs[i].Commit[2:10], height*4+uint64(i))
			b.Kernels[i].Excess = b.Outputs[i].Commit
		}
		b.Inputs = nil
		for _, out := range previous {
			b.Inputs = append(b.Inputs, types.Input{Commit: out.Commit, Features: out.Features})
		}
		return b
	}
	var s Store = newMemStore()
	if os.Getenv("NOSO_RESOURCE_MAX_BACKEND") == "badger" {
		disk, err := OpenBadger(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer disk.Close()
		s = disk
	}
	g := makeBlock(0, types.Hash{}, nil, 0)
	if err := s.WriteBlock(g); err != nil {
		t.Fatal(err)
	}
	previous := g
	for h := uint64(1); h <= MaxReorgBlocks; h++ {
		b := makeBlock(h, types.HeaderID(&previous.Header), previous.Outputs, 1)
		if err := s.WriteBlock(b); err != nil {
			t.Fatal(err)
		}
		previous = b
	}
	incoming := make([]*types.Block, MaxReorgBlocks)
	previous = g
	for i := range incoming {
		incoming[i] = makeBlock(uint64(i+1), types.HeaderID(&previous.Header), previous.Outputs, 2)
		previous = incoming[i]
	}
	if err := s.ReplaceSuffix(0, incoming); err != nil {
		t.Fatal(err)
	}
	tip, _ := s.Tip()
	if tip != incoming[len(incoming)-1].Header {
		t.Fatal("maximum suffix not published")
	}
	for h := uint64(1); h <= MaxReorgBlocks; h++ {
		undo, err := s.UndoAtBudget(h, MaxUndoRecordBytes)
		if err != nil || len(undo) != MaxBlockInputs {
			t.Fatalf("undo %d: %v", h, err)
		}
	}
	t.Logf("published %d synthetic maximum-shape blocks, %d proof bytes/output", MaxReorgBlocks, MaxRangeProofBytes)
}

func TestResourceV4ShapeBoundaries(t *testing.T) {
	b := maximumResourceBody()
	n, err := BodyResourceBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	const maximumShape = MaxBlockInputs*192 + MaxBlockOutputs*(128+MaxRangeProofBytes) + MaxBlockKernels*(128+65)
	if n != maximumShape || n > MaxBlockBodyBytes {
		t.Fatalf("maximum shape: %d, want %d", n, maximumShape)
	}
	for _, mutate := range []func(*types.Block){
		func(b *types.Block) { b.Inputs = append(b.Inputs, types.Input{}) },
		func(b *types.Block) { b.Outputs = append(b.Outputs, types.Output{}) },
		func(b *types.Block) { b.Kernels = append(b.Kernels, types.Kernel{}) },
		func(b *types.Block) { b.Outputs[0].RangeProof = append(b.Outputs[0].RangeProof, 0) },
		func(b *types.Block) { b.Kernels[0].ExcessSig = append(b.Kernels[0].ExcessSig, 0) },
	} {
		bad := cloneBlock(b)
		mutate(bad)
		if err := bodyBounds(bad); err == nil {
			t.Fatal("limit+1 accepted")
		}
	}
	// Sharing this fixture intentionally checks the aggregate without allocating
	// 1024 separate proof bodies. No identity/cryptographic validity is asserted.
	suffix := make([]*types.Block, MaxReorgBlocks)
	for i := range suffix {
		suffix[i] = b
	}
	if err := CheckReorgResourceBudget(suffix); err != nil {
		t.Fatal(err)
	}
	if err := CheckReorgResourceBudget(append(suffix, b)); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("depth+1: %v", err)
	}
}

func TestResourceMaximumEncodedUndoBoundAndIsolation(t *testing.T) {
	undo := maximumResourceBody().Outputs
	n, err := undoResourceBytes(undo)
	if err != nil || n != MaxUndoRecordBytes {
		t.Fatalf("undo charge: %d %v", n, err)
	}
	raw, err := encodeUndo(undo)
	if err != nil || len(raw) > MaxEncodedUndoBytes {
		t.Fatalf("encoded undo: %d %v", len(raw), err)
	}
	t.Logf("maximum shape undo charged=%d gob=%d encoded cap=%d", n, len(raw), MaxEncodedUndoBytes)
	s := newMemStore()
	s.undo[1] = undo
	if _, err := s.UndoAtBudget(1, n-1); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("budget-1: %v", err)
	}
	out, err := s.UndoAtBudget(1, n)
	if err != nil || !reflect.DeepEqual(out, undo) {
		t.Fatalf("budget boundary: %v", err)
	}
	out[0].RangeProof[0] = 9
	if undo[0].RangeProof[0] != 0 {
		t.Fatal("proof alias")
	}
	if _, err := undoResourceBytes(append(undo, types.Output{})); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("count+1: %v", err)
	}
}

func TestResourceBadgerUndoPredecodeGuard(t *testing.T) {
	s, err := OpenBadger(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Deliberately invalid gob: the expected sentinel proves the oversized raw
	// value was rejected before the decoder inspected it. This is only 123 KiB.
	if err := s.mutate(func(txn *stageTxn) error { return txn.Set(heightKey(kUndo, 1), make([]byte, MaxEncodedUndoBytes+1)) }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UndoAtBudget(1, MaxUndoRecordBytes); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("predecode: %v", err)
	}
	undo := maximumResourceBody().Outputs
	raw, err := encodeUndo(undo)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.mutate(func(txn *stageTxn) error { return txn.Set(heightKey(kUndo, 1), raw) }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UndoAtBudget(1, MaxUndoRecordBytes-1); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("decoded charge: %v", err)
	}
	if got, err := s.UndoAtBudget(1, MaxUndoRecordBytes); err != nil || !reflect.DeepEqual(got, undo) {
		t.Fatalf("maximum undo: %v", err)
	}
}

// With no height-0 exemption an output whose proof exceeds the consensus bound
// can never enter the store, so no oversized undo record can be produced. Both
// backends must refuse it atomically at the first write.
func TestResourceStoresRejectOversizedOutputAtomic(t *testing.T) {
	disk, err := OpenBadger(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	g := easyGenesisBlock(t)
	g.Outputs = []types.Output{{Commit: storePoint(t, 71), RangeProof: make([]byte, MaxRangeProofBytes+1)}}
	for _, s := range []Store{newMemStore(), disk} {
		if err := s.WriteBlock(g); err == nil {
			t.Fatal("oversized output accepted")
		}
		if _, ok := s.Tip(); ok || s.HasUTXO(g.Outputs[0].Commit) || s.HasOutput(g.Outputs[0].Commit) {
			t.Fatal("rejected write changed canonical state")
		}
	}
}

func TestResourceV4MaximumShapeStoreParity(t *testing.T) {
	disk, err := OpenBadger(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	mem := newMemStore()
	g := easyGenesisBlock(t)
	b := maximumResourceBody()
	b.Inputs = nil
	b.Header = easyHeader(types.HeaderID(&g.Header), 1)
	for i := range b.Outputs {
		b.Outputs[i].Commit = storePoint(t, byte(i+10))
	}
	for i := range b.Kernels {
		b.Kernels[i].Excess = storePoint(t, byte(i+20))
	}
	types.SetBlockRoots(b)
	for _, s := range []Store{mem, disk} {
		if err := s.WriteBlock(g); err != nil {
			t.Fatal(err)
		}
		if err := s.WriteBlock(b); err != nil {
			t.Fatal(err)
		}
		b.Header.Nonce++
		if err := s.ReplaceSuffix(0, []*types.Block{b}); err != nil {
			t.Fatal(err)
		}
		got, err := s.BlockAt(1)
		if err != nil || !reflect.DeepEqual(got, b) {
			t.Fatalf("roundtrip: %v", err)
		}
	}
}

// Four native inputs and all four output slots are exercised through actual
// PoW, two independent real range proofs, signatures, balance and publication.
func TestResourceV4NativePaymentFullPipeline(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		g := easyGenesisBlock(t)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		blocks := appendBlocks(t, c, 1, 64)
		const fee = 100
		var amount int64
		x := new(big.Int)
		inputs := make([]types.Input, MaxBlockInputs)
		for i := range inputs {
			source := blocks[i]
			seed := append([]byte("chain test coinbase"), source.Header.PrevHash[:]...)
			seed = binary.BigEndian.AppendUint64(seed, source.Header.Height)
			blind := sha256.Sum256(seed)
			x.Sub(x, new(big.Int).SetBytes(blind[:]))
			amount += types.BlockReward(source.Header.Height)
			inputs[i] = types.Input{Features: types.OutputFeaturesCoinbase, Commit: source.Outputs[0].Commit}
		}
		third := (amount - fee) / 3
		a, err := wallet.NewPlainOutput(int64(third))
		if err != nil {
			t.Fatal(err)
		}
		b, err := wallet.NewPlainOutput(int64(third))
		if err != nil {
			t.Fatal(err)
		}
		d, err := wallet.NewPlainOutput(int64(amount - fee - 2*third))
		if err != nil {
			t.Fatal(err)
		}
		if len(a.Output.RangeProof) != MaxRangeProofBytes || len(b.Output.RangeProof) != MaxRangeProofBytes || len(d.Output.RangeProof) != MaxRangeProofBytes {
			t.Fatal("proof encoding bound drift")
		}
		x.Add(x, new(big.Int).SetBytes(a.Blinding[:]))
		x.Add(x, new(big.Int).SetBytes(b.Blinding[:]))
		x.Add(x, new(big.Int).SetBytes(d.Blinding[:]))
		x.Mod(x, v2crypto.Curve().Params().N)
		scalar := x.FillBytes(make([]byte, 32))
		excess, err := v2crypto.PublicFromScalar(scalar)
		if err != nil {
			t.Fatal(err)
		}
		k := types.Kernel{Fee: fee, Excess: excess}
		k.ExcessSig, err = v2crypto.SchnorrSign(scalar, types.KernelSigningMessage(0, &k))
		if err != nil {
			t.Fatal(err)
		}
		tip, _ := c.Tip()
		block := &types.Block{Header: easyHeader(types.HeaderID(&tip), tip.Height+1), Inputs: inputs, Outputs: []types.Output{a.Output, b.Output, d.Output}, Kernels: []types.Kernel{k}}
		sealFixture(block)
		if len(block.Outputs) != MaxBlockOutputs {
			t.Fatal("expected all output slots")
		}
		if err := c.AddBlock(block); err != nil {
			t.Fatalf("native payment: %v", err)
		}
		if _, err := c.store.UndoAtBudget(block.Header.Height, MaxUndoRecordBytes); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, c)
		bad := cloneBlock(block)
		bad.Header.Height++
		bad.Header.PrevHash = types.HeaderID(&block.Header)
		bad.Inputs = append(bad.Inputs, types.Input{})
		types.SetBlockRoots(bad)
		if err := c.AddBlock(bad); err == nil {
			t.Fatal("input limit+1 accepted")
		}
		if !reflect.DeepEqual(before, snapshot(t, c)) {
			t.Fatal("oversize rejection mutated canonical state")
		}
	})
}
