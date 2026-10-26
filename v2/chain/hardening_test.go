package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/dgraph-io/badger/v4"
	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/pow"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

func backendChains(t *testing.T, fn func(*testing.T, *Chain, string)) {
	t.Helper()
	for _, backend := range []string{"memory", "badger"} {
		t.Run(backend, func(t *testing.T) {
			dir := t.TempDir()
			c := NewMemory()
			if backend == "badger" {
				var err error
				c, err = NewBadger(dir)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer c.Close()
			fn(t, c, dir)
		})
	}
}

func snapshot(t *testing.T, c *Chain) map[string][]byte {
	t.Helper()
	tip, ok := c.Tip()
	if !ok {
		t.Fatal("missing tip")
	}
	var blocks []*types.Block
	for h := uint64(0); h <= tip.Height; h++ {
		b, err := c.store.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, b)
	}
	entries, err := stateEntries(blocks)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range entries {
		if len(key) > 0 && key[0] == kOutputSeen {
			var commit types.Commitment
			copy(commit[:], []byte(key)[1:])
			if !c.store.HasOutput(commit) {
				t.Fatal("missing historical output index")
			}
		}
		if len(key) > 0 && key[0] == kKernelSeen {
			var id types.Hash
			copy(id[:], []byte(key)[1:])
			if !c.store.HasKernel(id) {
				t.Fatal("missing historical kernel index")
			}
		}

		if len(key) > 0 && key[0] == kUTXO {
			var commit types.Commitment
			copy(commit[:], []byte(key)[1:])
			o, ok := c.store.UTXOByCommit(commit)
			if !ok {
				t.Fatal("missing actual utxo")
			}
			got, _ := encodeOutput(o)
			if !bytes.Equal(got, want) {
				t.Fatal("actual UTXO metadata mismatch")
			}
		}
	}
	if b, ok := c.store.(*BadgerStore); ok {
		if err := b.verifyState(blocks); err != nil {
			t.Fatal(err)
		}
	}
	return entries
}

func TestSecurityBlockAuthorizationMutations(t *testing.T) {
	mutations := map[string]func(*types.Block){
		"missing subsidy":   func(b *types.Block) { b.Outputs = nil; b.Kernels = nil },
		"missing signature": func(b *types.Block) { b.Kernels[0].ExcessSig = nil },
		"wrong signature":   func(b *types.Block) { b.Kernels[0].ExcessSig[40] ^= 1 },
		"duplicate subsidy": func(b *types.Block) {
			b.Outputs = append(b.Outputs, b.Outputs[0])
			b.Kernels = append(b.Kernels, b.Kernels[0])
		},
		"wrong subsidy value": func(b *types.Block) {
			blind := sha256.Sum256([]byte("inflation"))
			commit, _ := v2crypto.PedersenCommit(types.BlockReward(1)+1, blind[:])
			sig, _ := wallet.SignCoinbase(wallet.CoinbaseRecord{Height: 1, Amount: types.BlockReward(1) + 1, Blinding: blind, Commit: commit})
			b.Outputs[0].Commit = commit
			b.Kernels[0].Excess = commit
			b.Kernels[0].ExcessSig = sig
		},
		"legacy mint": func(b *types.Block) {
			b.Outputs[0].Features = types.OutputFeaturesLegacy
			b.Outputs[0].LegacyAddress = "stolen"
			b.Outputs[0].LegacyAmount = 123
		},
		"unknown feature": func(b *types.Block) { b.Outputs[0].Features = 255 },
		"offset":          func(b *types.Block) { b.Header.TotalKernelOffset[0] = 1 },
		"version":         func(b *types.Block) { b.Header.Version-- },
		"foreign network": func(b *types.Block) { b.Header.NetworkMagic++ },
		"coinbase fee":    func(b *types.Block) { b.Kernels[0].Fee = 1 },
		"coinbase lock":   func(b *types.Block) { b.Kernels[0].LockHeight = 0 },
	}
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		g := easyGenesisBlock(t)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, c)
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				b := mineEasy(types.HeaderID(&g.Header), 1)
				mutate(b)
				types.SetBlockRoots(b)
				if err := c.AddBlock(b); err == nil {
					t.Fatal("malicious block accepted")
				}
				if !reflect.DeepEqual(before, snapshot(t, c)) {
					t.Fatal("failure changed chain")
				}
			})
		}
	})
}

func appendBlocks(t *testing.T, c *Chain, start, end uint64) []*types.Block {
	t.Helper()
	var blocks []*types.Block
	for h := start; h <= end; h++ {
		tip, _ := c.Tip()
		b := mineEasy(types.HeaderID(&tip), h)
		if err := c.AddBlock(b); err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, b)
	}
	return blocks
}

func TestSecurityReorgRollbackAndStrictWork(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		g := easyGenesisBlock(t)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		appendBlocks(t, c, 1, 3)
		before := snapshot(t, c)
		a := mineEasy(types.HeaderID(&g.Header), 1)
		b := mineEasy(types.HeaderID(&a.Header), 2)
		d := mineEasy(types.HeaderID(&b.Header), 3)
		e := mineEasy(types.HeaderID(&d.Header), 4)
		bad := cloneBlock(e)
		bad.Kernels[0].ExcessSig = nil
		types.SetBlockRoots(bad)
		if err := c.ReorgTo([]*types.Block{a, b, d, bad}); err == nil {
			t.Fatal("invalid later fork block accepted")
		}
		if !reflect.DeepEqual(before, snapshot(t, c)) {
			t.Fatal("failed suffix changed state")
		}
		if err := c.ReorgTo([]*types.Block{a, b, d}); err == nil {
			t.Fatal("equal work fork accepted")
		}
		if !reflect.DeepEqual(before, snapshot(t, c)) {
			t.Fatal("equal work changed state")
		}
		if err := c.ReorgTo([]*types.Block{a, b, d, e}); err != nil {
			t.Fatal(err)
		}
		if c.Height() != 4 {
			t.Fatal("higher work not selected")
		}
		if _, ok := c.store.HeightOf(types.HeaderID(&beforeBlock(before, 3).Header)); ok {
			t.Fatal("old hash index retained")
		}
	})
}

func beforeBlock(entries map[string][]byte, h uint64) *types.Block {
	b, _ := decodeBlock(entries[string(heightKey(kBlock, h))])
	return b
}

// noHistoricalIndex reproduces the former admission behavior without mutating
// production code or bypassing cryptographic/body/state checks.
type noHistoricalIndex struct{ Store }

func (noHistoricalIndex) HasOutput(types.Commitment) bool { return false }
func (noHistoricalIndex) HasKernel(types.Hash) bool       { return false }

type failReplace struct{ Store }

func (f failReplace) ReplaceChain([]*types.Block) error { return errors.New("injected commit failure") }
func TestSecurityReorgCommitFailureUnchanged(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	appendBlocks(t, c, 1, 1)
	before := snapshot(t, c)
	c.store = failReplace{c.store}
	a := mineEasy(types.HeaderID(&g.Header), 1)
	b := mineEasy(types.HeaderID(&a.Header), 2)
	if err := c.ReorgTo([]*types.Block{a, b}); err == nil {
		t.Fatal("missing injected failure")
	}
	if !reflect.DeepEqual(before, snapshot(t, c)) {
		t.Fatal("commit failure changed chain")
	}
}

func fixtureSpend(t *testing.T, source *types.Block, height uint64) (*types.Block, [32]byte) {
	t.Helper()
	seed := append([]byte("chain test coinbase"), source.Header.PrevHash[:]...)
	seed = binary.BigEndian.AppendUint64(seed, source.Header.Height)
	blind := sha256.Sum256(seed)
	out, err := wallet.NewPlainOutput(types.BlockReward(source.Header.Height))
	if err != nil {
		t.Fatal(err)
	}
	x := new(big.Int).Sub(new(big.Int).SetBytes(out.Blinding[:]), new(big.Int).SetBytes(blind[:]))
	x.Mod(x, secp.S256().Params().N)
	scalar := x.FillBytes(make([]byte, 32))
	excess, err := v2crypto.PedersenCommit(0, scalar)
	if err != nil {
		t.Fatal(err)
	}
	k := types.Kernel{Excess: excess}
	id := types.KernelID(&k)
	k.ExcessSig, err = v2crypto.SchnorrSign(scalar, id[:])
	if err != nil {
		t.Fatal(err)
	}
	return &types.Block{Header: types.BlockHeader{Height: height}, Inputs: []types.Input{{Features: types.OutputFeaturesCoinbase, Commit: source.Outputs[0].Commit}}, Outputs: []types.Output{out.Output}, Kernels: []types.Kernel{k}}, [32]byte(out.Blinding)
}

func TestSecurityNativeAuthorizationMaturityAndUndo(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		g := easyGenesisBlock(t)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		source := appendBlocks(t, c, 1, 1)[0]
		spend, spendBlind := fixtureSpend(t, source, 2)
		tip, _ := c.Tip()
		spend.Header = easyHeader(types.HeaderID(&tip), 2)
		sealFixture(spend)
		before := snapshot(t, c)
		if err := c.AddBlock(spend); err == nil {
			t.Fatal("immature coinbase accepted")
		}
		if !reflect.DeepEqual(before, snapshot(t, c)) {
			t.Fatal("immature rejection changed state")
		}
		appendBlocks(t, c, 2, 60)
		tip, _ = c.Tip()
		spend.Header = easyHeader(types.HeaderID(&tip), 61)
		spend.Outputs = spend.Outputs[:1]
		spend.Kernels = spend.Kernels[:1]
		sealFixture(spend)
		tx := &types.Transaction{Inputs: spend.Inputs, Outputs: spend.Outputs[:1], Kernels: spend.Kernels[:1]}
		if err := c.ValidateTransaction(tx); err != nil {
			t.Fatalf("valid mature tx rejected: %v", err)
		}
		original := append([]byte(nil), spend.Kernels[0].ExcessSig...)
		spend.Kernels[0].ExcessSig[40] ^= 1
		types.SetBlockRoots(spend)
		if err := c.AddBlock(spend); err == nil || !strings.Contains(err.Error(), "kernel authorization") {
			t.Fatalf("forged excess wrong rejection: %v", err)
		}
		spend.Kernels[0].ExcessSig = original
		proofMutation := cloneBlock(spend)
		proofMutation.Outputs[0].RangeProof[100] ^= 1
		if err := c.AddBlock(proofMutation); err == nil || !strings.Contains(err.Error(), "roots mismatch") {
			t.Fatalf("uncommitted body mutation wrong rejection: %v", err)
		}
		legacyProof := cloneBlock(spend)
		legacyProof.Outputs[0].RangeProof = append([]byte{1}, make([]byte, 32)...)
		types.SetBlockRoots(legacyProof)
		if err := c.AddBlock(legacyProof); !errors.Is(err, ErrBadOutput) {
			t.Fatalf("fake v1 proof wrong rejection: %v", err)
		}
		types.SetBlockRoots(proofMutation)
		if err := c.AddBlock(proofMutation); !errors.Is(err, ErrBadOutput) {
			t.Fatalf("invalid range proof wrong rejection: %v", err)
		}
		featureMutation := cloneBlock(spend)
		featureMutation.Inputs[0].Features = types.OutputFeaturesPlain
		types.SetBlockRoots(featureMutation)
		if err := c.AddBlock(featureMutation); err == nil || !strings.Contains(err.Error(), "metadata mismatch") {
			t.Fatalf("stored feature bypass wrong rejection: %v", err)
		}

		duplicate := cloneBlock(spend)
		duplicate.Inputs = append(duplicate.Inputs, duplicate.Inputs[0])
		types.SetBlockRoots(duplicate)
		if err := c.AddBlock(duplicate); err == nil {
			t.Fatal("duplicate spend accepted")
		}
		types.SetBlockRoots(spend)
		if err := c.AddBlock(spend); err != nil {
			t.Fatalf("valid mature spend: %v", err)
		}

		assertFixtureSupply(t, c, spendBlind)
		// A balance-valid owner can recreate a spent commitment and thereby
		// replay an old signed transfer unless active-history identities persist.
		seed := append([]byte("chain test coinbase"), source.Header.PrevHash[:]...)
		seed = binary.BigEndian.AppendUint64(seed, source.Header.Height)
		sourceBlind := sha256.Sum256(seed)
		proof, err := v2crypto.ProveRange(source.Outputs[0].Commit, sourceBlind[:], types.BlockReward(source.Header.Height))
		if err != nil {
			t.Fatal(err)
		}
		scalarInt := new(big.Int).Sub(new(big.Int).SetBytes(sourceBlind[:]), new(big.Int).SetBytes(spendBlind[:]))
		scalarInt.Mod(scalarInt, secp.S256().Params().N)
		scalar := scalarInt.FillBytes(make([]byte, 32))
		excess, err := v2crypto.PedersenCommit(0, scalar)
		if err != nil {
			t.Fatal(err)
		}
		kernel := types.Kernel{Excess: excess}
		id := types.KernelID(&kernel)
		kernel.ExcessSig, err = v2crypto.SchnorrSign(scalar, id[:])
		if err != nil {
			t.Fatal(err)
		}
		tip, _ = c.Tip()
		cycle := &types.Block{Header: easyHeader(types.HeaderID(&tip), 62), Inputs: []types.Input{{Commit: spend.Outputs[0].Commit}}, Outputs: []types.Output{{Commit: source.Outputs[0].Commit, RangeProof: proof}}, Kernels: []types.Kernel{kernel}}
		cycleTx := &types.Transaction{Inputs: cycle.Inputs, Outputs: cycle.Outputs, Kernels: cycle.Kernels}
		if err := c.validateBalance(cycle); err != nil {
			t.Fatalf("history recreation fixture not balanced: %v", err)
		}
		realStore := c.store
		c.store = noHistoricalIndex{realStore}
		priorErr := c.ValidateTransaction(cycleTx)
		c.store = realStore
		if priorErr != nil {
			t.Fatalf("historical recreation did not reproduce former admission: %v", priorErr)
		}
		if err := c.ValidateTransaction(cycleTx); err == nil || !strings.Contains(err.Error(), "existing output") {
			t.Fatalf("mempool historical recreation wrong rejection: %v", err)
		}
		sealFixture(cycle)
		beforeCycle := snapshot(t, c)
		if err := c.AddBlock(cycle); err == nil || !strings.Contains(err.Error(), "existing output") {
			t.Fatalf("historical recreation wrong rejection: %v", err)
		}
		// A prior signed excess can also make a valid zero-value output. The
		// balance equation alone cannot prohibit historical kernel replay.
		oldScalar := new(big.Int).Neg(scalarInt)
		oldScalar.Mod(oldScalar, secp.S256().Params().N)
		oldBytes := oldScalar.FillBytes(make([]byte, 32))
		zeroProof, err := v2crypto.ProveRange(spend.Kernels[0].Excess, oldBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		replay := &types.Block{Header: easyHeader(types.HeaderID(&tip), 62), Outputs: []types.Output{{Commit: spend.Kernels[0].Excess, RangeProof: zeroProof}}, Kernels: []types.Kernel{spend.Kernels[0]}}
		if err := c.validateBalance(replay); err != nil {
			t.Fatalf("kernel replay fixture not balanced: %v", err)
		}
		sealFixture(replay)
		c.store = noHistoricalIndex{realStore}
		priorErr = c.ValidateBlock(replay)
		c.store = realStore
		if priorErr != nil {
			t.Fatalf("kernel replay did not reproduce former admission: %v", priorErr)
		}
		if err := c.AddBlock(replay); err == nil || !strings.Contains(err.Error(), "duplicate kernel") {
			t.Fatalf("historical kernel wrong rejection: %v", err)
		}
		if !reflect.DeepEqual(beforeCycle, snapshot(t, c)) {
			t.Fatal("history rejection changed state")
		}
		// Undo must restore the complete original coinbase metadata, not input copies.
		if err := c.store.UndoBlock(); err != nil {
			t.Fatal(err)
		}
		restored, ok := c.store.UTXOByCommit(source.Outputs[0].Commit)
		if !ok || !reflect.DeepEqual(*restored, source.Outputs[0]) {
			t.Fatal("undo lost original output metadata")
		}
		assertFixtureSupply(t, c, spendBlind)
		if c.store.HasOutput(spend.Outputs[0].Commit) || c.store.HasKernel(types.KernelID(&spend.Kernels[0])) {
			t.Fatal("undo retained orphan history identities")
		}
		snapshot(t, c)
	})
}

func TestSecurityBadgerAbruptExit(t *testing.T) {
	if dir := os.Getenv("NOSO_CRASH_TEST_DIR"); dir != "" {
		c, err := NewBadger(dir)
		if err != nil {
			panic(err)
		}
		g := mineEasy(types.Hash{}, 0)
		if err = c.LoadOrInit(dir, g); err != nil {
			panic(err)
		}
		appendBlocks(t, c, 1, 2)
		a := mineEasy(types.HeaderID(&g.Header), 1)
		b := mineEasy(types.HeaderID(&a.Header), 2)
		d := mineEasy(types.HeaderID(&b.Header), 3)
		if err = c.ReorgTo([]*types.Block{a, b, d}); err != nil {
			panic(err)
		}
		os.Exit(23)
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSecurityBadgerAbruptExit$")
	cmd.Env = append(os.Environ(), "NOSO_CRASH_TEST_DIR="+dir)
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 23 {
		t.Fatalf("child: %v", err)
	}
	c, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := mineEasy(types.Hash{}, 0)
	if err = c.LoadOrInit(dir, g); err != nil {
		t.Fatal(err)
	}
	if c.Height() != 3 {
		t.Fatal("committed reorg lost after abrupt exit")
	}
	snapshot(t, c)
}

func TestSecurityBackendParityAndNestedSlices(t *testing.T) {
	dir := t.TempDir()
	disk, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	memory := NewMemory()
	defer memory.Close()
	g := easyGenesisBlock(t)
	if err := disk.LoadOrInit(dir, g); err != nil {
		t.Fatal(err)
	}
	if err := memory.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	parent := types.HeaderID(&g.Header)
	for h := uint64(1); h <= 5; h++ {
		b := mineEasy(parent, h)
		for _, c := range []*Chain{memory, disk} {
			if err := c.AddBlock(b); err != nil {
				t.Fatal(err)
			}
		}
		parent = types.HeaderID(&b.Header)
		b.Kernels[0].ExcessSig[40] ^= 1
	}
	if !reflect.DeepEqual(snapshot(t, memory), snapshot(t, disk)) {
		t.Fatal("backend states differ")
	}
	for _, c := range []*Chain{memory, disk} {
		before := snapshot(t, c)
		b, _ := c.BlockByHeight(3)
		b.Kernels[0].ExcessSig[0] ^= 1
		if !reflect.DeepEqual(before, snapshot(t, c)) {
			t.Fatal("getter signature aliases history")
		}
	}
}

func TestSecurityLegacyClaimFailsClosed(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		blind := sha256.Sum256([]byte("NosoX legacy blind Nlegacy"))
		commit, err := v2crypto.PedersenCommit(1234, blind[:])
		if err != nil {
			t.Fatal(err)
		}
		g := easyGenesisBlock(t)
		g.Outputs = []types.Output{{Features: types.OutputFeaturesLegacy, Commit: commit, LegacyAddress: "Nlegacy", LegacyAmount: 1234}}
		types.SetBlockRoots(g)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, c)
		// A public legacy blinding and an attacker-made native proof are insufficient
		// ownership evidence, even when the attacker supplies arbitrary legacy auth.
		b := mineEasy(types.HeaderID(&g.Header), 1)
		b.Inputs = []types.Input{{Features: types.OutputFeaturesLegacy, Commit: commit, LegacyAddr: "Nlegacy", LegacyAmount: 1234, LegacySig: "attacker"}}
		types.SetBlockRoots(b)
		if err := c.AddBlock(b); err == nil || !strings.Contains(err.Error(), "ownership procedure") {
			t.Fatalf("legacy theft wrong rejection: %v", err)
		}
		if !reflect.DeepEqual(before, snapshot(t, c)) {
			t.Fatal("legacy rejection changed state")
		}
	})
}

func TestSecurityBadgerOversizeTransactionRollback(t *testing.T) {
	dir := t.TempDir()
	c, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(dir, g); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, c)
	// Bypass consensus bounds deliberately to fault the backend itself after the
	// transaction has already accumulated writes. Oversize must never split commits.
	b := mineEasy(types.HeaderID(&g.Header), 1)
	b.Outputs = make([]types.Output, 40000)
	for i := range b.Outputs {
		binary.BigEndian.PutUint64(b.Outputs[i].Commit[1:9], uint64(i))
		b.Outputs[i].RangeProof = make([]byte, 512)
	}
	if err := c.store.ReplaceChain([]*types.Block{g, b}); !errors.Is(err, badger.ErrTxnTooBig) {
		t.Fatalf("expected actual Badger transaction-size failure, got %v", err)
	}
	if !reflect.DeepEqual(before, snapshot(t, c)) {
		t.Fatal("aborted backend transaction changed state")
	}
}

func TestSecurityBadgerMissingTipFailsClosed(t *testing.T) {
	dir := t.TempDir()
	c, err := NewBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(dir, g); err != nil {
		t.Fatal(err)
	}
	s := c.store.(*BadgerStore)
	if err := s.db.Update(func(txn *badger.Txn) error { return txn.Delete([]byte{kTip}) }); err != nil {
		t.Fatal(err)
	}
	if err := c.LoadOrInit(dir, g); err == nil {
		t.Fatal("corrupt nonempty database reinitialized")
	}
}

func TestSecurityShorterHeavierForkWins(t *testing.T) {
	if testing.Short() {
		t.Skip("full proof-of-work fork scenario")
	}
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	appendBlocks(t, c, 1, 100)
	forkChain := NewMemory()
	if err := forkChain.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	var fork []*types.Block
	for h := uint64(1); h <= 91; h++ {
		tip, _ := forkChain.Tip()
		b := &types.Block{Header: easyHeader(types.HeaderID(&tip), h)}
		b.Header.Timestamp = g.Header.Timestamp + int64(h)
		b.Header.Difficulty = forkChain.NextDifficulty()
		sealFixture(b)
		mined := false
		for n := uint64(0); n < 1<<16; n++ {
			b.Header.Nonce = n
			if pow.Verify(&b.Header) {
				mined = true
				break
			}
		}
		if !mined {
			t.Fatal("nonce budget exhausted")
		}
		if err := forkChain.AddBlock(b); err != nil {
			t.Fatal(err)
		}
		fork = append(fork, b)
	}
	if fork[len(fork)-1].Header.Difficulty <= 1 {
		t.Fatal("scenario failed to create greater work")
	}
	if err := c.ReorgTo(fork); err != nil {
		t.Fatal(err)
	}
	if c.Height() != 91 {
		t.Fatal("shorter greater-work fork not selected")
	}
	snapshot(t, c)
}

func TestSecurityFutureTimestampCannotFreezeChain(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		g := easyGenesisBlock(t)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		fixedNow := baseTime + 1000
		c.now = func() time.Time { return time.Unix(fixedNow, 0) }
		before := snapshot(t, c)
		for _, timestamp := range []int64{fixedNow + 7201, math.MaxInt64} {
			b := mineEasy(types.HeaderID(&g.Header), 1)
			b.Header.Timestamp = timestamp
			err := c.AddBlock(b)
			if err == nil || !strings.Contains(err.Error(), "future drift") {
				t.Fatalf("future timestamp rejected for wrong reason: %v", err)
			}
			if !reflect.DeepEqual(before, snapshot(t, c)) {
				t.Fatal("future timestamp changed state")
			}
		}
		b := mineEasy(types.HeaderID(&g.Header), 1)
		b.Header.Timestamp = fixedNow + 7200
		if err := c.AddBlock(b); err != nil {
			t.Fatalf("permitted drift boundary rejected: %v", err)
		}
	})
}

// scheduleStore supplies only a bounded synthetic difficulty window and tip.
// It exercises the complete AddBlock validator at distant schedule heights;
// it does not claim that a 2.31-million-block history was mined/replayed.
type scheduleStore struct {
	Store
	tip    types.BlockHeader
	writes int
}

func (s *scheduleStore) Tip() (types.BlockHeader, bool) { return s.tip, true }
func (s *scheduleStore) BlockAt(h uint64) (*types.Block, error) {
	if h > s.tip.Height || h < s.tip.Height-uint64(types.DifficultyWindow) {
		return nil, errors.New("synthetic history outside window")
	}
	hdr := s.tip
	hdr.Height = h
	hdr.Timestamp = baseTime + int64(h-(s.tip.Height-uint64(types.DifficultyWindow)))*types.TargetBlockTimeSeconds
	return &types.Block{Header: hdr}, nil
}
func (s *scheduleStore) WriteBlock(b *types.Block) error { s.writes++; s.tip = b.Header; return nil }

func scheduledCandidate(t *testing.T, height uint64, amount int64, coinbase bool) (*Chain, *scheduleStore, *types.Block) {
	t.Helper()
	tip := types.BlockHeader{Version: types.BlockVersion, Height: height - 1, Timestamp: baseTime + int64(types.DifficultyWindow)*types.TargetBlockTimeSeconds, Difficulty: 1}
	store := &scheduleStore{Store: newMemStore(), tip: tip}
	c := &Chain{store: store}
	b := &types.Block{Header: types.BlockHeader{Version: types.BlockVersion, Height: height, PrevHash: types.HeaderID(&tip), Timestamp: tip.Timestamp + types.TargetBlockTimeSeconds, Difficulty: 1}}
	if coinbase {
		blind := sha256.Sum256([]byte("schedule edge"))
		commit, err := v2crypto.PedersenCommit(amount, blind[:])
		if err != nil {
			t.Fatal(err)
		}
		sig, err := wallet.SignCoinbase(wallet.CoinbaseRecord{Height: height, Amount: amount, Blinding: blind, Commit: commit})
		if err != nil {
			t.Fatal(err)
		}
		b.Outputs = []types.Output{{Features: types.OutputFeaturesCoinbase, Commit: commit}}
		b.Kernels = []types.Kernel{{Features: types.KernelFeaturesCoinbase, Excess: commit, ExcessSig: sig, LockHeight: height + types.CoinbaseLock}}
	}
	types.SetBlockRoots(b)
	return c, store, b
}

func TestSecuritySyntheticScheduleEdgesThroughAddBlock(t *testing.T) {
	end := types.BlockHalvingInterval * (types.HalvingSteps + 1)
	for _, height := range []uint64{types.BlockHalvingInterval - 1, types.BlockHalvingInterval, types.BlockHalvingInterval + 1, end - 1, end, end + 1} {
		t.Run(fmt.Sprint(height), func(t *testing.T) {
			reward := types.BlockReward(height)
			c, s, b := scheduledCandidate(t, height, reward, reward > 0)
			if err := c.AddBlock(b); err != nil {
				t.Fatalf("correct scheduled issuance rejected: %v", err)
			}
			if s.writes != 1 {
				t.Fatal("correct block not written")
			}
			c, s, b = scheduledCandidate(t, height, reward+1, true)
			before := s.tip
			err := c.AddBlock(b)
			if err == nil || (!strings.Contains(err.Error(), "subsidy authorization") && !strings.Contains(err.Error(), "issuance ended")) {
				t.Fatalf("wrong subsidy rejection: %v", err)
			}
			if s.writes != 0 || s.tip != before {
				t.Fatal("issuance failure mutated state")
			}
		})
	}
	c, s, b := scheduledCandidate(t, types.BlockHalvingInterval, types.BlockReward(types.BlockHalvingInterval), true)
	scalar := make([]byte, 32)
	scalar[31] = 1
	excess, err := v2crypto.PublicFromScalar(scalar)
	if err != nil {
		t.Fatal(err)
	}
	k := types.Kernel{Excess: excess, Fee: math.MaxUint64}
	id := types.KernelID(&k)
	k.ExcessSig, err = v2crypto.SchnorrSign(scalar, id[:])
	if err != nil {
		t.Fatal(err)
	}
	b.Kernels = append(b.Kernels, k)
	types.SetBlockRoots(b)
	if err := c.AddBlock(b); err == nil || !strings.Contains(err.Error(), "fee overflow") {
		t.Fatalf("fee overflow wrong rejection: %v", err)
	}
	if s.writes != 0 {
		t.Fatal("fee overflow mutated state")
	}
}

// Check the aggregate actual unspent commitments against independently counted
// scheduled issuance, including subsidy moved into a consumed-and-replaced native
// output. The test knows fixture blindings; validators do not disclose them.
func assertFixtureSupply(t *testing.T, c *Chain, nativeBlind [32]byte) {
	t.Helper()
	tip, _ := c.Tip()
	var positive [][33]byte
	blindSum := new(big.Int)
	for h := uint64(1); h <= tip.Height; h++ {
		b, _ := c.BlockByHeight(h)
		for _, o := range b.Outputs {
			if !c.store.HasUTXO(o.Commit) {
				continue
			}
			positive = append(positive, o.Commit)
			var blind [32]byte
			switch o.Features {
			case types.OutputFeaturesCoinbase:
				seed := append([]byte("chain test coinbase"), b.Header.PrevHash[:]...)
				seed = binary.BigEndian.AppendUint64(seed, h)
				blind = sha256.Sum256(seed)
			case types.OutputFeaturesPlain:
				blind = nativeBlind
			default:
				t.Fatal("unexpected supply fixture feature")
			}
			blindSum.Add(blindSum, new(big.Int).SetBytes(blind[:]))
		}
	}
	blindSum.Mod(blindSum, secp.S256().Params().N)
	// This bounded scenario is entirely before the first halving.
	if tip.Height >= types.BlockHalvingInterval {
		t.Fatal("supply fixture crossed halving")
	}
	issued := int64(tip.Height) * types.InitialReward
	want, err := v2crypto.PedersenCommit(issued, blindSum.FillBytes(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := v2crypto.PedersenSumZero(positive, [][33]byte{want}, 0)
	if err != nil || !ok {
		t.Fatalf("retained UTXO supply differs from authorized issuance: %v", err)
	}
}

type countPrefixReads struct {
	Store
	reads *int
}

func (s countPrefixReads) BlockAt(h uint64) (*types.Block, error) {
	*s.reads++
	return s.Store.BlockAt(h)
}

func TestSecurityReorgRejectsMalformedBeforePrefixRead(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	b := mineEasy(types.HeaderID(&g.Header), 1)
	b.Header.OutputRoot[0] ^= 1
	reads := 0
	c.store = countPrefixReads{Store: c.store, reads: &reads}
	if err := c.ReorgTo([]*types.Block{b}); err == nil {
		t.Fatal("malformed suffix accepted")
	}
	if reads != 0 {
		t.Fatal("malformed suffix copied retained history before rejection")
	}
}
