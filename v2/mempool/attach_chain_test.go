package mempool

import (
	"path/filepath"
	"testing"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/pasichDev/noso-go/v2/chain"
	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/pow"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

// This file drives a REAL chain and a REAL pool joined by Attach: no mocks of
// either side. Blocks are mined at difficulty 1 with deterministic coinbase
// keys so a test can spend them.

func attachGenesis() *types.Block {
	hdr := types.BlockHeader{Version: types.BlockVersion, NetworkMagic: types.NetworkMagicTestnet,
		Timestamp: time.Now().Unix() - 600, Difficulty: 1}
	for n := uint64(0); n < 64; n++ {
		hdr.Nonce = n
		if pow.Verify(&hdr) {
			break
		}
	}
	b := &types.Block{Header: hdr}
	types.SetBlockRoots(b)
	return b
}

// cbBlind is the deterministic coinbase blinding of the block at height h on
// parent; salt separates competing branches.
func cbBlind(parent types.Hash, h uint64, salt byte) [32]byte {
	var b [32]byte
	b[31], b[30], b[29] = byte(h+1), parent[0], salt
	return b
}

// attachBlock mines a block at difficulty 1 carrying tx (may be nil).
func attachBlock(t *testing.T, parent types.Hash, h uint64, salt byte, tx *types.Transaction) *types.Block {
	t.Helper()
	hdr := types.BlockHeader{Version: types.BlockVersion, NetworkMagic: types.NetworkMagicTestnet,
		Height: h, Timestamp: time.Now().Unix() - 300 + int64(h), PrevHash: parent, Difficulty: 1}
	blind := cbBlind(parent, h, salt)
	commit, err := v2crypto.PedersenCommit(types.BlockReward(h), blind[:])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wallet.SignCoinbase(hdr.NetworkMagic, wallet.CoinbaseRecord{Height: h, Amount: types.BlockReward(h), Commit: commit, Blinding: blind})
	if err != nil {
		t.Fatal(err)
	}
	b := &types.Block{Header: hdr,
		Outputs: []types.Output{{Features: types.OutputFeaturesCoinbase, Commit: commit}},
		Kernels: []types.Kernel{{Features: types.KernelFeaturesCoinbase, LockHeight: h + types.CoinbaseLock, Excess: commit, ExcessSig: sig}}}
	if tx != nil {
		b.Inputs = append(b.Inputs, tx.Inputs...)
		b.Outputs = append(b.Outputs, tx.Outputs...)
		b.Kernels = append(b.Kernels, tx.Kernels...)
	}
	types.SetBlockRoots(b)
	for n := uint64(0); n < 256; n++ {
		b.Header.Nonce = n
		if pow.Verify(&b.Header) {
			return b
		}
	}
	t.Fatal("no nonce at difficulty 1")
	return nil
}

// spendCoinbase builds a valid zero-fee transaction spending the coinbase of
// block in (whose blinding is inBlind) into a fresh output. Every call yields a
// different output, so two calls give two conflicting spends of one input.
func spendCoinbase(t *testing.T, in *types.Block, inBlind [32]byte) *types.Transaction {
	t.Helper()
	out, err := wallet.NewPlainOutput(types.BlockReward(in.Header.Height))
	if err != nil {
		t.Fatal(err)
	}
	var excess, negative secp.ModNScalar
	outBlind := [32]byte(out.Blinding)
	excess.SetBytes(&outBlind)
	negative.SetBytes(&inBlind)
	negative.Negate()
	excess.Add(&negative)
	secret := excess.Bytes()
	ex, err := v2crypto.PedersenCommit(0, secret[:])
	if err != nil {
		t.Fatal(err)
	}
	k := types.Kernel{Features: types.KernelFeaturesPlain, Excess: ex}
	k.ExcessSig, err = v2crypto.SchnorrSign(secret[:], types.KernelSigningMessage(types.NetworkMagicTestnet, &k))
	if err != nil {
		t.Fatal(err)
	}
	return &types.Transaction{
		Inputs:  []types.Input{{Features: types.OutputFeaturesCoinbase, Commit: in.Outputs[0].Commit}},
		Outputs: []types.Output{out.Output},
		Kernels: []types.Kernel{k},
	}
}

func TestAttachedPoolFollowsRealChain(t *testing.T) {
	if testing.Short() {
		t.Skip("mines a mature coinbase and a reorg")
	}
	g := attachGenesis()
	c := chain.NewMemory()
	if err := c.LoadOrInit(filepath.Join(t.TempDir(), "chain"), g); err != nil {
		t.Fatal(err)
	}
	pool := NewValidated(0, c.ValidateTransaction)
	att := Attach(c, pool)
	defer att.Stop()

	// Mature a coinbase: blocks 1..CoinbaseLock on branch A (salt 0).
	parent := types.HeaderID(&g.Header)
	var first *types.Block
	var firstBlind [32]byte
	for h := uint64(1); h <= types.CoinbaseLock; h++ {
		b := attachBlock(t, parent, h, 0, nil)
		if h == 1 {
			first, firstBlind = b, cbBlind(parent, h, 0)
		}
		if err := c.AddBlock(b); err != nil {
			t.Fatalf("block %d: %v", h, err)
		}
		parent = types.HeaderID(&b.Header)
	}
	forkPoint := parent // block CoinbaseLock

	tx1 := spendCoinbase(t, first, firstBlind)
	id1 := TxID(tx1)
	if _, err := pool.Add(tx1); err != nil {
		t.Fatalf("admission of a spend of a mature coinbase: %v", err)
	}

	// 1. A block confirms tx1: it leaves the pool.
	a1 := attachBlock(t, forkPoint, types.CoinbaseLock+1, 0, tx1)
	if err := c.AddBlock(a1); err != nil {
		t.Fatalf("block carrying tx1: %v", err)
	}
	att.Wait()
	if pool.Len() != 0 {
		t.Fatalf("confirmed transaction still in the pool (%d entries)", pool.Len())
	}

	// 2. A longer branch without tx1 reorgs a1 out: tx1 returns to the pool.
	b1 := attachBlock(t, forkPoint, types.CoinbaseLock+1, 1, nil)
	b2 := attachBlock(t, types.HeaderID(&b1.Header), types.CoinbaseLock+2, 1, nil)
	if err := c.ReorgTo([]*types.Block{b1, b2}); err != nil {
		t.Fatalf("reorg: %v", err)
	}
	att.Wait()
	snap := pool.Snapshot()
	if len(snap) != 1 || TxID(snap[0]) != id1 {
		t.Fatalf("reorged-out transaction did not return to the pool (%d entries)", len(snap))
	}

	// 3. A conflicting spend of the same input is mined: tx1 is dropped and not
	// re-admitted.
	tx2 := spendCoinbase(t, first, firstBlind)
	if TxID(tx2) == id1 {
		t.Fatal("conflicting transactions are identical")
	}
	b3 := attachBlock(t, types.HeaderID(&b2.Header), types.CoinbaseLock+3, 1, tx2)
	if err := c.AddBlock(b3); err != nil {
		t.Fatalf("block carrying the conflicting spend: %v", err)
	}
	att.Wait()
	if pool.Len() != 0 {
		t.Fatalf("conflicting transaction survived (%d entries)", pool.Len())
	}
}

// The size estimate the wallet uses for its default fee must equal the size the
// pool charges on, or the "default fee clears the relay floor" promise rots.
func TestEstimatedSizeMatchesPoolAccounting(t *testing.T) {
	proof := make([]byte, types.MaxRangeProofBytes)
	for _, shape := range [][2]int{{1, 1}, {1, 2}, {4, 2}} {
		tx := &types.Transaction{}
		for i := 0; i < shape[0]; i++ {
			tx.Inputs = append(tx.Inputs, types.Input{})
		}
		for i := 0; i < shape[1]; i++ {
			tx.Outputs = append(tx.Outputs, types.Output{RangeProof: proof})
		}
		tx.Kernels = []types.Kernel{{ExcessSig: make([]byte, 65)}}
		if got, want := types.EstimateTxSize(shape[0], shape[1], 1, len(proof), 65), transactionSize(tx); got != want {
			t.Errorf("shape %v: estimate %d, pool accounts %d", shape, got, want)
		}
	}
	// The wallet's default fee clears the real relay floor for its largest payment.
	size := types.EstimateTxSize(types.MaxBlockInputs, 2, 1, types.MaxRangeProofBytes, 65)
	if wallet.DefaultFee() < MinFee(DefaultPolicy.MinFeeRate, size) {
		t.Fatalf("DefaultFee %d is below the relay minimum %d", wallet.DefaultFee(), MinFee(DefaultPolicy.MinFeeRate, size))
	}
}
