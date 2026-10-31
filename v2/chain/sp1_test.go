package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"reflect"
	"testing"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

// This exercises the complete acceptance path: historical output uniqueness
// must coexist with two genuine, equal-fee, signed and range-proven spends.
func TestSP1ConsecutiveEqualFees(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		g := easyGenesisBlock(t)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		blocks := appendBlocks(t, c, 1, 61)
		var previous types.Commitment
		var coinbaseCommits []types.Commitment
		for i := 0; i < 2; i++ {
			source := blocks[i]
			seed := append([]byte("chain test coinbase"), source.Header.PrevHash[:]...)
			seed = binary.BigEndian.AppendUint64(seed, source.Header.Height)
			blind := sha256.Sum256(seed)
			const fee = 100
			amount := types.BlockReward(source.Header.Height) - fee
			out, err := wallet.NewPlainOutput(amount)
			if err != nil {
				t.Fatal(err)
			}
			x := new(big.Int).Sub(new(big.Int).SetBytes(out.Blinding[:]), new(big.Int).SetBytes(blind[:]))
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
			b := &types.Block{Header: easyHeader(types.HeaderID(&tip), tip.Height+1), Inputs: []types.Input{{Features: types.OutputFeaturesCoinbase, Commit: source.Outputs[0].Commit}}, Outputs: []types.Output{out.Output}, Kernels: []types.Kernel{k}}
			sealFixture(b)
			// A fully re-rooted body cannot over- or under-claim the fees.
			for _, delta := range []int64{1, -1} {
				bad := cloneBlock(b)
				bad.Outputs = bad.Outputs[:1]
				bad.Kernels = bad.Kernels[:1]
				sealFixtureClaim(bad, delta)
				if err := c.AddBlock(bad); err == nil {
					t.Fatalf("coinbase claiming fees%+d accepted", delta)
				}
			}
			if err := c.AddBlock(b); err != nil {
				t.Fatalf("fee block %d: %v", i+1, err)
			}
			cb := b.Outputs[len(b.Outputs)-1].Commit
			if i > 0 && previous == cb {
				t.Fatal("equal fees reused a historical coinbase commitment")
			}
			previous = cb
			coinbaseCommits = append(coinbaseCommits, cb)
		}
		for _, commit := range coinbaseCommits {
			if _, ok := c.store.UTXOByCommit(commit); !ok || !c.store.HasOutput(commit) {
				t.Fatal("coinbase commitment missing from state")
			}
		}
		before := snapshot(t, c)
		if err := c.Save(); err != nil {
			t.Fatal(err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		var restored *Chain
		if _, isBadger := c.store.(*BadgerStore); isBadger {
			var err error
			restored, err = NewBadger(dir)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			restored = NewMemory()
		}
		defer restored.Close()
		if err := restored.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, snapshot(t, restored)) {
			t.Fatal("fee state changed on restart")
		}
		// Replace both fee blocks with a heavier, valid no-fee suffix, then check
		// that the orphaned coinbase commitments can no longer shadow the fork.
		anchor := blocks[len(blocks)-1]
		a := mineEasy(types.HeaderID(&anchor.Header), 62)
		b := mineEasy(types.HeaderID(&a.Header), 63)
		d := mineEasy(types.HeaderID(&b.Header), 64)
		if err := restored.ReorgTo([]*types.Block{a, b, d}); err != nil {
			t.Fatal(err)
		}
		for _, commit := range coinbaseCommits {
			if _, ok := restored.store.UTXOByCommit(commit); ok || restored.store.HasOutput(commit) {
				t.Fatal("orphaned coinbase output retained")
			}
		}
	})
}
