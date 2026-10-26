package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
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
		var feeCommits []types.Commitment
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
			id := types.KernelID(&k)
			k.ExcessSig, err = v2crypto.SchnorrSign(scalar, id[:])
			if err != nil {
				t.Fatal(err)
			}
			tip, _ := c.Tip()
			b := &types.Block{Header: easyHeader(types.HeaderID(&tip), tip.Height+1), Inputs: []types.Input{{Features: types.OutputFeaturesCoinbase, Commit: source.Outputs[0].Commit}}, Outputs: []types.Output{out.Output}, Kernels: []types.Kernel{k}}
			dev, err := ExpectedDevFundCommit(&b.Header, fee)
			if err != nil {
				t.Fatal(err)
			}
			b.Outputs = append(b.Outputs, types.Output{Features: types.OutputFeaturesDevFund, Commit: dev})
			sealFixture(b)
			// Even a fully re-rooted body cannot redirect or inflate the fee output.
			for _, mutate := range []func(*types.BlockHeader){func(h *types.BlockHeader) { h.Height++ }, func(h *types.BlockHeader) { h.NetworkMagic ^= 1 }, func(h *types.BlockHeader) { h.PrevHash[0] ^= 1 }} {
				wrongContext := b.Header
				mutate(&wrongContext)
				badDev, err := ExpectedDevFundCommit(&wrongContext, fee)
				if err != nil {
					t.Fatal(err)
				}
				bad := *b
				bad.Outputs = append([]types.Output(nil), b.Outputs...)
				bad.Outputs[1].Commit = badDev
				types.SetBlockRoots(&bad)
				if err := c.AddBlock(&bad); !errors.Is(err, ErrDevFund) {
					t.Fatalf("wrong-context dev output: %v", err)
				}
			}
			inflatedDev, err := ExpectedDevFundCommit(&b.Header, fee+1)
			if err != nil {
				t.Fatal(err)
			}
			bad := *b
			bad.Outputs = append([]types.Output(nil), b.Outputs...)
			bad.Outputs[1].Commit = inflatedDev
			types.SetBlockRoots(&bad)
			if err := c.AddBlock(&bad); !errors.Is(err, ErrDevFund) {
				t.Fatalf("inflated dev output: %v", err)
			}
			if err := c.AddBlock(b); err != nil {
				t.Fatalf("fee block %d: %v", i+1, err)
			}
			if i > 0 && previous == dev {
				t.Fatal("equal fees reused historical commitment")
			}
			previous = dev
			feeCommits = append(feeCommits, dev)
		}
		for _, commit := range feeCommits {
			if _, ok := c.store.UTXOByCommit(commit); !ok || !c.store.HasOutput(commit) {
				t.Fatal("fee commitment missing from state")
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
		// that the orphan's historical commitments can no longer shadow the fork.
		anchor := blocks[len(blocks)-1]
		a := mineEasy(types.HeaderID(&anchor.Header), 62)
		b := mineEasy(types.HeaderID(&a.Header), 63)
		d := mineEasy(types.HeaderID(&b.Header), 64)
		if err := restored.ReorgTo([]*types.Block{a, b, d}); err != nil {
			t.Fatal(err)
		}
		for _, commit := range feeCommits {
			if _, ok := restored.store.UTXOByCommit(commit); ok || restored.store.HasOutput(commit) {
				t.Fatal("orphan fee output retained")
			}
		}
	})
}

// The production recipient secret is deliberately unavailable. This verifies
// the same group equation and an actual signed/proven spend with a separate
// public test recipient; it does not insert that key into consensus.
func TestSP1TweakedRecipientSpendability(t *testing.T) {
	h := types.BlockHeader{Version: types.BlockVersion, NetworkMagic: types.NetworkMagicTestnet, Height: 62, PrevHash: types.Hash{9}}
	const amount int64 = 100
	tweak, err := DevFundBlindingTweak(&h, uint64(amount))
	if err != nil {
		t.Fatal(err)
	}
	d := [32]byte{31: 7}
	p, err := v2crypto.PublicFromScalar(d[:])
	if err != nil {
		t.Fatal(err)
	}
	publicPart, err := v2crypto.PedersenCommit(amount, tweak[:])
	if err != nil {
		t.Fatal(err)
	}
	c, err := v2crypto.PointAdd(publicPart, p)
	if err != nil {
		t.Fatal(err)
	}
	x := new(big.Int).Add(new(big.Int).SetBytes(d[:]), new(big.Int).SetBytes(tweak[:]))
	x.Mod(x, v2crypto.Curve().Params().N)
	blind := x.FillBytes(make([]byte, 32))
	direct, err := v2crypto.PedersenCommit(amount, blind)
	if err != nil || direct != c {
		t.Fatalf("public/private tweak mismatch: %v", err)
	}
	// Independently evaluate Q=P+tG with the pinned decred Jacobian API.
	var ts secp.ModNScalar
	ts.SetByteSlice(tweak[:])
	var tG, pj, q secp.JacobianPoint
	secp.ScalarBaseMultNonConst(&ts, &tG)
	parsed, err := secp.ParsePubKey(p[:])
	if err != nil {
		t.Fatal(err)
	}
	parsed.AsJacobian(&pj)
	secp.AddNonConst(&pj, &tG, &q)
	q.ToAffine()
	qBytes := secp.NewPublicKey(&q.X, &q.Y).SerializeCompressed()
	feeH, err := v2crypto.PedersenCommit(amount, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := v2crypto.PointSubtract(c, feeH)
	if err != nil || !bytes.Equal(recovered[:], qBytes) {
		t.Fatalf("independent tweak equation: %v", err)
	}
	out, err := wallet.NewPlainOutput(amount)
	if err != nil {
		t.Fatal(err)
	}
	spendX := new(big.Int).Sub(new(big.Int).SetBytes(out.Blinding[:]), x)
	spendX.Mod(spendX, v2crypto.Curve().Params().N)
	scalar := spendX.FillBytes(make([]byte, 32))
	excess, err := v2crypto.PublicFromScalar(scalar)
	if err != nil {
		t.Fatal(err)
	}
	k := types.Kernel{Excess: excess}
	id := types.KernelID(&k)
	k.ExcessSig, err = v2crypto.SchnorrSign(scalar, id[:])
	if err != nil {
		t.Fatal(err)
	}
	if !v2crypto.SchnorrVerify(excess, id[:], k.ExcessSig) {
		t.Fatal("tweaked output spend signature invalid")
	}
	if !v2crypto.VerifyRange(out.Output.Commit, out.Output.RangeProof) {
		t.Fatal("spend output proof invalid")
	}
	ok, err := v2crypto.PedersenSumZero([][33]byte{out.Output.Commit}, [][33]byte{c, excess}, 0)
	if err != nil || !ok {
		t.Fatalf("tweaked spend conservation: %v", err)
	}
	// Inflation remains impossible under the very same equation.
	inflated, err := v2crypto.PedersenCommit(amount+1, out.Blinding[:])
	if err != nil {
		t.Fatal(err)
	}
	ok, err = v2crypto.PedersenSumZero([][33]byte{inflated}, [][33]byte{c, excess}, 0)
	if err != nil || ok {
		t.Fatalf("inflation balance accepted: %v", err)
	}
	// The production constant obeys the same equation, with no secret access.
	prod, err := ExpectedDevFundCommit(&h, uint64(amount))
	if err != nil {
		t.Fatal(err)
	}
	want, err := v2crypto.PointAdd(publicPart, types.DevFundPoint())
	if err != nil || prod != want {
		t.Fatalf("production destination changed: %v", err)
	}
}
