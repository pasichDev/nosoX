package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"reflect"
	"strings"
	"testing"

	v2crypto "github.com/pasichDev/nosoX/v2/crypto"
	"github.com/pasichDev/nosoX/v2/types"
	"github.com/pasichDev/nosoX/v2/wallet"
)

// With the dev fund gone the miner is paid reward + fees and nothing else, and
// the unspent set always sums to the cumulative subsidy: a fee is destroyed by
// the spend (outputs + fee = inputs) and re-created exactly once in the coinbase.

func fixtureCoinbaseBlind(b *types.Block) [32]byte {
	seed := append([]byte("chain test coinbase"), b.Header.PrevHash[:]...)
	seed = binary.BigEndian.AppendUint64(seed, b.Header.Height)
	return sha256.Sum256(seed)
}

// feeSpendParts builds one input/output/kernel spend of a value-known source
// (value, blinding) that pays fee. The returned blinding belongs to the output.
func feeSpendParts(t *testing.T, in types.Input, value int64, inBlind [32]byte, fee int64) (types.Output, [32]byte, types.Kernel) {
	t.Helper()
	out, err := wallet.NewPlainOutput(value - fee)
	if err != nil {
		t.Fatal(err)
	}
	x := new(big.Int).Sub(new(big.Int).SetBytes(out.Blinding[:]), new(big.Int).SetBytes(inBlind[:]))
	x.Mod(x, v2crypto.Curve().Params().N)
	scalar := x.FillBytes(make([]byte, 32))
	excess, err := v2crypto.PublicFromScalar(scalar)
	if err != nil {
		t.Fatal(err)
	}
	k := types.Kernel{Fee: uint64(fee), Excess: excess}
	k.ExcessSig, err = v2crypto.SchnorrSign(scalar, types.KernelSigningMessage(0, &k))
	if err != nil {
		t.Fatal(err)
	}
	return out.Output, out.Blinding, k
}

// feeBlock spends the coinbase of source on top of the chain tip, paying fee.
// claim is added to the coinbase amount; noCoinbase omits the coinbase.
func feeBlock(t *testing.T, parent *types.Block, source *types.Block, fee, claim int64, noCoinbase bool) (*types.Block, [32]byte) {
	t.Helper()
	in := types.Input{Features: types.OutputFeaturesCoinbase, Commit: source.Outputs[0].Commit}
	out, blind, k := feeSpendParts(t, in, types.BlockReward(source.Header.Height), fixtureCoinbaseBlind(source), fee)
	b := &types.Block{Header: easyHeader(types.HeaderID(&parent.Header), parent.Header.Height+1), Inputs: []types.Input{in}, Outputs: []types.Output{out}, Kernels: []types.Kernel{k}}
	if noCoinbase {
		types.SetBlockRoots(b)
	} else {
		sealFixtureClaim(b, claim)
	}
	return b, blind
}

// assertSupply checks, on the real UTXO set, that the unspent commitments sum
// to exactly the cumulative block reward: Σ unspent − Σ rewards·H = (Σ blinds)·G.
func assertSupply(t *testing.T, c *Chain, plainBlinds map[types.Commitment][32]byte) {
	t.Helper()
	tip, _ := c.Tip()
	var commits [][33]byte
	var blinds [][32]byte
	var rewards int64
	for h := uint64(1); h <= tip.Height; h++ {
		b, _ := c.BlockByHeight(h)
		rewards += types.BlockReward(h)
		for _, o := range b.Outputs {
			if !c.store.HasUTXO(o.Commit) {
				continue
			}
			var blind [32]byte
			if o.Features == types.OutputFeaturesCoinbase {
				blind = fixtureCoinbaseBlind(b)
			} else {
				var ok bool
				if blind, ok = plainBlinds[o.Commit]; !ok {
					t.Fatalf("unspent plain output with unknown blinding at height %d", h)
				}
			}
			commits = append(commits, o.Commit)
			blinds = append(blinds, blind)
		}
	}
	assertUnspentSum(t, commits, blinds, rewards)
}

// assertUnspentSum is the core of assertSupply for chains that cannot serve
// BlockByHeight (the synthetic schedule store): the commitments, whose
// blindings are known, must sum to exactly total·H plus (Σ blinds)·G.
func assertUnspentSum(t *testing.T, commits [][33]byte, blinds [][32]byte, total int64) {
	t.Helper()
	sum := new(big.Int)
	for _, b := range blinds {
		sum.Add(sum, new(big.Int).SetBytes(b[:]))
	}
	sum.Mod(sum, v2crypto.Curve().Params().N)
	g, err := v2crypto.PedersenCommit(0, sum.FillBytes(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := v2crypto.PedersenSumZero(commits, [][33]byte{g}, total)
	if err != nil || !ok {
		t.Fatalf("unspent set does not sum to %d: %v", total, err)
	}
}

func TestCoinbaseMustClaimExactlyRewardPlusFees(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		g := easyGenesisBlock(t)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		blocks := appendBlocks(t, c, 1, 61)
		parent := blocks[len(blocks)-1]
		const fee = 100
		before := snapshot(t, c)
		for _, claim := range []int64{1, -1, fee, -fee} {
			bad, _ := feeBlock(t, parent, blocks[0], fee, claim, false)
			if err := c.AddBlock(bad); err == nil {
				t.Fatalf("coinbase claiming reward+F%+d accepted", claim)
			}
		}
		bad, _ := feeBlock(t, parent, blocks[0], fee, 0, true)
		if err := c.AddBlock(bad); err == nil {
			t.Fatal("fee-paying block without a coinbase accepted")
		}
		if !reflect.DeepEqual(before, snapshot(t, c)) {
			t.Fatal("rejections changed state")
		}
		good, _ := feeBlock(t, parent, blocks[0], fee, 0, false)
		if err := c.AddBlock(good); err != nil {
			t.Fatalf("exact reward+F rejected: %v", err)
		}
		// A fee-free block must still claim exactly the reward.
		tip, _ := c.Tip()
		over := &types.Block{Header: easyHeader(types.HeaderID(&tip), tip.Height+1)}
		sealFixtureClaim(over, 1)
		if err := c.AddBlock(over); err == nil {
			t.Fatal("reward+1 accepted")
		}
	})
}

func TestOutputFeatureTwoIsRejected(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		g := easyGenesisBlock(t)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		tip, _ := c.Tip()
		b := &types.Block{Header: easyHeader(types.HeaderID(&tip), 1)}
		sealFixture(b)
		extra := b.Outputs[0]
		extra.Features = 2
		b.Outputs = append(b.Outputs, extra)
		types.SetBlockRoots(b)
		if err := c.AddBlock(b); err == nil {
			t.Fatal("output feature 2 accepted")
		}
		only := cloneBlock(b)
		only.Outputs = []types.Output{extra}
		only.Kernels = nil
		types.SetBlockRoots(only)
		if err := c.AddBlock(only); err == nil {
			t.Fatal("block with only a feature-2 output accepted")
		}
	})
}

func TestSupplyEqualsRewardsWithFeesAndReorg(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		g := easyGenesisBlock(t)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		blocks := appendBlocks(t, c, 1, 61)
		plain := map[types.Commitment][32]byte{}
		parent := blocks[len(blocks)-1]
		// Two fee-paying spends on the main branch.
		var branch []*types.Block
		for i, fee := range []int64{100, 777} {
			b, blind := feeBlock(t, parent, blocks[i], fee, 0, false)
			if err := c.AddBlock(b); err != nil {
				t.Fatalf("fee block %d: %v", i, err)
			}
			plain[b.Outputs[0].Commit] = blind
			branch = append(branch, b)
			parent = b
		}
		assertSupply(t, c, plain)

		// Heavier fork from the same ancestor, with a different fee on the first
		// source and a fee-free tail. The orphaned fees must not linger.
		anchor := blocks[len(blocks)-1]
		f1, blind := feeBlock(t, anchor, blocks[0], 5, 0, false)
		plain2 := map[types.Commitment][32]byte{f1.Outputs[0].Commit: blind}
		f2 := mineEasy(types.HeaderID(&f1.Header), anchor.Header.Height+2)
		f3 := mineEasy(types.HeaderID(&f2.Header), anchor.Header.Height+3)
		if err := c.ReorgTo([]*types.Block{f1, f2, f3}); err != nil {
			t.Fatalf("reorg: %v", err)
		}
		assertSupply(t, c, plain2)
		for _, b := range branch {
			if c.store.HasUTXO(b.Outputs[0].Commit) {
				t.Fatal("orphaned fee spend output retained")
			}
		}
	})
}

// Post-emission blocks reach heights no test can mine; the schedule store lets
// the full AddBlock validator run at height 2,310,001.
func TestPostEmissionCoinbaseIsFeesOnly(t *testing.T) {
	height := types.BlockHalvingInterval*(types.HalvingSteps+1) + 1
	if types.BlockReward(height) != 0 {
		t.Fatal("emission has not ended")
	}
	const value, fee = int64(1_000_000), int64(300)
	build := func(t *testing.T, claim int64, withCoinbase, withTx bool) (*Chain, *scheduleStore, *types.Block) {
		c, s, b := scheduledCandidate(t, height, 0, false)
		if withTx {
			var inBlind [32]byte
			inBlind[31] = 9
			commit, err := v2crypto.PedersenCommit(value, inBlind[:])
			if err != nil {
				t.Fatal(err)
			}
			s.Store.(*memStore).utxo[commit] = types.Output{Features: types.OutputFeaturesPlain, Commit: commit}
			in := types.Input{Features: types.OutputFeaturesPlain, Commit: commit}
			out, _, k := feeSpendParts(t, in, value, inBlind, fee)
			b.Inputs, b.Outputs, b.Kernels = []types.Input{in}, []types.Output{out}, []types.Kernel{k}
		}
		if withCoinbase {
			amount, err := CoinbaseAmount(b)
			if err != nil {
				t.Fatal(err)
			}
			amount += claim
			blind := sha256.Sum256([]byte("post emission"))
			commit, err := v2crypto.PedersenCommit(amount, blind[:])
			if err != nil {
				t.Fatal(err)
			}
			sig, err := wallet.SignCoinbase(b.Header.NetworkMagic, wallet.CoinbaseRecord{Height: height, Amount: amount, Blinding: blind, Commit: commit})
			if err != nil {
				t.Fatal(err)
			}
			b.Outputs = append(b.Outputs, types.Output{Features: types.OutputFeaturesCoinbase, Commit: commit})
			b.Kernels = append(b.Kernels, types.Kernel{Features: types.KernelFeaturesCoinbase, Excess: commit, ExcessSig: sig, LockHeight: height + types.CoinbaseLock})
		}
		types.SetBlockRoots(b)
		return c, s, b
	}
	t.Run("fees and a coinbase of exactly F accepted", func(t *testing.T) {
		c, s, b := build(t, 0, true, true)
		if err := c.AddBlock(b); err != nil {
			t.Fatalf("rejected: %v", err)
		}
		if s.writes != 1 {
			t.Fatal("not written")
		}
	})
	for _, claim := range []int64{1, -1} {
		t.Run("fees and a coinbase of F"+map[int64]string{1: "+1", -1: "-1"}[claim]+" rejected", func(t *testing.T) {
			c, s, b := build(t, claim, true, true)
			if err := c.AddBlock(b); err == nil || s.writes != 0 {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	t.Run("fees without a coinbase rejected", func(t *testing.T) {
		c, s, b := build(t, 0, false, true)
		err := c.AddBlock(b)
		if err == nil || !strings.Contains(err.Error(), "coinbase") || s.writes != 0 {
			t.Fatalf("accepted or wrong error: %v", err)
		}
	})
	t.Run("no fees with a coinbase rejected", func(t *testing.T) {
		for _, amount := range []int64{0, 1} {
			c, s, b := scheduledCandidate(t, height, amount, true)
			if err := c.AddBlock(b); err == nil || s.writes != 0 {
				t.Fatalf("zero-payout block with coinbase of %d accepted: %v", amount, err)
			}
		}
	})
	t.Run("no fees and no coinbase accepted", func(t *testing.T) {
		c, s, b := scheduledCandidate(t, height, 0, false)
		if err := c.AddBlock(b); err != nil || s.writes != 1 {
			t.Fatalf("empty post-emission block rejected: %v", err)
		}
	})
}

func TestCoinbaseAmountOverflow(t *testing.T) {
	b := &types.Block{Header: types.BlockHeader{Height: 1}, Kernels: []types.Kernel{{Fee: 1<<63 - 1}}}
	if _, err := CoinbaseAmount(b); err == nil {
		t.Fatal("reward + MaxInt64 fees did not overflow")
	}
	b.Kernels = []types.Kernel{{Fee: 1 << 63}}
	if _, err := CoinbaseAmount(b); err == nil {
		t.Fatal("fee sum above MaxInt64 accepted")
	}
}
