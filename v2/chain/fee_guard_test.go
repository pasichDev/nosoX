package chain

import (
	"math/big"
	"reflect"
	"strings"
	"testing"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

// Tests for the rules that stand between a block and unbounded issuance. Each
// one is the only test that reaches its rule: the rejection must come from that
// rule, so every case asserts the exact error and that a block that died
// earlier (at a signature check, say) does not count.

const emissionEnd = types.BlockHalvingInterval * (types.HalvingSteps + 1)

// coinbaseParts commits amount under a fixed blinding and signs it as a valid
// coinbase kernel for block b.
func coinbaseParts(t *testing.T, b *types.Block, amount int64, seed byte) (types.Commitment, []byte) {
	t.Helper()
	var blind [32]byte
	blind[31] = seed
	commit, err := v2crypto.PedersenCommit(amount, blind[:])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wallet.SignCoinbase(b.Header.NetworkMagic, wallet.CoinbaseRecord{Height: b.Header.Height, Amount: amount, Blinding: blind, Commit: commit})
	if err != nil {
		t.Fatal(err)
	}
	return commit, sig
}

// wantReject requires an error that contains want and is not a signature
// failure, which would mean the block never reached the rule under test.
func wantReject(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("block accepted, want %q", want)
	}
	if !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "authorization") {
		t.Fatalf("rejected by the wrong rule: %v, want %q", err, want)
	}
}

// validation.go: cb.Commit != cbK.Excess. The output is not covered by any
// signature, so without the binding it could hold any amount.
func TestCoinbaseOutputMustCommitToKernelExcess(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		g := easyGenesisBlock(t)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, c)
		b := &types.Block{Header: easyHeader(types.HeaderID(&g.Header), 1)}
		// The kernel is validly signed for exactly the reward ...
		excess, sig := coinbaseParts(t, b, types.BlockReward(1), 42)
		// ... but the output commits to 2^60.
		var blind [32]byte
		blind[31] = 43
		huge, err := v2crypto.PedersenCommit(1<<60, blind[:])
		if err != nil {
			t.Fatal(err)
		}
		b.Outputs = []types.Output{{Features: types.OutputFeaturesCoinbase, Commit: huge}}
		b.Kernels = []types.Kernel{{Features: types.KernelFeaturesCoinbase, LockHeight: 1 + types.CoinbaseLock, Excess: excess, ExcessSig: sig}}
		types.SetBlockRoots(b)
		wantReject(t, c.AddBlock(b), "chain: invalid or missing coinbase")
		if !reflect.DeepEqual(before, snapshot(t, c)) {
			t.Fatal("rejection changed state")
		}
	})
}

// validation.go: a coinbase is forbidden when reward + fees == 0. An output
// with no kernel carries no signature at all and balance skips coinbase
// outputs, so only this rule stops it.
func TestCoinbaseForbiddenWhenBlockPaysNothing(t *testing.T) {
	c, s, b := scheduledCandidate(t, emissionEnd, 0, false)
	if types.BlockReward(emissionEnd) != 0 {
		t.Fatal("emission has not ended")
	}
	commit, _ := coinbaseParts(t, b, 1_000_000, 42)
	b.Outputs = []types.Output{{Features: types.OutputFeaturesCoinbase, Commit: commit}}
	types.SetBlockRoots(b)
	wantReject(t, c.AddBlock(b), "chain: coinbase in a block that pays nothing")
	if s.writes != 0 {
		t.Fatal("rejected block was written")
	}
}

// validation.go: a coinbase kernel must have Fee 0. The signature does not bind
// the fee, so a kernel that carries one is otherwise a validly signed block.
func TestCoinbaseKernelFeeIsRejected(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		g := easyGenesisBlock(t)
		if err := c.LoadOrInit(dir, g); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, c)
		b := &types.Block{Header: easyHeader(types.HeaderID(&g.Header), 1)}
		amount, err := CoinbaseAmount(&types.Block{Header: b.Header, Kernels: []types.Kernel{{Features: types.KernelFeaturesCoinbase, Fee: 1000}}})
		if err != nil || amount != types.BlockReward(1) {
			t.Fatalf("a coinbase kernel's fee changed the coinbase amount: %d, %v", amount, err)
		}
		commit, sig := coinbaseParts(t, b, amount, 42)
		b.Outputs = []types.Output{{Features: types.OutputFeaturesCoinbase, Commit: commit}}
		b.Kernels = []types.Kernel{{Features: types.KernelFeaturesCoinbase, Fee: 1000, LockHeight: 1 + types.CoinbaseLock, Excess: commit, ExcessSig: sig}}
		types.SetBlockRoots(b)
		wantReject(t, c.AddBlock(b), "chain: invalid coinbase kernel")
		if !reflect.DeepEqual(before, snapshot(t, c)) {
			t.Fatal("rejection changed state")
		}
	})
}

// The balance equation and the coinbase amount must count the same fees. They
// used to differ: CoinbaseAmount summed every kernel, validateBalance only the
// plain ones, so a coinbase kernel's Fee was paid out but never destroyed.
func TestFeeTotalsIgnoreCoinbaseKernels(t *testing.T) {
	b := &types.Block{Header: types.BlockHeader{Height: 1}, Kernels: []types.Kernel{
		{Features: types.KernelFeaturesPlain, Fee: 5},
		{Features: types.KernelFeaturesCoinbase, Fee: 1000},
		{Features: types.KernelFeaturesPlain, Fee: 7},
	}}
	fees, err := PlainKernelFees(b)
	if err != nil || fees != 12 {
		t.Fatalf("PlainKernelFees = %d, %v, want 12", fees, err)
	}
	amount, err := CoinbaseAmount(b)
	if err != nil || amount != types.BlockReward(1)+12 {
		t.Fatalf("CoinbaseAmount = %d, %v, want reward+12", amount, err)
	}
	b.Kernels = append(b.Kernels, types.Kernel{Features: types.KernelFeaturesCoinbase, Fee: 1 << 63})
	if _, err := CoinbaseAmount(b); err != nil {
		t.Fatalf("a coinbase kernel's fee overflowed the plain total: %v", err)
	}
	b.Kernels = append(b.Kernels, types.Kernel{Features: types.KernelFeaturesPlain, Fee: 1<<63 - 1})
	if _, err := PlainKernelFees(b); err == nil {
		t.Fatal("plain fees above MaxInt64 accepted")
	}
}

// validation.go: coinbase maturity at the exact boundary, for a coinbase that
// carries fees, on both stores. A coinbase is spendable CoinbaseLock blocks
// after its own, not one earlier. The supply stays exact after the spend.
func TestFeeCarryingCoinbaseMaturityBoundary(t *testing.T) {
	backendChains(t, func(t *testing.T, c *Chain, dir string) {
		if err := c.LoadOrInit(dir, easyGenesisBlock(t)); err != nil {
			t.Fatal(err)
		}
		blocks := appendBlocks(t, c, 1, types.CoinbaseLock+1)
		const fee, fee2 = int64(100), int64(7)
		fb, blind := feeBlock(t, blocks[len(blocks)-1], blocks[0], fee, 0, false)
		if err := c.AddBlock(fb); err != nil {
			t.Fatal(err)
		}
		plain := map[types.Commitment][32]byte{fb.Outputs[0].Commit: blind}
		assertSupply(t, c, plain)
		created := fb.Header.Height
		if fb.Outputs[1].Features != types.OutputFeaturesCoinbase {
			t.Fatal("fixture: second output is not the coinbase")
		}
		spend := func(h uint64) (*types.Block, [32]byte) {
			tip, _ := c.Tip()
			in := types.Input{Features: types.OutputFeaturesCoinbase, Commit: fb.Outputs[1].Commit}
			out, bl, k := feeSpendParts(t, in, types.BlockReward(created)+fee, fixtureCoinbaseBlind(fb), fee2)
			b := &types.Block{Header: easyHeader(types.HeaderID(&tip), h), Inputs: []types.Input{in}, Outputs: []types.Output{out}, Kernels: []types.Kernel{k}}
			sealFixture(b)
			return b, bl
		}
		appendBlocks(t, c, created+1, created+types.CoinbaseLock-2)
		early, _ := spend(created + types.CoinbaseLock - 1)
		if err := c.AddBlock(early); err == nil || !strings.Contains(err.Error(), "immature coinbase input") {
			t.Fatalf("coinbase spent one block early: %v", err)
		}
		appendBlocks(t, c, created+types.CoinbaseLock-1, created+types.CoinbaseLock-1)
		ok, bl := spend(created + types.CoinbaseLock)
		if err := c.AddBlock(ok); err != nil {
			t.Fatalf("coinbase refused at exactly CoinbaseLock blocks: %v", err)
		}
		plain[ok.Outputs[0].Commit] = bl
		assertSupply(t, c, plain)
	})
}

// writeThroughStore is scheduleStore that also applies each block's UTXO,
// output and kernel changes, so consecutive blocks can be added at heights no
// test can mine. Block bodies are not kept; only the tip and the window the
// difficulty rule reads are synthetic.
type writeThroughStore struct{ *scheduleStore }

func (s *writeThroughStore) WriteBlock(b *types.Block) error {
	m := s.Store.(*memStore)
	for _, in := range b.Inputs {
		delete(m.utxo, in.Commit)
	}
	for _, o := range b.Outputs {
		m.utxo[o.Commit] = o
		m.outputSeen[o.Commit] = b.Header.Height
	}
	for i := range b.Kernels {
		m.kernelSeen[types.KernelID(&b.Kernels[i])] = true
	}
	return s.scheduleStore.WriteBlock(b)
}

// With the subsidy gone the miner is paid fees only. Run a fee-paying block,
// the 59 empty blocks (no coinbase allowed) and the spend of that fee-only
// coinbase, which carries fees again; the unspent set must equal the seeded
// supply all along.
func TestPostEmissionRunConservesSupply(t *testing.T) {
	const value, fee1, fee2 = int64(1_000_000), int64(1000), int64(300)
	first := emissionEnd + 1
	_, base, _ := scheduledCandidate(t, first, 0, false)
	store := &writeThroughStore{base}
	c := &Chain{store: store}
	var seedBlind [32]byte
	seedBlind[31] = 9
	seed, err := v2crypto.PedersenCommit(value, seedBlind[:])
	if err != nil {
		t.Fatal(err)
	}
	store.Store.(*memStore).utxo[seed] = types.Output{Features: types.OutputFeaturesPlain, Commit: seed}

	next := func(inputs []types.Input, outs []types.Output, kernels []types.Kernel) *types.Block {
		tip, _ := c.Tip()
		b := &types.Block{Header: types.BlockHeader{Version: types.BlockVersion, Height: tip.Height + 1, PrevHash: types.HeaderID(&tip), Timestamp: tip.Timestamp + types.TargetBlockTimeSeconds, Difficulty: 1}, Inputs: inputs, Outputs: outs, Kernels: kernels}
		sealFixture(b)
		return b
	}
	set := map[types.Commitment][32]byte{seed: seedBlind}
	check := func() {
		t.Helper()
		var commits [][33]byte
		var blinds [][32]byte
		for cm, bl := range set {
			if !store.HasUTXO(cm) {
				t.Fatal("tracked output missing from the UTXO set")
			}
			commits = append(commits, cm)
			blinds = append(blinds, bl)
		}
		if got := len(store.Store.(*memStore).utxo); got != len(set) {
			t.Fatalf("UTXO set has %d outputs, tracked %d", got, len(set))
		}
		assertUnspentSum(t, commits, blinds, value)
	}
	check()

	// Block 1: spend the seed, pay fee1; the coinbase holds exactly fee1.
	in := types.Input{Features: types.OutputFeaturesPlain, Commit: seed}
	out, outBlind, k := feeSpendParts(t, in, value, seedBlind, fee1)
	b1 := next([]types.Input{in}, []types.Output{out}, []types.Kernel{k})
	if len(b1.Outputs) != 2 || b1.Outputs[1].Features != types.OutputFeaturesCoinbase {
		t.Fatal("fixture: a post-emission fee block must carry a coinbase")
	}
	if err := c.AddBlock(b1); err != nil {
		t.Fatalf("fee-only coinbase block rejected: %v", err)
	}
	delete(set, seed)
	set[out.Commit] = outBlind
	set[b1.Outputs[1].Commit] = fixtureCoinbaseBlind(b1)
	check()

	// Empty blocks must carry no coinbase at all.
	for i := uint64(1); i < types.CoinbaseLock; i++ {
		b := next(nil, nil, nil)
		if len(b.Outputs) != 0 || len(b.Kernels) != 0 {
			t.Fatal("fixture: an empty post-emission block grew a coinbase")
		}
		if err := c.AddBlock(b); err != nil {
			t.Fatalf("empty block %d: %v", i, err)
		}
	}
	check()

	// Spend the fee-only coinbase once it is mature.
	cbIn := types.Input{Features: types.OutputFeaturesCoinbase, Commit: b1.Outputs[1].Commit}
	out2, out2Blind, k2 := feeSpendParts(t, cbIn, fee1, fixtureCoinbaseBlind(b1), fee2)
	b2 := next([]types.Input{cbIn}, []types.Output{out2}, []types.Kernel{k2})
	if err := c.AddBlock(b2); err != nil {
		t.Fatalf("spend of a fee-only coinbase rejected: %v", err)
	}
	delete(set, cbIn.Commit)
	set[out2.Commit] = out2Blind
	set[b2.Outputs[1].Commit] = fixtureCoinbaseBlind(b2)
	check()
}

// The coinbase reserve is decided by one function; its table is the contract
// for both the mempool admission check and the miner's transaction selection.
func TestCoinbaseReserveTable(t *testing.T) {
	const cbBytes = 128 + 128 + 65
	for _, tc := range []struct {
		name         string
		height       uint64
		fees         uint64
		outs, kernel int
	}{
		{"last subsidy block, no fees", emissionEnd - 1, 0, 1, 1},
		{"last subsidy block, fees", emissionEnd - 1, 5, 1, 1},
		{"first block without subsidy, no fees", emissionEnd, 0, 0, 0},
		{"first block without subsidy, fees", emissionEnd, 5, 1, 1},
		{"long after emission, fees", emissionEnd + 1_000_000, 1, 1, 1},
	} {
		o, k, n := CoinbaseReserve(tc.height, tc.fees)
		wantBytes := uint64(0)
		if tc.outs > 0 {
			wantBytes = cbBytes
		}
		if o != tc.outs || k != tc.kernel || n != wantBytes {
			t.Errorf("%s: reserve = %d, %d, %d; want %d, %d, %d", tc.name, o, k, n, tc.outs, tc.kernel, wantBytes)
		}
	}
	// The byte charge equals what BodyResourceBytes bills the real coinbase.
	cb := &types.Block{Outputs: []types.Output{{}}, Kernels: []types.Kernel{{ExcessSig: make([]byte, 65)}}}
	if n, err := BodyResourceBytes(cb); err != nil || n != cbBytes {
		t.Fatalf("coinbase body charge = %d, %v; reserve says %d", n, err, cbBytes)
	}
}

// multiOutputSpend builds a valid plain transaction from a seeded input to n
// equal outputs, paying fee.
func multiOutputSpend(t *testing.T, s *scheduleStore, n int, fee int64) *types.Transaction {
	t.Helper()
	const value = int64(1_000_000)
	var inBlind [32]byte
	inBlind[31] = 9
	commit, err := v2crypto.PedersenCommit(value, inBlind[:])
	if err != nil {
		t.Fatal(err)
	}
	s.Store.(*memStore).utxo[commit] = types.Output{Features: types.OutputFeaturesPlain, Commit: commit}
	tx := &types.Transaction{Inputs: []types.Input{{Features: types.OutputFeaturesPlain, Commit: commit}}}
	share := (value - fee) / int64(n)
	sum := new(big.Int).Neg(new(big.Int).SetBytes(inBlind[:]))
	for i := 0; i < n; i++ {
		v := share
		if i == n-1 {
			v = value - fee - share*int64(n-1)
		}
		out, err := wallet.NewPlainOutput(v)
		if err != nil {
			t.Fatal(err)
		}
		tx.Outputs = append(tx.Outputs, out.Output)
		sum.Add(sum, new(big.Int).SetBytes(out.Blinding[:]))
	}
	sum.Mod(sum, v2crypto.Curve().Params().N)
	scalar := sum.FillBytes(make([]byte, 32))
	excess, err := v2crypto.PublicFromScalar(scalar)
	if err != nil {
		t.Fatal(err)
	}
	k := types.Kernel{Fee: uint64(fee), Excess: excess}
	if k.ExcessSig, err = v2crypto.SchnorrSign(scalar, types.KernelSigningMessage(0, &k)); err != nil {
		t.Fatal(err)
	}
	tx.Kernels = []types.Kernel{k}
	return tx
}

// validation.go: checkTransactionCheap keeps room for the block's mandatory
// coinbase. The cases pin both sides of the post-emission branch: nothing is
// reserved while the block needs no coinbase, one slot once a fee makes it
// mandatory, and always while the subsidy lasts.
func TestTransactionLeavesRoomForCoinbase(t *testing.T) {
	const noRoom = "chain: transaction leaves no mandatory block capacity"
	for _, tc := range []struct {
		name    string
		height  uint64
		outputs int
		fee     int64
		reject  bool
	}{
		{"subsidy block, 4 outputs", emissionEnd - 1, 4, 0, true},
		{"subsidy block, 4 outputs with fee", emissionEnd - 1, 4, 100, true},
		{"subsidy block, 3 outputs", emissionEnd - 1, 3, 0, false},
		{"no subsidy, fee, 4 outputs", emissionEnd, 4, 100, true},
		{"no subsidy, fee, 3 outputs", emissionEnd, 3, 100, false},
		{"no subsidy, no fee, 4 outputs", emissionEnd, 4, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s, _ := scheduledCandidate(t, tc.height, 0, false)
			err := c.ValidateTransaction(multiOutputSpend(t, s, tc.outputs, tc.fee))
			if tc.reject {
				wantReject(t, err, noRoom)
			} else if err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

// resource_budget.go / validation.go: MaxBlockBodyBytes is a ceiling the item
// limits never reach. The largest charged body is 4 inputs, 4 outputs with
// maximum range proofs and 4 kernels.
func TestMaximalBodyStaysUnderByteLimit(t *testing.T) {
	b := &types.Block{}
	for i := 0; i < types.MaxBlockInputs; i++ {
		b.Inputs = append(b.Inputs, types.Input{})
	}
	for i := 0; i < types.MaxBlockOutputs; i++ {
		b.Outputs = append(b.Outputs, types.Output{RangeProof: make([]byte, types.MaxRangeProofBytes)})
	}
	for i := 0; i < types.MaxBlockKernels; i++ {
		b.Kernels = append(b.Kernels, types.Kernel{ExcessSig: make([]byte, 65)})
	}
	n, err := BodyResourceBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != 60168 || n >= types.MaxBlockBodyBytes {
		t.Fatalf("maximal charged body = %d bytes (limit %d); update docs/limits.md if this changed", n, types.MaxBlockBodyBytes)
	}
}
