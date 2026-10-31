package wallet_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pasichDev/noso-go/v2/chain"
	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/genesis"
	"github.com/pasichDev/noso-go/v2/mempool"
	"github.com/pasichDev/noso-go/v2/miner"
	"github.com/pasichDev/noso-go/v2/pow"
	"github.com/pasichDev/noso-go/v2/rpc"
	"github.com/pasichDev/noso-go/v2/types"
	"github.com/pasichDev/noso-go/v2/wallet"
)

// testNode is a real Chain + mempool + miner behind the real JSON-RPC handler.
type testNode struct {
	t       *testing.T
	kind    string
	dir     string
	genesis *types.Block
	c       *chain.Chain
	pool    *mempool.Pool
	m       *miner.Miner
	cb      *wallet.CoinbaseStore
	srv     *httptest.Server
	rpc     *wallet.RPCNode
	bcasts  atomic.Int32
	cancel  context.CancelFunc
}

func easyGenesis(t *testing.T) *types.Block {
	g, err := genesis.Build(genesis.Config{NetworkMagic: types.NetworkMagicTestnet, Timestamp: time.Now().Unix() - 600, InitialDifficulty: 1})
	if err != nil {
		t.Fatal(err)
	}
	for n := uint64(0); n < 64; n++ {
		g.Header.Nonce = n
		if pow.Verify(&g.Header) {
			break
		}
	}
	return g
}

func openChain(t *testing.T, kind, dir string, g *types.Block) *chain.Chain {
	t.Helper()
	switch kind {
	case "memory":
		c := chain.NewMemory()
		if err := c.LoadOrInit(filepath.Join(dir, "mem"), g); err != nil {
			t.Fatal(err)
		}
		return c
	case "badger":
		c, err := chain.NewBadger(filepath.Join(dir, "badger"))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.LoadOrInit(filepath.Join(dir, "badger"), g); err != nil {
			t.Fatal(err)
		}
		return c
	}
	t.Fatal("unknown store kind")
	return nil
}

func startNode(t *testing.T, kind string) *testNode {
	n := &testNode{t: t, kind: kind, dir: t.TempDir(), genesis: easyGenesis(t)}
	n.boot()
	t.Cleanup(n.shutdown)
	return n
}

// boot (re)opens every component from the data directory: a process restart.
func (n *testNode) boot() {
	t := n.t
	n.c = openChain(t, n.kind, n.dir, n.genesis)
	n.pool = mempool.NewValidated(2048, n.c.ValidateTransaction)
	cb, err := wallet.OpenCoinbaseStore(filepath.Join(n.dir, "coinbases.json"))
	if err != nil {
		t.Fatal(err)
	}
	n.cb = cb
	n.m = miner.New(n.c, n.pool, cb)
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	svc := &rpc.Service{Chain: n.c, Mempool: n.pool, Miner: n.m, Token: "e2e-token", DaemonContext: ctx,
		BroadcastTx: func(*types.Transaction) error { n.bcasts.Add(1); return nil }}
	n.srv = httptest.NewServer(svc.HTTPHandler())
	n.rpc, err = wallet.NewRPCNode(n.srv.URL, "e2e-token")
	if err != nil {
		t.Fatal(err)
	}
}

func (n *testNode) shutdown() {
	if n.m != nil {
		n.m.Stop()
	}
	if n.cancel != nil {
		n.cancel()
	}
	if n.srv != nil {
		n.srv.Close()
	}
	if n.c != nil {
		n.c.Close()
	}
	n.m, n.cancel, n.srv, n.c = nil, nil, nil, nil
}

func (n *testNode) restart() {
	n.shutdown()
	n.boot()
}

// mineUntil runs the real miner until cond() holds, then stops it.
func (n *testNode) mineUntil(cond func() bool) {
	n.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := n.m.Start(ctx, 2, "e2e"); err != nil {
		n.t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Minute)
	for !cond() {
		if time.Now().After(deadline) {
			n.m.Stop()
			n.t.Fatal("mining did not reach the target in time")
		}
		time.Sleep(15 * time.Millisecond)
	}
	n.m.Stop()
}

func (n *testNode) mineToHeight(h uint64) {
	n.mineUntil(func() bool { return n.c.Height() >= h })
}

func (n *testNode) mineOut() { // until the mempool is empty
	n.t.Helper()
	n.mineUntil(func() bool { return n.pool.Len() == 0 })
}

func (n *testNode) containsKernel(excess types.Commitment) (uint64, bool) {
	for h := n.c.Height(); h > 0; h-- {
		b, ok := n.c.BlockByHeight(h)
		if !ok {
			return 0, false
		}
		for _, k := range b.Kernels {
			if k.Features == types.KernelFeaturesPlain && k.Excess == excess {
				return h, true
			}
		}
		if n.c.Height()-h > 12 {
			break
		}
	}
	return 0, false
}

type party struct {
	t  *testing.T
	st *wallet.Store
}

func newParty(t *testing.T, name string) *party {
	w, err := wallet.NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name+".json")
	if err := w.Save(path, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	st, err := wallet.OpenStore(path, "correct horse battery", w.MasterPublic())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close(); w.Close() })
	if err := st.SetNetwork(types.NetworkMagicTestnet); err != nil {
		t.Fatal(err)
	}
	return &party{t: t, st: st}
}

func (p *party) sync(n *testNode) *wallet.SyncReport {
	p.t.Helper()
	rep, err := p.st.Sync(n.rpc)
	if err != nil {
		p.t.Fatalf("sync: %v", err)
	}
	return rep
}

// pay runs the three rounds between two wallets and returns the response slate.
func pay(t *testing.T, n *testNode, from, to *party, amount int64, fee uint64) (*wallet.Slate, *wallet.FinalizeResult) {
	t.Helper()
	offer, err := from.st.Pay(n.rpc, wallet.PayParams{Amount: amount, Fee: fee, Memo: "e2e"})
	if err != nil {
		t.Fatalf("pay: %v", err)
	}
	// The slates travel as text between the wallets.
	encOffer, err := offer.Encode()
	if err != nil {
		t.Fatal(err)
	}
	offerRx, err := wallet.Decode(encOffer)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := to.st.Receive(offerRx)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	encResp, _ := resp.Encode()
	respRx, err := wallet.Decode(encResp)
	if err != nil {
		t.Fatal(err)
	}
	res, err := from.st.Finalize(n.rpc, respRx)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	return respRx, res
}

func TestEndToEndMiningPaymentsRestartAndReorg(t *testing.T) {
	for _, kind := range []string{"memory", "badger"} {
		t.Run(kind, func(t *testing.T) { endToEnd(t, kind) })
	}
}

func endToEnd(t *testing.T, kind string) {
	n := startNode(t, kind)
	reward := types.BlockReward(1)

	// Mine past the first coinbase's maturity with the real miner.
	n.mineToHeight(types.CoinbaseLock + 2)
	tip := n.c.Height()

	alice, bob, carol := newParty(t, "alice"), newParty(t, "bob"), newParty(t, "carol")
	rep, err := alice.st.ImportCoinbase(filepath.Join(n.dir, "coinbases.json"))
	if err != nil || rep.Imported < int(tip) {
		t.Fatalf("import: %+v %v", rep, err)
	}
	alice.sync(n)
	bal := alice.st.Balance()
	wantMature := int64(tip-types.CoinbaseLock+1) * reward // heights 1..tip-59
	if int64(bal.Spendable) != wantMature || int64(bal.Immature) != int64(types.CoinbaseLock-1)*reward || bal.Tip != tip {
		t.Fatalf("alice balance %+v, want spendable %d immature %d at tip %d", bal, wantMature, (types.CoinbaseLock-1)*uint64(reward), tip)
	}

	// Immature coinbase cannot be spent: asking for more than the mature part fails.
	if _, err := alice.st.Pay(n.rpc, wallet.PayParams{Amount: wantMature + 1, Fee: 1}); err == nil {
		t.Fatal("spent immature coinbase outputs")
	}

	// alice -> bob (spends two coinbases, makes change).
	amount1, fee1 := reward+reward/2, uint64(1_000_000)
	resp1, res1 := pay(t, n, alice, bob, amount1, fee1)
	if n.pool.Len() != 1 || n.bcasts.Load() != 1 {
		t.Fatalf("pool=%d broadcasts=%d", n.pool.Len(), n.bcasts.Load())
	}
	// A retry of finalize is idempotent: same transaction, still one pool entry.
	again, err := alice.st.Finalize(n.rpc, resp1)
	if err != nil || !again.Resubmitted || again.TxHash != res1.TxHash || n.pool.Len() != 1 {
		t.Fatalf("retry: %+v %v pool=%d", again, err, n.pool.Len())
	}
	n.mineOut()
	// Replaying the finalize after confirmation: the node rejects it (the inputs
	// are gone) and the wallet reports a rejection, never a second signature.
	if _, err := alice.st.Finalize(n.rpc, resp1); !errors.Is(err, wallet.ErrRejected) {
		t.Fatalf("replay of a confirmed payment: %v", err)
	}
	k1 := firstKernel(t, n, res1)
	h1, ok := n.containsKernel(k1)
	if !ok {
		t.Fatal("payment kernel not found in a mined block")
	}
	alice.sync(n)
	bob.sync(n)
	if got := bob.st.Balance(); int64(got.Spendable) != amount1 || got.Pending != 0 {
		t.Fatalf("bob %+v", got)
	}
	// (Imported coinbase records of candidate blocks that never landed stay
	// pending forever; everything else must have settled.)
	if got := alice.st.Balance(); got.Locked != 0 || nonCoinbasePending(alice) != 0 {
		t.Fatalf("alice %+v", got)
	}
	changeCount := 0
	for _, o := range alice.st.Outputs() {
		if o.Origin == wallet.OriginChange && o.Status == wallet.StatusUnspent {
			changeCount++
			if o.Value != 2*reward-amount1-int64(fee1) {
				t.Fatalf("change %d", o.Value)
			}
		}
	}
	if changeCount != 1 {
		t.Fatalf("change outputs: %d", changeCount)
	}

	// bob spends the received output onward to carol.
	amount2, fee2 := amount1/3, uint64(500_000)
	resp2, res2 := pay(t, n, bob, carol, amount2, fee2)
	n.mineOut()
	bob.sync(n)
	carol.sync(n)
	if got := carol.st.Balance(); int64(got.Spendable) != amount2 {
		t.Fatalf("carol %+v", got)
	}
	if got := bob.st.Balance(); int64(got.Spendable) != amount1-amount2-int64(fee2) {
		t.Fatalf("bob after onward payment %+v", got)
	}
	_ = resp2
	_ = res2

	// Restart the whole node from disk and keep going.
	n.restart()
	for _, p := range []*party{alice, bob, carol} {
		rep := p.sync(n)
		if rep.Confirmed+rep.Spent+rep.Restored+rep.Reorged != 0 {
			t.Fatalf("restart changed wallet view: %+v", rep)
		}
	}
	amount3, fee3 := amount2/2, uint64(250_000)
	resp3, res3 := pay(t, n, carol, alice, amount3, fee3)
	n.mineOut()
	h3, ok := n.containsKernel(firstKernel(t, n, res3))
	if !ok {
		t.Fatal("post-restart payment not mined")
	}
	carol.sync(n)
	alice.sync(n)
	if !hasOutput(alice, wallet.OriginReceive, wallet.StatusUnspent, amount3) {
		t.Fatalf("alice has no confirmed %d output: %+v", amount3, alice.st.Outputs())
	}

	// Reorg: a longer fork from before carol's payment drops it.
	if h3 <= h1 {
		t.Fatalf("heights: %d %d", h1, h3)
	}
	cur := n.c.Height()
	forkFrom := h3 - 1
	parent, _ := n.c.HeaderByHeight(forkFrom)
	var fork []*types.Block
	for i := uint64(0); i < cur-forkFrom+1; i++ {
		b := forkBlock(t, parent, byte(i))
		fork = append(fork, b)
		parent = b.Header
	}
	if err := n.c.ReorgTo(fork); err != nil {
		t.Fatalf("reorg: %v", err)
	}
	if _, still := n.containsKernel(firstKernel(t, n, res3)); still {
		t.Fatal("kernel still on chain after reorg")
	}
	repC := carol.sync(n)
	repA := alice.sync(n)
	if len(repC.ReorgedTxs) != 1 || repA.Reorged != 1 {
		t.Fatalf("reorg not seen by wallets: carol=%+v alice=%+v", repC, repA)
	}
	if !hasOutput(alice, wallet.OriginReceive, wallet.StatusPending, amount3) || hasOutput(alice, wallet.OriginReceive, wallet.StatusUnspent, amount3) {
		t.Fatalf("alice's received output should be pending again: %+v", alice.st.Outputs())
	}
	// Resubmit the stored signed transaction (same signature) and re-mine it.
	re, err := carol.st.Finalize(n.rpc, resp3)
	if err != nil || !re.Resubmitted || re.TxHash != res3.TxHash {
		t.Fatalf("resubmit after reorg: %+v %v", re, err)
	}
	n.mineOut()
	carol.sync(n)
	alice.sync(n)
	if !hasOutput(alice, wallet.OriginReceive, wallet.StatusUnspent, amount3) {
		t.Fatalf("alice's output did not come back after re-mining: %+v", alice.st.Outputs())
	}
	if got := carol.st.Balance(); nonCoinbasePending(carol) != 0 || got.Locked != 0 {
		t.Fatalf("carol %+v", got)
	}
	// Stored nonce contexts: none anywhere.
	for _, p := range []*party{alice, bob, carol} {
		if len(p.st.Contexts()) != 0 {
			t.Fatal("nonce context left behind")
		}
	}
}

func hasOutput(p *party, origin string, status wallet.OutputStatus, value int64) bool {
	for _, o := range p.st.Outputs() {
		if o.Origin == origin && o.Status == status && o.Value == value {
			return true
		}
	}
	return false
}

func nonCoinbasePending(p *party) uint64 {
	var sum uint64
	for _, o := range p.st.Outputs() {
		if o.Status == wallet.StatusPending && o.Origin != wallet.OriginCoinbase {
			sum += uint64(o.Value)
		}
	}
	return sum
}

func firstKernel(t *testing.T, n *testNode, res *wallet.FinalizeResult) types.Commitment {
	t.Helper()
	raw, err := hex.DecodeString(res.Excess)
	if err != nil || len(raw) != 33 {
		t.Fatalf("bad excess %q", res.Excess)
	}
	var c types.Commitment
	copy(c[:], raw)
	return c
}

// forkBlock builds a coinbase-only block on parent at difficulty 1.
func forkBlock(t *testing.T, parent types.BlockHeader, salt byte) *types.Block {
	t.Helper()
	h := types.BlockHeader{Version: types.BlockVersion, NetworkMagic: parent.NetworkMagic, Height: parent.Height + 1,
		Timestamp: parent.Timestamp + 1, PrevHash: types.HeaderID(&parent), Difficulty: parent.Difficulty}
	reward := types.BlockReward(h.Height)
	seed := append([]byte("e2e fork coinbase"), h.PrevHash[:]...)
	seed = binary.BigEndian.AppendUint64(seed, h.Height)
	seed = append(seed, salt)
	blind := sha256.Sum256(seed)
	commit, err := v2crypto.PedersenCommit(reward, blind[:])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wallet.SignCoinbase(h.NetworkMagic, wallet.CoinbaseRecord{Height: h.Height, Amount: reward, Blinding: blind, Commit: commit})
	if err != nil {
		t.Fatal(err)
	}
	b := &types.Block{Header: h,
		Outputs: []types.Output{{Features: types.OutputFeaturesCoinbase, Commit: commit}},
		Kernels: []types.Kernel{{Features: types.KernelFeaturesCoinbase, LockHeight: h.Height + types.CoinbaseLock, Excess: commit, ExcessSig: sig}}}
	types.SetBlockRoots(b)
	for nonce := uint64(0); ; nonce++ {
		b.Header.Nonce = nonce
		if pow.Verify(&b.Header) {
			return b
		}
	}
}
