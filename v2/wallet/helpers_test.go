package wallet

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
)

// fakeNode is an in-memory node that enforces the same transaction rules as
// the chain (kernel signature, commitment balance, range proofs, input
// existence/maturity, output uniqueness) without any mining.
type fakeNode struct {
	mu        sync.Mutex
	utxo      map[types.Commitment]UTXOInfo
	seen      map[types.Commitment]bool
	blocks    map[uint64]string
	tip       uint64
	pool      map[types.Hash][]byte
	submits   [][]byte // every Submit call, encoded
	submitErr error    // returned by Submit before any validation (transport failure)
	queried   map[types.Commitment]int
	magic     uint32 // 0 = testnet
}

func newFakeNode() *fakeNode {
	return &fakeNode{utxo: map[types.Commitment]UTXOInfo{}, seen: map[types.Commitment]bool{}, blocks: map[uint64]string{}, pool: map[types.Hash][]byte{}, tip: 100}
}

func (n *fakeNode) UTXO(c types.Commitment) (UTXOInfo, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.queried == nil {
		n.queried = map[types.Commitment]int{}
	}
	n.queried[c]++
	info := n.utxo[c]
	info.Tip = n.tip
	if info.Present && info.Features == types.OutputFeaturesCoinbase {
		info.Mature = n.tip+1 >= info.MaturesAt
	}
	return info, nil
}

func (n *fakeNode) NetworkMagic() (uint32, error) {
	if n.magic != 0 {
		return n.magic, nil
	}
	return types.NetworkMagicTestnet, nil
}

func (n *fakeNode) BlockHash(h uint64) (string, bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	s, ok := n.blocks[h]
	return s, ok, nil
}

func (n *fakeNode) Submit(tx *types.Transaction) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	raw, err := EncodeTx(tx)
	if err != nil {
		return err
	}
	n.submits = append(n.submits, raw)
	if n.submitErr != nil {
		return n.submitErr
	}
	id := types.TransactionID(tx)
	if _, dup := n.pool[id]; dup {
		return nil // idempotent
	}
	if err := n.validate(tx); err != nil {
		return fmt.Errorf("%w: %v", ErrRejected, err)
	}
	n.pool[id] = raw
	return nil
}

func (n *fakeNode) validate(tx *types.Transaction) error {
	var pos, neg [][33]byte
	var fees uint64
	for _, in := range tx.Inputs {
		info, ok := n.utxo[in.Commit]
		if !ok || !info.Present {
			return errors.New("input not unspent")
		}
		if info.Features != in.Features {
			return errors.New("input feature mismatch")
		}
		if info.Features == types.OutputFeaturesCoinbase && n.tip+1 < info.MaturesAt {
			return errors.New("immature coinbase")
		}
		neg = append(neg, in.Commit)
	}
	for _, o := range tx.Outputs {
		if n.seen[o.Commit] || !v2crypto.VerifyRange(o.Commit, o.RangeProof) {
			return errors.New("bad output")
		}
		pos = append(pos, o.Commit)
	}
	if len(tx.Kernels) == 0 {
		return errors.New("no kernel")
	}
	for _, k := range tx.Kernels {
		if !v2crypto.SchnorrVerify(k.Excess, types.KernelSigningMessage(types.NetworkMagicTestnet, &k), k.ExcessSig) {
			return errors.New("bad kernel signature")
		}
		neg = append(neg, k.Excess)
		fees += k.Fee
	}
	if fees > 0 {
		feeH, _ := v2crypto.PedersenCommit(int64(fees), make([]byte, 32))
		pos = append(pos, feeH)
	}
	ok, err := v2crypto.PedersenSumZero(pos, neg, 0)
	if err != nil || !ok {
		return errors.New("does not balance")
	}
	return nil
}

// mine confirms every pooled transaction in a new block.
func (n *fakeNode) mine() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.tip++
	var hb [32]byte
	rand.Read(hb[:])
	hash := hex.EncodeToString(hb[:])
	n.blocks[n.tip] = hash
	for _, raw := range n.pool {
		tx, _ := DecodeTx(raw)
		for _, in := range tx.Inputs {
			delete(n.utxo, in.Commit)
		}
		for _, o := range tx.Outputs {
			n.utxo[o.Commit] = UTXOInfo{Present: true, Features: o.Features, Height: n.tip, BlockHash: hash}
			n.seen[o.Commit] = true
		}
	}
	n.pool = map[types.Hash][]byte{}
}

// reorgOut removes the tip block: its outputs vanish and the given inputs
// return (tx bytes are supplied by the caller).
func (n *fakeNode) reorgOut(tx *types.Transaction) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.blocks, n.tip)
	n.tip--
	for _, o := range tx.Outputs {
		delete(n.utxo, o.Commit)
		delete(n.seen, o.Commit)
	}
	for _, in := range tx.Inputs {
		n.utxo[in.Commit] = UTXOInfo{Present: true, Features: in.Features, Height: 5, BlockHash: fmt.Sprintf("%064x", 5)}
	}
}

func newWalletStore(t testing.TB, name string) *Store {
	t.Helper()
	dir := t.TempDir()
	w, err := NewRandom()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	path := filepath.Join(dir, name+".json")
	if err := w.Save(path, testPass); err != nil {
		t.Fatal(err)
	}
	st, err := OpenStore(path, testPass, w.MasterPublic())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	st.st.Magic = types.NetworkMagicTestnet
	if err := st.commit(); err != nil {
		t.Fatal(err)
	}
	return st
}

// reopen closes the store and opens the same state file again (a process restart).
func reopen(t testing.TB, st *Store) *Store {
	t.Helper()
	walletPath := st.path[:len(st.path)-len(StateSuffix)]
	master := append([]byte(nil), st.st.Master...)
	st.Close()
	ns, err := OpenStore(walletPath, testPass, master)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ns.Close)
	return ns
}

// fund adds an unspent output of the given value to st and registers it on node.
func fund(t testing.TB, st *Store, n *fakeNode, value int64, feat types.OutputFeatures, createdAt uint64) types.Commitment {
	t.Helper()
	r, err := randomScalar()
	if err != nil {
		t.Fatal(err)
	}
	rb := r.Bytes()
	commit, err := v2crypto.PedersenCommit(value, rb[:])
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%064x", createdAt)
	origin := OriginReceive
	var maturesAt uint64
	if feat == types.OutputFeaturesCoinbase {
		origin = OriginCoinbase
		maturesAt = createdAt + types.CoinbaseLock
	}
	st.st.Outputs = append(st.st.Outputs, OutputRecord{Commit: commitHex(commit), Value: value, Blinding: append([]byte(nil), rb[:]...),
		Features: uint8(feat), Status: StatusUnspent, Origin: origin, Height: createdAt, MaturesAt: maturesAt, BlockHash: hash})
	if err := st.commit(); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	n.utxo[commit] = UTXOInfo{Present: true, Features: feat, Height: createdAt, BlockHash: hash, MaturesAt: maturesAt,
		Mature: feat != types.OutputFeaturesCoinbase || n.tip+1 >= maturesAt}
	n.seen[commit] = true
	n.blocks[createdAt] = hash
	n.mu.Unlock()
	return commit
}
