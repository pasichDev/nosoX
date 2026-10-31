package wallet

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
)

func TestStateFileIsEncryptedAndAuthenticated(t *testing.T) {
	d := newDuo(t, 1000)
	offer, err := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.r.Receive(offer); err != nil {
		t.Fatal(err)
	}
	for _, st := range []*Store{d.s, d.r} {
		raw, err := os.ReadFile(st.path)
		if err != nil {
			t.Fatal(err)
		}
		// None of the secrets may appear on disk in any common encoding.
		var secrets [][]byte
		for _, o := range st.st.Outputs {
			secrets = append(secrets, o.Blinding)
		}
		for _, c := range st.st.Contexts {
			secrets = append(secrets, c.XS, c.KS)
		}
		if len(secrets) == 0 {
			t.Fatal("no secrets to look for")
		}
		for _, sec := range secrets {
			for _, enc := range [][]byte{sec, []byte(hex.EncodeToString(sec)), []byte(base64.StdEncoding.EncodeToString(sec)), []byte(base64.URLEncoding.EncodeToString(sec))} {
				if bytes.Contains(raw, enc) {
					t.Fatal("a secret appears in the state file in the clear")
				}
			}
		}
		if bytes.Contains(raw, []byte("blinding")) || bytes.Contains(raw, []byte("commit")) {
			t.Fatal("state file leaks structure")
		}
		info, _ := os.Stat(st.path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("state file mode %o", info.Mode().Perm())
		}
	}
	// Fresh nonce on every write.
	a, _ := os.ReadFile(d.s.path)
	if err := d.s.commit(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(d.s.path)
	var ea, eb Encrypted
	json.Unmarshal(a, &ea)
	json.Unmarshal(b, &eb)
	if ea.Nonce == eb.Nonce || ea.Ciphertext == eb.Ciphertext {
		t.Fatal("AEAD nonce reused across writes")
	}
	if ea.Salt != eb.Salt {
		t.Fatal("salt should be stable within a store")
	}
}

func TestStateRejectsWrongPassphraseWalletAndTampering(t *testing.T) {
	d := newDuo(t, 1000)
	walletPath := d.s.path[:len(d.s.path)-len(StateSuffix)]
	master := append(ed25519.PublicKey(nil), d.s.st.Master...)
	statePath := d.s.path
	d.s.Close()

	if _, err := OpenStore(walletPath, "wrong", master); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	other, _ := NewRandom()
	defer other.Close()
	if _, err := OpenStore(walletPath, testPass, other.MasterPublic()); err == nil {
		t.Fatal("state of another wallet accepted")
	}
	raw, _ := os.ReadFile(statePath)
	var enc Encrypted
	json.Unmarshal(raw, &enc)
	ct, _ := base64.StdEncoding.DecodeString(enc.Ciphertext)
	ct[len(ct)/2] ^= 1
	enc.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	bad, _ := json.Marshal(enc)
	if err := os.WriteFile(statePath, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(walletPath, testPass, master); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	// The keystore envelope uses a different AAD: it cannot stand in for state.
	ks, err := os.ReadFile(walletPath)
	if err != nil || len(ks) == 0 {
		t.Fatalf("keystore unreadable: %v", err)
	}
	if err := os.WriteFile(statePath, ks, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(walletPath, testPass, master); err == nil {
		t.Fatal("the keystore file was accepted as the output state")
	}
	if err := os.WriteFile(statePath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(walletPath, testPass, master); err == nil {
		t.Fatal("empty envelope accepted")
	}
}

func TestStoreIsExclusive(t *testing.T) {
	d := newDuo(t, 1000)
	walletPath := d.s.path[:len(d.s.path)-len(StateSuffix)]
	if _, err := OpenStore(walletPath, testPass, d.s.st.Master); err == nil {
		t.Fatal("second opener got the lock while the first is open")
	}
	d.s.Close()
	s2, err := OpenStore(walletPath, testPass, d.s.st.Master)
	if err != nil {
		t.Fatalf("lock not released on Close: %v", err)
	}
	s2.Close()
}

func TestCloseZeroizesSecrets(t *testing.T) {
	d := newDuo(t, 1000)
	if _, err := d.s.Pay(d.node, PayParams{Amount: 5, Fee: 1}); err != nil {
		t.Fatal(err)
	}
	blind := d.s.st.Outputs[0].Blinding
	xs := d.s.st.Contexts[0].XS
	key := d.s.key
	d.s.Close()
	for name, b := range map[string][]byte{"blinding": blind, "excess scalar": xs, "state key": key} {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("%s not zeroed on Close", name)
		}
	}
}

func TestOutputsListingHidesBlindingFactors(t *testing.T) {
	d := newDuo(t, 1000)
	for _, o := range d.s.Outputs() {
		if len(o.Blinding) != 0 {
			t.Fatal("Outputs() exposes a blinding factor")
		}
	}
	out, _ := json.Marshal(d.s.Outputs())
	if bytes.Contains(out, []byte("blinding\":\"")) {
		t.Fatal("blinding in listing JSON")
	}
}

// ---- sync --------------------------------------------------------------------

func TestSyncTracksPendingConfirmedSpentAndReorg(t *testing.T) {
	d := newDuo(t, 1000)
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	resp, _ := d.r.Receive(offer)
	if _, err := d.s.Finalize(d.node, resp); err != nil {
		t.Fatal(err)
	}
	// In the mempool only: receiver and change are pending, input is spent-pending.
	if _, err := d.s.Sync(d.node); err != nil {
		t.Fatal(err)
	}
	if b := d.s.Balance(); b.Pending != 390 || b.Spendable != 0 {
		t.Fatalf("pre-confirmation sender balance %+v", b)
	}
	d.node.mine()
	rep, err := d.s.Sync(d.node)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Confirmed != 1 || rep.Spent != 1 {
		t.Fatalf("sync report %+v", rep)
	}
	if _, err := d.r.Sync(d.node); err != nil {
		t.Fatal(err)
	}
	if d.r.Balance().Spendable != 600 || d.s.Balance().Spendable != 390 {
		t.Fatalf("balances %+v %+v", d.s.Balance(), d.r.Balance())
	}
	// Sync is idempotent.
	rep, _ = d.s.Sync(d.node)
	if rep.Confirmed+rep.Spent+rep.Restored+rep.Reorged != 0 {
		t.Fatalf("idempotent sync changed things: %+v", rep)
	}

	// Reorg: the block holding the payment disappears and its tx is not re-mined.
	tx, _ := DecodeTx(d.node.submits[0])
	d.node.reorgOut(tx)
	rep, err = d.s.Sync(d.node)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Reorged != 1 || rep.Restored != 1 || len(rep.ReorgedTxs) != 1 {
		t.Fatalf("reorg not detected: %+v", rep)
	}
	if b := d.s.Balance(); b.Pending != 390 || b.Spendable != 0 {
		t.Fatalf("sender after reorg %+v", b)
	}
	if _, err := d.r.Sync(d.node); err != nil {
		t.Fatal(err)
	}
	if b := d.r.Balance(); b.Pending != 600 || b.Spendable != 0 {
		t.Fatalf("receiver after reorg %+v", b)
	}
	// Resubmitting the stored transaction (same signature) puts everything back.
	if _, err := d.s.Finalize(d.node, resp); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.node.submits[len(d.node.submits)-1], d.node.submits[0]) {
		t.Fatal("resubmission after reorg used a different signature")
	}
	d.node.mine()
	d.s.Sync(d.node)
	d.r.Sync(d.node)
	if d.r.Balance().Spendable != 600 || d.s.Balance().Spendable != 390 {
		t.Fatalf("after re-mine: %+v %+v", d.s.Balance(), d.r.Balance())
	}
}

func TestSyncFailureLeavesStateUntouched(t *testing.T) {
	d := newDuo(t, 1000)
	before, _ := os.ReadFile(d.s.path)
	n := &errNode{fakeNode: d.node}
	if _, err := d.s.Sync(n); err == nil {
		t.Fatal("expected node error")
	}
	after, _ := os.ReadFile(d.s.path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed sync wrote state")
	}
}

type errNode struct{ *fakeNode }

func (e *errNode) UTXO(types.Commitment) (UTXOInfo, error) { return UTXOInfo{}, os.ErrDeadlineExceeded }

func TestBalanceSeparatesImmatureCoinbase(t *testing.T) {
	node := newFakeNode()
	s := newWalletStore(t, "s")
	fund(t, s, node, 500, types.OutputFeaturesCoinbase, node.tip-10)
	fund(t, s, node, 300, types.OutputFeaturesCoinbase, node.tip-80)
	fund(t, s, node, 7, types.OutputFeaturesPlain, 3)
	if _, err := s.Sync(node); err != nil {
		t.Fatal(err)
	}
	b := s.Balance()
	if b.Immature != 500 || b.Spendable != 307 || !b.Synced || b.Tip != node.tip {
		t.Fatalf("%+v", b)
	}
}

// ---- import-coinbase -----------------------------------------------------------

func TestImportCoinbaseVerifiesEachCommit(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenCoinbaseStore(filepath.Join(dir, "coinbases.json"))
	if err != nil {
		t.Fatal(err)
	}
	for h := uint64(1); h <= 3; h++ {
		if _, err := store.Allocate(h, 5_000_000_000); err != nil {
			t.Fatal(err)
		}
	}
	s := newWalletStore(t, "w")
	rep, err := s.ImportCoinbase(filepath.Join(dir, "coinbases.json"))
	if err != nil || rep.Imported != 3 || rep.Invalid != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if rep, _ = s.ImportCoinbase(filepath.Join(dir, "coinbases.json")); rep.Imported != 0 || rep.Duplicate != 3 {
		t.Fatalf("re-import: %+v", rep)
	}
	for _, o := range s.Outputs() {
		if o.Status != StatusPending || o.Origin != OriginCoinbase || o.Features != uint8(types.OutputFeaturesCoinbase) {
			t.Fatalf("%+v", o)
		}
	}

	// A record whose blinding does not open its commitment is skipped; the rest import.
	recs := store.All()
	recs[0].Blinding[5] ^= 0xff
	bad := recs[0]
	good := CoinbaseRecord{Height: 9, Amount: 123}
	good.Blinding = [32]byte{31: 7}
	good.Commit, _ = v2crypto.PedersenCommit(123, good.Blinding[:])
	body, _ := json.Marshal([]CoinbaseRecord{bad, good, {Height: 1, Amount: 0}})
	p := filepath.Join(dir, "mixed.json")
	os.WriteFile(p, body, 0o600)
	s2 := newWalletStore(t, "w2")
	rep, err = s2.ImportCoinbase(p)
	if err != nil || rep.Imported != 1 || rep.Invalid != 2 {
		t.Fatalf("mixed import: %+v %v", rep, err)
	}
	// Garbage and oversized files.
	os.WriteFile(p, []byte("not json"), 0o600)
	if _, err := s2.ImportCoinbase(p); err == nil {
		t.Fatal("garbage accepted")
	}
	os.WriteFile(p, []byte(`[{"h":1,"v":1,"b":[0],"c":[0],"extra":1}]`), 0o600)
	if _, err := s2.ImportCoinbase(p); err == nil {
		t.Fatal("unknown fields / wrong shapes accepted")
	}
	if _, err := s2.ImportCoinbase(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestImportedCoinbaseBecomesSpendableAfterSync(t *testing.T) {
	dir := t.TempDir()
	store, _ := OpenCoinbaseStore(filepath.Join(dir, "cb.json"))
	rec, _ := store.Allocate(1, 5_000_000_000)
	node := newFakeNode()
	node.tip = 70
	node.mu.Lock()
	node.utxo[rec.Commit] = UTXOInfo{Present: true, Features: types.OutputFeaturesCoinbase, Height: 1, BlockHash: "aa", MaturesAt: 61}
	node.mu.Unlock()
	s, r := newWalletStore(t, "s"), newWalletStore(t, "r")
	if _, err := s.ImportCoinbase(filepath.Join(dir, "cb.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pay(node, PayParams{Amount: 1, Fee: 1}); err == nil {
		t.Fatal("pending (unsynced) coinbase was spent")
	}
	if _, err := s.Sync(node); err != nil {
		t.Fatal(err)
	}
	offer, err := s.Pay(node, PayParams{Amount: 1_000_000_000, Fee: 1000})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Finalize(node, resp); err != nil {
		t.Fatalf("spend of a mined coinbase: %v", err)
	}
}

type blockHashErrNode struct{ *fakeNode }

func (b *blockHashErrNode) BlockHash(uint64) (string, bool, error) {
	return "", false, os.ErrDeadlineExceeded
}

// A sync that fails half way must not leave in-memory state that was never
// written (a long-lived library caller would act on it).
func TestSyncFailingMidwayLeavesMemoryAndDiskUntouched(t *testing.T) {
	d := newDuo(t, 1000, 400)
	// One output vanishes from the node; deciding whether it was spent or reorged
	// out needs BlockHash, which fails. The other output is confirmed-present.
	d.node.mu.Lock()
	var gone types.Commitment
	for _, o := range d.s.st.Outputs {
		if o.Value == 1000 {
			gone, _ = parseCommit(o.Commit)
		}
	}
	delete(d.node.utxo, gone)
	d.node.mu.Unlock()
	// Mutate something Sync would change first (pending -> unspent happens for the
	// other output only if it were pending), so also add a pending-but-present one.
	// Outputs are processed in commitment order: make the pending one come first,
	// so its in-place pending -> unspent edit has happened when the failure hits.
	var pend types.Commitment
	var rb [32]byte
	for {
		r, _ := randomScalar()
		rb = r.Bytes()
		c, err := v2crypto.PedersenCommit(5, rb[:])
		if err != nil {
			t.Fatal(err)
		}
		if commitHex(c) < commitHex(gone) {
			pend = c
			break
		}
	}
	d.s.st.Outputs = append(d.s.st.Outputs, OutputRecord{Commit: commitHex(pend), Value: 5, Blinding: append([]byte(nil), rb[:]...), Features: 0, Status: StatusPending, Origin: OriginReceive})
	if err := d.s.commit(); err != nil {
		t.Fatal(err)
	}
	d.node.mu.Lock()
	d.node.utxo[pend] = UTXOInfo{Present: true, Height: 7, BlockHash: "cc"}
	d.node.mu.Unlock()

	beforeBal, beforeOut := d.s.Balance(), d.s.Outputs()
	beforeFile, _ := os.ReadFile(d.s.path)
	if _, err := d.s.Sync(&blockHashErrNode{d.node}); err == nil {
		t.Fatal("expected sync failure")
	}
	if d.s.Balance() != beforeBal {
		t.Fatalf("balance changed by a failed sync: %+v -> %+v", beforeBal, d.s.Balance())
	}
	afterOut := d.s.Outputs()
	if len(afterOut) != len(beforeOut) {
		t.Fatal("outputs changed")
	}
	for i := range afterOut {
		if !reflect.DeepEqual(afterOut[i], beforeOut[i]) {
			t.Fatalf("output %d changed by a failed sync: %+v -> %+v", i, beforeOut[i], afterOut[i])
		}
	}
	afterFile, _ := os.ReadFile(d.s.path)
	if !bytes.Equal(beforeFile, afterFile) {
		t.Fatal("failed sync wrote state")
	}
}
