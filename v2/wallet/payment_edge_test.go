package wallet

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pasichDev/nosoX/v2/types"
)

// ---- helpers -------------------------------------------------------------

// liarNode answers every UTXO query "absent" with a chosen tip: a hostile or
// squatted node. Everything else is delegated to the honest fake.
type liarNode struct {
	*fakeNode
	tip uint64
}

func (l *liarNode) UTXO(c types.Commitment) (UTXOInfo, error) {
	return UTXOInfo{Present: false, Tip: l.tip}, nil
}

// holdsKey reports whether the wallet still holds the blinding factor of commit,
// live or archived.
func holdsKey(st *Store, commit string) bool {
	for _, o := range st.st.Outputs {
		if o.Commit == commit && len(o.Blinding) == 32 && !bytes.Equal(o.Blinding, make([]byte, 32)) {
			return true
		}
	}
	for _, a := range st.st.Archive {
		if a.Commit == commit && len(a.Blinding) == 32 && !bytes.Equal(a.Blinding, make([]byte, 32)) {
			return true
		}
	}
	return false
}

// importedCoinbase adds a coinbase key the way ImportCoinbase does (pending,
// claimed height) and registers it on the node.
func importedCoinbase(t *testing.T, st *Store, n *fakeNode, value int64, claimed uint64) string {
	t.Helper()
	c := fund(t, st, n, value, types.OutputFeaturesCoinbase, claimed)
	h := commitHex(c)
	o := st.output(h)
	o.Status, o.BlockHash = StatusPending, ""
	if err := st.commit(); err != nil {
		t.Fatal(err)
	}
	return h
}

// ---- item 1: a lying node must not destroy keys ---------------------------

func TestLyingNodeHugeTipDestroysNoKeys(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	a := commitHex(fund(t, st, n, 700, types.OutputFeaturesPlain, 5))
	b := commitHex(fund(t, st, n, 300, types.OutputFeaturesPlain, 6))
	cb := importedCoinbase(t, st, n, 500, 7)
	if _, err := st.Sync(n); err != nil { // an honest sync first
		t.Fatal(err)
	}
	liar := &liarNode{fakeNode: n, tip: math.MaxUint64}
	for i := 0; i < 3; i++ {
		_, _ = st.Sync(liar) // may be refused or accepted: keys must survive either way
	}
	for _, h := range []string{a, b, cb} {
		if !holdsKey(st, h) {
			t.Fatalf("key %s... destroyed on a lying node's word", h[:12])
		}
	}
	if _, err := st.Sync(n); err != nil { // the honest node returns
		t.Fatalf("honest sync after the liar: %v", err)
	}
	if bal := st.Balance(); bal.Spendable+bal.Immature+bal.Pending != 1500 {
		t.Fatalf("funds lost after a correct node returned: %+v", bal)
	}
	if _, err := st.Pay(n, PayParams{Amount: 900, Fee: 1}); err != nil {
		t.Fatalf("funds not spendable after the honest node returned: %v", err)
	}
}

func TestSlowLiarWithinBoundsDestroysNoKeys(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	clock := time.Unix(1_800_000_000, 0)
	st.now = func() time.Time { return clock }
	a := commitHex(fund(t, st, n, 700, types.OutputFeaturesPlain, 5))
	cb := importedCoinbase(t, st, n, 500, 7)
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	// The liar advances its claimed tip as fast as the wallet would believe, one
	// day per sync, and says "absent" every time.
	tip := n.tip
	for i := 0; i < 4; i++ {
		clock = clock.Add(24 * time.Hour)
		tip += 8640 + 32
		// Every lie is within the tip bounds, so every sync must be ACCEPTED: the
		// guarantee under test is the archive, not the refusal.
		if _, err := st.Sync(&liarNode{fakeNode: n, tip: tip}); err != nil {
			t.Fatalf("liar sync %d refused: %v", i, err)
		}
		if st.st.SyncedAt != clock.Unix() {
			t.Fatalf("SyncedAt %d, clock %d", st.st.SyncedAt, clock.Unix())
		}
	}
	for _, h := range []string{a, cb} {
		if !holdsKey(st, h) {
			t.Fatalf("key %s... destroyed by a slow liar", h[:12])
		}
		if !st.archived(h) || st.output(h) != nil {
			t.Fatalf("%s... should have been moved to the archive by the lies, so the test exercises it", h[:12])
		}
	}
	clock = clock.Add(time.Hour)
	if _, err := st.Sync(n); err != nil {
		t.Fatalf("honest sync after the slow liar: %v", err)
	}
	if _, err := st.Pay(n, PayParams{Amount: 1100, Fee: 1}); err != nil {
		t.Fatalf("funds not spendable after the honest node returned: %v", err)
	}
}

// ---- item 2: a full wallet can always spend --------------------------------

func TestPayWorksAtTheRecordCap(t *testing.T) {
	for _, amount := range []int64{999, 100} { // zero change, and with change
		n := newFakeNode()
		st := newWalletStore(t, "a")
		fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
		fillDummies(t, st, maxOutputRecords-1, StatusUnspent, 0)
		if _, err := st.Pay(n, PayParams{Amount: amount, Fee: 1}); err != nil {
			t.Fatalf("pay %d at the record cap: %v", amount, err)
		}
	}
}

// ---- item 3: cancel after a restored backup keeps the change ----------------

func TestCancelAfterRestoreKeepsChangeForAMinedTx(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
	offer, err := st.Pay(n, PayParams{Amount: 600, Fee: 10})
	if err != nil {
		t.Fatal(err)
	}
	backup, _ := os.ReadFile(st.path)
	r := newWalletStore(t, "r")
	resp, err := r.Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Finalize(n, resp); err != nil { // the real timeline: signed and submitted
		t.Fatal(err)
	}
	p, m, wp := st.path, append([]byte(nil), st.st.Master...), walletPathOf(st)
	st.Close()
	if err := os.WriteFile(p, backup, 0o600); err != nil {
		t.Fatal(err)
	}
	st2, err := OpenStore(wp, testPass, m)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if err := st2.Cancel(hexID(offer.TxID), false); err != nil {
		t.Fatal(err)
	}
	n.mine() // the transaction signed before the restore is mined
	if _, err := st2.Sync(n); err != nil {
		t.Fatal(err)
	}
	if _, err := st2.Pay(n, PayParams{Amount: 389, Fee: 1}); err != nil {
		t.Fatalf("the change of a mined transaction was lost by cancel: %v", err)
	}
}

// ---- item 4 ----------------------------------------------------------------

func TestUpgradeKeepsABackupOfTheOldKeystore(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "w.json")
	w, _ := NewRandom()
	defer w.Close()
	writeV1Keystore(t, p, w, testPass)
	old, _ := os.ReadFile(p)
	loaded, err := Load(p, testPass)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if err := loaded.Upgrade(p, testPass); err != nil {
		t.Fatal(err)
	}
	bak, err := os.ReadFile(p + ".v1.bak")
	if err != nil {
		t.Fatalf("no backup of the old keystore: %v", err)
	}
	if !bytes.Equal(bak, old) {
		t.Fatal("backup differs from the original file")
	}
	if fi, _ := os.Stat(p + ".v1.bak"); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %o", fi.Mode().Perm())
	}
}

func noDirRead(t *testing.T, dir string) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX directory permissions and a non-root user")
	}
	if err := os.Chmod(dir, 0o300); err != nil { // write+search but not read: renames work, fsync(dir) cannot open it
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

func TestCoinbaseRotateRecoversAfterATransientDirectoryFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "coinbases.json")
	cs, err := OpenCoinbaseStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < CoinbaseRotateRecords; i++ {
		rec, err := cs.NewRecord(uint64(i+1), 5)
		if err != nil {
			t.Fatal(err)
		}
		cs.all = append(cs.all, rec)
	}
	if err := cs.flushLocked(); err != nil {
		t.Fatal(err)
	}
	rec, _ := cs.NewRecord(99999, 5)
	noDirRead(t, dir)
	if err := cs.Persist(rec); err == nil {
		t.Fatal("expected the directory sync to fail")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cs.Persist(rec); err != nil {
		t.Fatalf("the miner stays wedged after a transient failure: %v", err)
	}
	arch, _ := CoinbaseArchives(path)
	if len(arch) != 1 {
		t.Fatalf("archives: %v", arch)
	}
	if _, ok := cs.Lookup(rec.Commit); !ok {
		t.Fatal("record not stored")
	}
}

func TestStateMissingWithMarkerPresentIsNotAnEmptyWallet(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
	p, m, wp := st.path, append([]byte(nil), st.st.Master...), walletPathOf(st)
	st.Close()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if s2, err := OpenStore(wp, testPass, m); err == nil {
		s2.Close()
		t.Fatal("a wallet whose .outputs vanished opened as silently empty")
	}
}

func TestResubmitWaitsForADurableState(t *testing.T) {
	d := newDuo(t, 1000)
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	resp, _ := d.r.Receive(offer)
	d.node.submitErr = errors.New("connection refused")
	if _, err := d.s.Finalize(d.node, resp); err == nil {
		t.Fatal("expected submit failure")
	}
	before := len(d.node.submits)
	d.node.submitErr = nil
	noDirRead(t, filepath.Dir(d.s.path))
	if _, err := d.s.Finalize(d.node, resp); err == nil {
		t.Fatal("resubmitted although the state could not be made durable")
	}
	if len(d.node.submits) != before {
		t.Fatal("transaction was submitted before its state was durable")
	}
}
