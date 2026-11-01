package wallet

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v2crypto "github.com/pasichDev/nosoX/v2/crypto"
	"github.com/pasichDev/nosoX/v2/types"
	"golang.org/x/crypto/chacha20poly1305"
)

// ---- helpers -----------------------------------------------------------

func dummyRecord(i int, st OutputStatus, spentTip uint64) OutputRecord {
	o := OutputRecord{Commit: fmt.Sprintf("02%064x", i), Value: 1, Blinding: make([]byte, 32), Status: st, Origin: OriginCoinbase}
	if st == StatusSpent {
		o.ChainSpent, o.SpentTip = spentTip > 0, spentTip
	}
	return o
}

func fillDummies(t *testing.T, st *Store, n int, status OutputStatus, spentTip uint64) {
	t.Helper()
	for i := 0; i < n; i++ {
		st.st.Outputs = append(st.st.Outputs, dummyRecord(1000+i, status, spentTip))
	}
	if err := st.commit(); err != nil {
		t.Fatal(err)
	}
}

func walletPathOf(st *Store) string { return st.path[:len(st.path)-len(StateSuffix)] }

func reopenErr(st *Store) (*Store, error) {
	wp, m := walletPathOf(st), append([]byte(nil), st.st.Master...)
	st.Close()
	return OpenStore(wp, testPass, m)
}

func fakeOffer(t *testing.T, i int) *Slate {
	t.Helper()
	in, _ := randomScalar()
	inb := in.Bytes()
	inC, err := v2crypto.PedersenCommit(100, inb[:])
	if err != nil {
		t.Fatal(err)
	}
	xs := in
	xs.Negate()
	Ps, _ := pointOf(&xs)
	k, _ := randomScalar()
	Rs, _ := pointOf(&k)
	var id [16]byte
	binary.BigEndian.PutUint64(id[:], uint64(i)+1)
	return &Slate{Stage: StageOffer, Magic: types.NetworkMagicTestnet, TxID: id, Amount: 99, Fee: 1, Inputs: []types.Input{{Commit: inC}}, SenderExc: Ps, SenderNon: Rs}
}

// ---- H1: the state file can never be bricked ------------------------------

func TestPayAtHardBoundFailsCleanlyAndNeverBricks(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
	fillDummies(t, st, maxLoadRecords-1, StatusSpent, 0) // spent in flight (not seen on chain): nothing may be moved out
	_, err := st.Pay(n, PayParams{Amount: 100, Fee: 1})
	if !errors.Is(err, ErrStateFull) {
		t.Fatalf("pay at the hard bound: %v, want ErrStateFull", err)
	}
	if len(st.st.Contexts) != 0 || len(n.submits) != 0 {
		t.Fatal("a failed pay left a context behind")
	}
	for _, o := range st.st.Outputs {
		if o.Status == StatusLocked {
			t.Fatal("a failed pay left an input locked")
		}
	}
	re, err := reopenErr(st)
	if err != nil {
		t.Fatalf("reopen after refused pay: %v", err)
	}
	defer re.Close()
	if len(re.st.Outputs) != maxLoadRecords {
		t.Fatalf("records %d", len(re.st.Outputs))
	}
}

func TestPayPrunesFinishedRecordsToMakeRoom(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
	fillDummies(t, st, maxOutputRecords-1, StatusSpent, 10) // seen spent at tip 10
	st.st.Tip, st.st.Synced = 10+pruneDepth, true
	if _, err := st.Pay(n, PayParams{Amount: 100, Fee: 1}); err != nil {
		t.Fatalf("pay: %v", err)
	}
	if len(st.st.Outputs) > 3 {
		t.Fatalf("finished records not pruned: %d", len(st.st.Outputs))
	}
	re, err := reopenErr(st)
	if err != nil {
		t.Fatal(err)
	}
	re.Close()
}

func TestWriteNeverProducesAFileLoadRefuses(t *testing.T) {
	st := newWalletStore(t, "a")
	for i := 0; i < maxLoadRecords+1; i++ {
		st.st.Outputs = append(st.st.Outputs, dummyRecord(i, StatusSpent, 0))
	}
	if err := st.commit(); err == nil {
		t.Fatal("write accepted a state above the load bound")
	}
	if len(st.st.Outputs) != 0 {
		t.Fatal("memory not restored after refused write")
	}
}

func TestOversizedStateFromOlderBuildOpensAndIsPruned(t *testing.T) {
	st := newWalletStore(t, "a")
	fillDummies(t, st, maxOutputRecords+50, StatusSpent, 10) // 10050 records: what the old Pay could write
	st.st.Tip = 10 + pruneDepth
	if err := st.commit(); err != nil {
		t.Fatal(err)
	}
	re, err := reopenErr(st)
	if err != nil {
		t.Fatalf("over-full state must open: %v", err)
	}
	defer re.Close()
	if len(re.st.Outputs) != 0 || len(re.st.Archive) != maxOutputRecords+50 {
		t.Fatalf("finished records must move to the archive, not vanish: live %d archived %d", len(re.st.Outputs), len(re.st.Archive))
	}
	// An over-full state with nothing final still opens (recovery), and refuses growth.
	st2 := newWalletStore(t, "b")
	fillDummies(t, st2, maxOutputRecords+50, StatusUnspent, 0)
	re2, err := reopenErr(st2)
	if err != nil {
		t.Fatalf("over-full unprunable state must open: %v", err)
	}
	defer re2.Close()
	if err := re2.roomFor(1); !errors.Is(err, ErrStateFull) {
		t.Fatalf("growth allowed: %v", err)
	}
}

func TestReceiveRationsPendingOutputs(t *testing.T) {
	old := maxPendingReceives
	maxPendingReceives = 3
	defer func() { maxPendingReceives = old }()
	rc := newWalletStore(t, "r")
	for i := 0; i < 3; i++ {
		if _, err := rc.Receive(fakeOffer(t, i)); err != nil {
			t.Fatalf("offer %d: %v", i, err)
		}
	}
	if _, err := rc.Receive(fakeOffer(t, 99)); !errors.Is(err, ErrTooManyPending) {
		t.Fatalf("fourth fake offer: %v, want ErrTooManyPending", err)
	}
}

func TestExpiredPendingReceivesAreArchivedNotDeleted(t *testing.T) {
	n := newFakeNode()
	rc := newWalletStore(t, "r")
	if _, err := rc.Receive(fakeOffer(t, 1)); err != nil {
		t.Fatal(err)
	}
	if rep, err := rc.Sync(n); err != nil || rep.Pruned != 0 || rep.Archived != 0 || len(rc.st.Outputs) != 1 {
		t.Fatalf("fresh receive archived: %+v %v", rep, err)
	}
	rc.now = func() time.Time { return time.Now().Add(pendingReceiveTTL + time.Hour) }
	rep, err := rc.Sync(n)
	if err != nil || rep.Pruned != 0 || rep.Archived != 1 || len(rc.st.Outputs) != 0 || rc.ArchivedCount() != 1 {
		t.Fatalf("expired receive not archived: %+v %v", rep, err)
	}
	if len(rc.st.Archive[0].Blinding) != 32 {
		t.Fatal("archived record lost its blinding factor")
	}
	// An archived receive still remembers its session: replaying the offer fails.
	if _, err := rc.Receive(fakeOffer(t, 1)); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay of an archived receive: %v, want ErrReplay", err)
	}
	// The archive survives a restart and does not count against the live quota.
	rc = reopen(t, rc)
	if rc.ArchivedCount() != 1 {
		t.Fatal("archive lost on reopen")
	}
	old := maxPendingReceives
	maxPendingReceives = 1
	defer func() { maxPendingReceives = old }()
	if _, err := rc.Receive(fakeOffer(t, 2)); err != nil {
		t.Fatalf("archived record counted against the live quota: %v", err)
	}
}

// A receive whose sender finalizes and mines it AFTER the 30-day expiry must
// still be spendable by the receiver: the blinding factor was never deleted.
func TestReceiveMinedAfterExpiryStaysSpendable(t *testing.T) {
	node := newFakeNode()
	sender, receiver, third := newWalletStore(t, "s"), newWalletStore(t, "r"), newWalletStore(t, "t")
	fund(t, sender, node, 1000, types.OutputFeaturesPlain, 5)
	offer, err := sender.Pay(node, PayParams{Amount: 600, Fee: 10})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := receiver.Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	// The sender signs but does not broadcast yet.
	node.submitErr = errors.New("offline")
	_, _ = sender.Finalize(node, resp)
	node.submitErr = nil

	// 31 days pass; the receiver syncs: the record is archived, not deleted.
	late := time.Now().Add(pendingReceiveTTL + 24*time.Hour)
	receiver.now = func() time.Time { return late }
	if rep, err := receiver.Sync(node); err != nil || rep.Archived != 1 || len(receiver.st.Outputs) != 0 {
		t.Fatalf("expiry: %+v %v", rep, err)
	}
	// Still unknown on chain: stays archived across further syncs and restarts.
	receiver = reopen(t, receiver)
	receiver.now = func() time.Time { return late }
	if _, err := receiver.Sync(node); err != nil || receiver.ArchivedCount() != 1 {
		t.Fatalf("archive dropped: %v", err)
	}

	// The sender finally broadcasts and the transaction is mined.
	if _, err := sender.Finalize(node, resp); err != nil {
		t.Fatal(err)
	}
	node.mine()
	rep, err := receiver.Sync(node)
	if err != nil || rep.Revived != 1 || receiver.ArchivedCount() != 0 {
		t.Fatalf("late confirmation not matched: %+v %v", rep, err)
	}
	if b := receiver.Balance(); b.Spendable != 600 {
		t.Fatalf("receiver balance %+v, want 600 spendable", b)
	}
	// And it really can be spent.
	off2, err := receiver.Pay(node, PayParams{Amount: 300, Fee: 10})
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := third.Receive(off2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Finalize(node, resp2); err != nil {
		t.Fatalf("spend of the late-confirmed receive failed: %v", err)
	}
}

func TestArchiveFullRefusesReceiveButNeverEvicts(t *testing.T) {
	rc := newWalletStore(t, "r")
	for i := 0; i < maxArchived; i++ {
		rc.st.Archive = append(rc.st.Archive, ArchivedReceive{Commit: dummyRecord(i+1, StatusPending, 0).Commit, Value: 1, Blinding: make([]byte, 32)})
	}
	if _, err := rc.Receive(fakeOffer(t, 7)); !errors.Is(err, ErrArchiveFull) {
		t.Fatalf("full archive accepted an offer: %v", err)
	}
	if len(rc.st.Archive) != maxArchived {
		t.Fatal("archive entry evicted")
	}
	// Eviction could only happen in Sync: run it with an expired live receive that
	// wants to move in, and a node that has never heard of any archived entry.
	n := newFakeNode()
	exp := dummyRecord(5000, StatusPending, 0)
	exp.Origin, exp.Created = OriginReceive, 1 // far older than pendingReceiveTTL
	rc.st.Outputs = append(rc.st.Outputs, exp)
	if err := rc.commit(); err != nil {
		t.Fatal(err)
	}
	first := rc.st.Archive[0].Commit
	if _, err := rc.Sync(n); err != nil {
		t.Fatal(err)
	}
	if len(rc.st.Archive) != maxArchived || rc.st.Archive[0].Commit != first {
		t.Fatalf("sync evicted an archived receive: %d entries", len(rc.st.Archive))
	}
	if rc.output(exp.Commit) == nil {
		t.Fatal("the live receive was dropped although the archive had no room")
	}
}

// pruneDepth is the reorg horizon for every prune of a spent record or a
// never-landed candidate; it must cover the deepest reorg consensus allows.
func TestPruneDepthCoversMaxReorg(t *testing.T) {
	if pruneDepth < types.MaxReorgBlocks {
		t.Fatalf("pruneDepth %d < MaxReorgBlocks %d: a reorg could resurrect a pruned spend", pruneDepth, types.MaxReorgBlocks)
	}
	// Behaviour at the boundary: a spend seen at height S is still live for every
	// tip a reorg of MaxReorgBlocks could produce, and only moves out (to the
	// archive, key kept) from S+pruneDepth on.
	const spentAt = 50
	for _, c := range []struct {
		tip   uint64
		moved bool
	}{
		{spentAt, false},
		{spentAt + types.MaxReorgBlocks - 1, false},
		{spentAt + pruneDepth - 1, false},
		{spentAt + pruneDepth, true},
	} {
		st := newWalletStore(t, "a")
		st.st.Outputs = append(st.st.Outputs, dummyRecord(1, StatusSpent, spentAt))
		st.pruneLocked(c.tip)
		if got := len(st.st.Outputs) == 0; got != c.moved {
			t.Fatalf("tip %d: moved=%v, want %v", c.tip, got, c.moved)
		}
		if c.moved && !st.archived(dummyRecord(1, StatusSpent, spentAt).Commit) {
			t.Fatal("a pruned spend was not archived")
		}
	}
}

func TestStaleCoinbaseCandidatesAreDropped(t *testing.T) {
	n := newFakeNode()
	n.tip = 5000
	st := newWalletStore(t, "a")
	old, recent := dummyRecord(1, StatusPending, 0), dummyRecord(2, StatusPending, 0)
	old.Height, recent.Height = 10, 4990
	st.st.Outputs = append(st.st.Outputs, old, recent)
	if err := st.commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	if len(st.st.Outputs) != 1 || st.st.Outputs[0].Height != 4990 {
		t.Fatalf("outputs after sync: %+v", st.st.Outputs)
	}
}

func TestSyncDoesNotQueryFinalSpends(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	done, live := dummyRecord(1, StatusSpent, 10), dummyRecord(2, StatusUnspent, 0)
	st.st.Outputs = append(st.st.Outputs, done, live)
	st.st.Tip, st.st.Synced = 10+pruneDepth, true
	if err := st.commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	dc, _ := parseCommit(done.Commit)
	lc, _ := parseCommit(live.Commit)
	if n.queried[dc] != 0 {
		t.Fatalf("a final spent output was queried %d times", n.queried[dc])
	}
	if n.queried[lc] != 1 {
		t.Fatalf("a live output was queried %d times", n.queried[lc])
	}
}

// ---- reorg handling (M1, L1, L2) ----------------------------------------

func TestReorgKeepsAnInputReservedByALivePayment(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	c := fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
	if _, err := st.Pay(n, PayParams{Amount: 100, Fee: 1}); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	delete(n.utxo, c)
	n.blocks[5] = "other"
	n.mu.Unlock()
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	n.utxo[c] = UTXOInfo{Present: true, Height: 6, BlockHash: "other2"}
	n.blocks[6] = "other2"
	n.mu.Unlock()
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	if r := st.output(commitHex(c)); r.Status != StatusLocked || r.LockedBy == "" {
		t.Fatalf("input released: status=%s lockedBy=%q", r.Status, r.LockedBy)
	}
	if _, err := st.Pay(n, PayParams{Amount: 200, Fee: 1}); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("second pay selected a reserved input: %v", err)
	}
}

func TestCancelAfterReorgDoesNotMarkMissingInputSpent(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	c := fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
	offer, err := st.Pay(n, PayParams{Amount: 100, Fee: 1})
	if err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	delete(n.utxo, c)
	n.blocks[5] = "other"
	n.mu.Unlock()
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	if err := st.Cancel(fmt.Sprintf("%x", offer.TxID), false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	if r := st.output(commitHex(c)); r.Status != StatusPending {
		t.Fatalf("input that is not on chain is %s, want pending", r.Status)
	}
}

func TestPrunedSentTxDoesNotStrandAnInputAfterReorg(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	rc := newWalletStore(t, "b")
	c := fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
	offer, _ := st.Pay(n, PayParams{Amount: 100, Fee: 1})
	resp, _ := rc.Receive(offer)
	if _, err := st.Finalize(n, resp); err != nil {
		t.Fatal(err)
	}
	tx, _ := DecodeTx(st.st.Sent[0].Tx)
	n.mine()
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	if !st.pruneSent() {
		t.Fatal("prune")
	}
	if err := st.commit(); err != nil {
		t.Fatal(err)
	}
	n.reorgOut(tx)
	n.mu.Lock()
	n.pool = map[types.Hash][]byte{}
	n.blocks[5] = fmt.Sprintf("%064x", 5)
	n.mu.Unlock()
	for i := 0; i < 2; i++ {
		if _, err := st.Sync(n); err != nil {
			t.Fatal(err)
		}
	}
	if r := st.output(commitHex(c)); r.Status != StatusUnspent {
		t.Fatalf("input stuck as %s lockedBy=%s", r.Status, r.LockedBy)
	}
}

func TestSpentInputWhoseCreatingBlockLeftIsNotMarkedChainSpent(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	rc := newWalletStore(t, "b")
	c := fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
	offer, _ := st.Pay(n, PayParams{Amount: 100, Fee: 1})
	resp, _ := rc.Receive(offer)
	if _, err := st.Finalize(n, resp); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	delete(n.utxo, c)
	n.blocks[5] = "other" // the block that created the input is gone; the tx was never mined
	n.mu.Unlock()
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	if r := st.output(commitHex(c)); r.ChainSpent {
		t.Fatal("a vanished creating block was taken for a confirmed spend")
	}
	if st.sentConfirmedLocked(&st.st.Sent[0]) {
		t.Fatal("tx reported confirmed")
	}
}

// ---- M2/M8 ---------------------------------------------------------------

func TestWalletCreateNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "w.json")
	w1, _ := NewRandom()
	defer w1.Close()
	if err := w1.Create(p, testPass); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(p)
	w2, _ := NewRandom()
	defer w2.Close()
	if err := w2.Create(p, testPass); err == nil {
		t.Fatal("second Create overwrote the wallet")
	}
	if now, _ := os.ReadFile(p); string(now) != string(orig) {
		t.Fatal("wallet file changed")
	}
	// A leftover state file also blocks creation at that path.
	p2 := filepath.Join(dir, "w2.json")
	if err := os.WriteFile(StatePath(p2), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w2.Create(p2, testPass); err == nil {
		t.Fatal("created over an existing state file")
	}
	if err := w2.Create(filepath.Join(dir, "w3.json"), "short"); err == nil {
		t.Fatal("weak passphrase accepted")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".wallet-*")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

// ---- M3: rollback ----------------------------------------------------------

func TestRestoredBackupCannotSignASecondTransactionWithTheSameNonce(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
	offer, err := st.Pay(n, PayParams{Amount: 100, Fee: 1})
	if err != nil {
		t.Fatal(err)
	}
	backup, _ := os.ReadFile(st.path)
	r1, r2 := newWalletStore(t, "r1"), newWalletStore(t, "r2")
	resp1, err := r1.Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := r2.Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Finalize(n, resp1); err != nil {
		t.Fatal(err)
	}
	p, m := st.path, append([]byte(nil), st.st.Master...)
	wp := walletPathOf(st)
	st.Close()
	if err := os.WriteFile(p, backup, 0o600); err != nil { // the attacker restores the old state
		t.Fatal(err)
	}
	st2, err := OpenStore(wp, testPass, m)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if _, err := st2.Finalize(n, resp2); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("finalize on a rolled-back state: %v, want ErrRolledBack", err)
	}
	if len(st2.st.Sent) != 0 {
		t.Fatal("a second signature was produced")
	}
	// The suspect marker survives a restart; cancelling clears it and frees the inputs.
	st3, err := reopenErr(st2)
	if err != nil {
		t.Fatal(err)
	}
	defer st3.Close()
	if _, err := st3.Finalize(n, resp2); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("after restart: %v", err)
	}
	if err := st3.Cancel(fmt.Sprintf("%x", offer.TxID), false); err != nil {
		t.Fatal(err)
	}
	if len(st3.st.Suspect) != 0 {
		t.Fatal("suspect marker not cleared by cancel")
	}
	// The transaction was signed in the timeline that was rolled back: its change
	// is real money if it was mined, so cancel must keep the key.
	var kept bool
	for _, a := range st3.st.Archive {
		if a.Reason == archReasonChange && a.Value == 899 && len(a.Blinding) == 32 && !bytes.Equal(a.Blinding, make([]byte, 32)) {
			kept = true
		}
	}
	if !kept {
		t.Fatal("cancel after a restored backup destroyed the change key")
	}
}

func TestNormalUseNeverLooksLikeARollback(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
	if _, err := st.Pay(n, PayParams{Amount: 100, Fee: 1}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		var err error
		if st, err = reopenErr(st); err != nil {
			t.Fatal(err)
		}
		if len(st.st.Suspect) != 0 {
			t.Fatal("false rollback detection after a clean restart")
		}
	}
	defer st.Close()
	// A crash between the state rename and the marker write leaves the marker one behind: not a rollback.
	g := st.st.Gen
	body, _ := json.Marshal(genFile{Gen: g - 1})
	_ = body
	if err := (&Store{key: st.key, st: walletState{Gen: g - 1}, path: st.path}).writeGen(); err != nil {
		t.Fatal(err)
	}
	st4, err := reopenErr(st)
	if err != nil {
		t.Fatal(err)
	}
	defer st4.Close()
	if len(st4.st.Suspect) != 0 {
		t.Fatal("marker behind the state treated as rollback")
	}
}

func TestMissingOrForgedMarkerMakesLiveContextsSuspect(t *testing.T) {
	for _, how := range []string{"missing", "forged"} {
		t.Run(how, func(t *testing.T) {
			n := newFakeNode()
			st := newWalletStore(t, "a")
			fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
			if _, err := st.Pay(n, PayParams{Amount: 100, Fee: 1}); err != nil {
				t.Fatal(err)
			}
			if how == "missing" {
				os.Remove(st.genPath())
			} else {
				os.WriteFile(st.genPath(), []byte(`{"gen":1,"mac":"00"}`), 0o600)
			}
			re, err := reopenErr(st)
			if err != nil {
				t.Fatal(err)
			}
			defer re.Close()
			if len(re.st.Suspect) != 1 {
				t.Fatalf("suspect %v", re.st.Suspect)
			}
		})
	}
}

func TestSenderNonceIsDerivedFromSecretContextAndFreshRandomness(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	xs, _ := randomScalar()
	ctx := []byte("context")
	a, err := deriveNonce(key, &xs, ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := deriveNonce(key, &xs, ctx)
	if a.Equals(&b) {
		t.Fatal("same context produced the same nonce twice (fresh randomness missing)")
	}
	if a.IsZero() {
		t.Fatal("zero nonce")
	}
}

// ---- M5/L8: envelope -----------------------------------------------------

func TestProductionKDFIsStrong(t *testing.T) {
	if productionKDF.T < 3 || productionKDF.MemKiB < 256*1024 || productionKDF.P < 1 {
		t.Fatalf("production KDF too weak: %+v", productionKDF)
	}
	if kdfFloor.T > productionKDF.T {
		t.Fatal("floor above default")
	}
}

func readEnv(t *testing.T, p string) Encrypted {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var e Encrypted
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEnvelopeStoresAndAuthenticatesKDFParameters(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "w.json")
	w, _ := NewRandom()
	defer w.Close()
	if err := w.Create(p, testPass); err != nil {
		t.Fatal(err)
	}
	e := readEnv(t, p)
	if e.Version != envelopeV2 || e.KDF == nil || *e.KDF != kdfDefault {
		t.Fatalf("envelope: %+v", e)
	}
	// Altering a stored parameter (even to a legal value) breaks authentication.
	e.KDF.T++
	b, _ := json.Marshal(e)
	os.WriteFile(p, b, 0o600)
	if _, err := Load(p, testPass); err == nil {
		t.Fatal("tampered parameters accepted")
	}
	// Out-of-range parameters are refused before any derivation (no 64 GiB demands).
	e.KDF.T, e.KDF.MemKiB = kdfDefault.T, 64<<20
	b, _ = json.Marshal(e)
	os.WriteFile(p, b, 0o600)
	if _, err := Load(p, testPass); err == nil || !strings.Contains(err.Error(), "range") {
		t.Fatalf("huge memory parameter: %v", err)
	}
	// Weaker than the floor is refused.
	old := kdfFloor
	kdfFloor = KDFParams{T: 3, MemKiB: 256 * 1024, P: 1}
	defer func() { kdfFloor = old }()
	e.KDF = &KDFParams{T: 1, MemKiB: 64, P: 1}
	b, _ = json.Marshal(e)
	os.WriteFile(p, b, 0o600)
	if _, err := Load(p, testPass); err == nil || !strings.Contains(err.Error(), "weaker") {
		t.Fatalf("weak parameters: %v", err)
	}
}

func TestEnvelopeBindsKeystoreAndStateTogetherWithTheirLabel(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "w.json")
	w, _ := NewRandom()
	defer w.Close()
	if err := w.Create(p, testPass); err != nil {
		t.Fatal(err)
	}
	st, err := OpenStore(p, testPass, w.MasterPublic())
	if err != nil {
		t.Fatal(err)
	}
	st.st.Magic = types.NetworkMagicTestnet
	if err := st.commit(); err != nil {
		t.Fatal(err)
	}
	st.Close()
	// Swapping the two files must not decrypt.
	ks, _ := os.ReadFile(p)
	state, _ := os.ReadFile(StatePath(p))
	os.WriteFile(p, state, 0o600)
	if _, err := Load(p, testPass); err == nil {
		t.Fatal("state file accepted as a keystore")
	}
	os.WriteFile(p, ks, 0o600)
	os.WriteFile(StatePath(p), ks, 0o600)
	if _, err := OpenStore(p, testPass, w.MasterPublic()); err == nil {
		t.Fatal("keystore accepted as a state file")
	}
}

func TestPassphrasePolicyAppliesToNewWalletsOnly(t *testing.T) {
	for _, bad := range []string{"", "short", "elevenchars"} {
		if ValidatePassphrase(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if ValidatePassphrase("twelve chars") != nil || ValidatePassphrase("парольпарольпароль") != nil {
		t.Error("valid passphrase refused")
	}
	// An existing short-passphrase wallet still opens (version 1 file, short passphrase).
	p := filepath.Join(t.TempDir(), "old.json")
	w, _ := NewRandom()
	defer w.Close()
	writeV1Keystore(t, p, w, "pw")
	got, err := Load(p, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if !got.Legacy {
		t.Fatal("v1 file not flagged")
	}
	if err := got.Upgrade(p, "pw"); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if e := readEnv(t, p); e.Version != envelopeV2 || e.KDF == nil {
		t.Fatalf("not upgraded: %+v", e)
	}
	again, err := Load(p, "pw")
	if err != nil || again.Legacy {
		t.Fatalf("reload upgraded: %v", err)
	}
	again.Close()
}

func writeV1Keystore(t *testing.T, path string, w *Wallet, pass string) {
	t.Helper()
	plain, _ := json.Marshal(plainView{MasterSeedB64: base64.StdEncoding.EncodeToString(w.Master.Seed())})
	salt := make([]byte, 16)
	rand.Read(salt)
	key := deriveKey(pass, salt, legacyKDF)
	aead, _ := chacha20poly1305.NewX(key)
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	body, _ := json.Marshal(Encrypted{Version: envelopeV1, Salt: base64.StdEncoding.EncodeToString(salt), Nonce: base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, nil))})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVersion1StateFileIsMigrated(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "w.json")
	w, _ := NewRandom()
	defer w.Close()
	writeV1Keystore(t, p, w, testPass)
	// A version 1 state file: legacy KDF, legacy AAD, state version 1.
	rec := dummyRecord(7, StatusUnspent, 0)
	plain, _ := json.Marshal(walletState{Version: 1, Master: w.MasterPublic(), Outputs: []OutputRecord{rec}})
	salt := make([]byte, 16)
	rand.Read(salt)
	key := deriveKey(testPass, salt, legacyKDF)
	aead, _ := chacha20poly1305.NewX(key)
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	body, _ := json.Marshal(Encrypted{Version: envelopeV1, Salt: base64.StdEncoding.EncodeToString(salt), Nonce: base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, []byte(legacyStateAAD)))})
	if err := os.WriteFile(StatePath(p), body, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := OpenStore(p, testPass, w.MasterPublic())
	if err != nil {
		t.Fatalf("open v1 state: %v", err)
	}
	if len(st.st.Outputs) != 1 {
		t.Fatal("record lost in migration")
	}
	st.Close()
	if e := readEnv(t, StatePath(p)); e.Version != envelopeV2 || e.KDF == nil || e.Salt == base64.StdEncoding.EncodeToString(salt) {
		t.Fatalf("state not rewritten as v2 with a fresh salt: %+v", e)
	}
	again, err := OpenStore(p, testPass, w.MasterPublic())
	if err != nil || len(again.st.Outputs) != 1 {
		t.Fatalf("reopen migrated state: %v", err)
	}
	again.Close()
}

// ---- M7: confirmation depth, transport -----------------------------------

func TestConfirmationDepthIsRequired(t *testing.T) {
	d := newDuo(t, 1000)
	if err := d.r.SetMinConfirmations(0); err == nil {
		t.Fatal("zero depth accepted")
	}
	if err := d.r.SetMinConfirmations(5); err != nil {
		t.Fatal(err)
	}
	if err := d.s.SetMinConfirmations(5); err != nil {
		t.Fatal(err)
	}
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	resp, _ := d.r.Receive(offer)
	if _, err := d.s.Finalize(d.node, resp); err != nil {
		t.Fatal(err)
	}
	d.node.mine() // the payment is in a block: depth 1
	rep, err := d.r.Sync(d.node)
	if err != nil || rep.Confirmed != 0 || rep.Shallow != 1 || d.r.Balance().Pending != 600 {
		t.Fatalf("depth 1 counted as confirmed: %+v %v %+v", rep, err, d.r.Balance())
	}
	for i := 0; i < 3; i++ {
		d.node.mine()
	}
	if rep, _ = d.r.Sync(d.node); rep.Confirmed != 0 {
		t.Fatalf("depth 4 counted as confirmed: %+v", rep)
	}
	d.node.mine() // depth 5
	if rep, _ = d.r.Sync(d.node); rep.Confirmed != 1 || d.r.Balance().Spendable != 600 {
		t.Fatalf("depth 5 not confirmed: %+v %+v", rep, d.r.Balance())
	}
}

func TestShallowOutputsAreNotSpent(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	if err := st.SetMinConfirmations(10); err != nil {
		t.Fatal(err)
	}
	fund(t, st, n, 1000, types.OutputFeaturesPlain, n.tip-3) // 4 blocks deep
	if _, err := st.Pay(n, PayParams{Amount: 100, Fee: 1}); !errors.Is(err, ErrInsufficientFunds) || !strings.Contains(err.Error(), "deep") {
		t.Fatalf("pay with a shallow output: %v", err)
	}
}

func TestNodeAddressMustBeHTTPSOrLoopback(t *testing.T) {
	for _, a := range []string{"http://node.example.org:7780", "node.example.org:7780", "http://10.1.2.3:7780", "http://[2001:db8::1]:7780"} {
		if _, err := NewRPCNode(a, ""); err == nil {
			t.Errorf("%s accepted without a token", a)
		}
		if _, err := NewRPCNode(a, "tok"); err == nil {
			t.Errorf("%s accepted with a token", a)
		}
	}
	for _, a := range []string{"https://node.example.org", "127.0.0.1:7780", "http://localhost:7780", "http://[::1]:7780"} {
		if _, err := NewRPCNode(a, ""); err != nil {
			t.Errorf("%s refused: %v", a, err)
		}
	}
}

func TestClientRetriesWhenThrottled(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32021,"message":"Rate limit exceeded"},"id":1}`))
			return
		}
		w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","id":1}`))
	}))
	defer srv.Close()
	n, err := NewRPCNode(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Call("version", nil); err != nil || calls.Load() != 3 {
		t.Fatalf("calls=%d err=%v", calls.Load(), err)
	}
}

func TestTransientNodeRefusalIsNotAFinalRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32011,"message":"retry later"},"id":1}`))
	}))
	defer srv.Close()
	n, _ := NewRPCNode(srv.URL, "")
	d := newDuo(t, 1000)
	_ = d
	err := n.Submit(&types.Transaction{Inputs: []types.Input{{}}, Outputs: []types.Output{{}}, Kernels: []types.Kernel{{ExcessSig: make([]byte, 65)}}})
	if errors.Is(err, ErrRejected) {
		t.Fatalf("a transient refusal was reported as a rejection: %v", err)
	}
}

// ---- F8: network binding ---------------------------------------------------

func TestKernelSignatureIsBoundToTheNetwork(t *testing.T) {
	d := newDuo(t, 1000)
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	if offer.Magic != types.NetworkMagicTestnet {
		t.Fatalf("slate magic %08x", offer.Magic)
	}
	resp, _ := d.r.Receive(offer)
	if _, err := d.s.Finalize(d.node, resp); err != nil {
		t.Fatal(err)
	}
	tx, _ := DecodeTx(d.node.submits[0])
	k := tx.Kernels[0]
	if !v2crypto.SchnorrVerify(k.Excess, types.KernelSigningMessage(types.NetworkMagicTestnet, &k), k.ExcessSig) {
		t.Fatal("does not verify on its own network")
	}
	if v2crypto.SchnorrVerify(k.Excess, types.KernelSigningMessage(types.NetworkMagicMainnet, &k), k.ExcessSig) {
		t.Fatal("verifies on another network: replayable")
	}
	id := types.KernelID(&k)
	if v2crypto.SchnorrVerify(k.Excess, id[:], k.ExcessSig) {
		t.Fatal("still verifies under the unbound kernel id")
	}
}

func TestSlatesOfAnotherNetworkAreRefused(t *testing.T) {
	d := newDuo(t, 1000)
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	foreign := *offer
	foreign.Magic = types.NetworkMagicMainnet
	if _, err := d.r.Receive(&foreign); !errors.Is(err, ErrNetwork) {
		t.Fatalf("receive of a foreign slate: %v", err)
	}
	resp, err := d.r.Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	other := newFakeNode()
	other.magic = types.NetworkMagicMainnet
	if _, err := d.s.Finalize(other, resp); !errors.Is(err, ErrNetwork) {
		t.Fatalf("finalize against another network: %v", err)
	}
	if len(d.s.st.Sent) != 0 {
		t.Fatal("signed for the wrong network")
	}
	// A wallet is pinned to the first network it sees.
	if _, err := d.s.Pay(other, PayParams{Amount: 1, Fee: 1}); !errors.Is(err, ErrNetwork) {
		t.Fatalf("pay on a second network: %v", err)
	}
	// An unpinned wallet cannot judge a slate and refuses.
	w, _ := NewRandom()
	defer w.Close()
	p := filepath.Join(t.TempDir(), "x.json")
	w.Create(p, testPass)
	fresh, _ := OpenStore(p, testPass, w.MasterPublic())
	defer fresh.Close()
	if _, err := fresh.Receive(offer); err == nil {
		t.Fatal("unpinned wallet accepted a slate")
	}
}

// keep imports honest
var _ = big.NewInt

// The file the old build actually bricked: a version 1 envelope holding state
// version 1 with 10001 records. It must open (migrating to v2) and stay usable.
func TestBrickedVersion1StateWith10001RecordsOpens(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "w.json")
	w, _ := NewRandom()
	defer w.Close()
	writeV1Keystore(t, p, w, testPass)
	var recs []OutputRecord
	for i := 0; i < maxOutputRecords+1; i++ {
		recs = append(recs, dummyRecord(i, StatusSpent, 5))
	}
	plain, _ := json.Marshal(walletState{Version: 1, Master: w.MasterPublic(), Outputs: recs, Tip: 5 + pruneDepth})
	salt := make([]byte, 16)
	rand.Read(salt)
	aead, _ := chacha20poly1305.NewX(deriveKey(testPass, salt, legacyKDF))
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	body, _ := json.Marshal(Encrypted{Version: envelopeV1, Salt: base64.StdEncoding.EncodeToString(salt), Nonce: base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, []byte(legacyStateAAD)))})
	if err := os.WriteFile(StatePath(p), body, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := OpenStore(p, testPass, w.MasterPublic())
	if err != nil {
		t.Fatalf("bricked state does not open: %v", err)
	}
	defer st.Close()
	if len(st.st.Outputs) != 0 {
		t.Fatalf("finished records kept: %d", len(st.st.Outputs))
	}
}
