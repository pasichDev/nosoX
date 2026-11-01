package wallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pasichDev/nosoX/v2/types"
)

// ---- production defaults (TestMain lowers them for speed) ------------------

func TestProductionDefaultsAreStrong(t *testing.T) {
	if DefaultMinConfirmations != 10 || prodDefaultMinConfirmations != 10 {
		t.Fatalf("default confirmation depth %d / %d, want 10", DefaultMinConfirmations, prodDefaultMinConfirmations)
	}
	if prodKDFDefault.T < 3 || prodKDFDefault.MemKiB < 256*1024 || prodKDFDefault.P < 4 {
		t.Fatalf("production KDF default too weak: %+v", prodKDFDefault)
	}
	if prodKDFFloor.T < 3 || prodKDFFloor.MemKiB < 256*1024 || prodKDFFloor.P < 1 {
		t.Fatalf("KDF floor too weak: %+v", prodKDFFloor)
	}
	// The floor really rejects a weak file (TestMain lowered the live floor, so
	// check the production floor against the validator's own comparison).
	// Behavioural: with the production floor in place, the v1 parameters and a
	// single pass are refused, the production parameters accepted.
	saved := kdfFloor
	kdfFloor = prodKDFFloor
	defer func() { kdfFloor = saved }()
	for _, weak := range []KDFParams{{T: 1, MemKiB: 64 * 1024, P: 1}, {T: 3, MemKiB: 64 * 1024, P: 4}, {T: 2, MemKiB: 256 * 1024, P: 4}} {
		if err := weak.validate(); err == nil {
			t.Fatalf("%+v passed the production floor", weak)
		}
	}
	if err := prodKDFDefault.validate(); err != nil {
		t.Fatalf("production parameters refused: %v", err)
	}
	if prodKDFFloor.T > prodKDFDefault.T || prodKDFFloor.MemKiB > prodKDFDefault.MemKiB {
		t.Fatal("floor above default")
	}
}

// ---- item 1 ----------------------------------------------------------------

type tipNode struct {
	*fakeNode
	tip func() uint64
	hit int
}

func (l *tipNode) UTXO(c types.Commitment) (UTXOInfo, error) {
	info, _ := l.fakeNode.UTXO(c)
	l.hit++
	info.Tip = l.tip()
	return info, nil
}

// A retired coinbase comes back as a coinbase with its claimed height, not as a
// receive (a receive would later expire into the receive quota).
func TestRevivedCoinbaseKeepsItsOriginAndHeight(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	clock := time.Unix(1_800_000_000, 0)
	st.now = func() time.Time { return clock }
	cb := importedCoinbase(t, st, n, 500, 7)
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	for _, tip := range []uint64{5000, 5000 + pruneDepth + 10} { // marked spent, then buried
		clock = clock.Add(24 * time.Hour)
		if _, err := st.Sync(&liarNode{fakeNode: n, tip: tip}); err != nil {
			t.Fatal(err)
		}
	}
	if !st.archived(cb) {
		t.Fatal("setup: the coinbase was not archived")
	}
	if a := st.st.Archive[0]; a.Origin != OriginCoinbase || a.Height != 7 || a.Reason == "" || a.Features != uint8(types.OutputFeaturesCoinbase) {
		t.Fatalf("archive entry %+v", a)
	}
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	if o := st.output(cb); o == nil || o.Origin != OriginCoinbase || o.Height != 7 || o.Features != uint8(types.OutputFeaturesCoinbase) {
		t.Fatalf("revived: %+v", o)
	}
	if st.receiveArchived() != 0 {
		t.Fatal("a retired key leaked into the receive section")
	}
}

// The lies also reach the reorg branch: "absent" plus "no block at that height".
type noBlockNode struct{ *liarNode }

func (noBlockNode) BlockHash(uint64) (string, bool, error) { return "", false, nil }

func TestLiarDenyingBlocksDestroysNoKeys(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	clock := time.Unix(1_800_000_000, 0)
	st.now = func() time.Time { return clock }
	a := commitHex(fund(t, st, n, 700, types.OutputFeaturesPlain, 5))
	cb := importedCoinbase(t, st, n, 500, 7)
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	tip := n.tip
	for i := 0; i < 4; i++ {
		clock = clock.Add(24 * time.Hour)
		tip += 8640 + 32
		if _, err := st.Sync(noBlockNode{&liarNode{fakeNode: n, tip: tip}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range []string{a, cb} {
		if !holdsKey(st, h) {
			t.Fatalf("%s... destroyed", h[:12])
		}
	}
	clock = clock.Add(time.Hour)
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pay(n, PayParams{Amount: 1100, Fee: 1}); err != nil {
		t.Fatalf("not spendable after the honest node returned: %v", err)
	}
}

func TestTipRiseIsBoundedByElapsedTime(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	clock := time.Unix(1_800_000_000, 0)
	st.now = func() time.Time { return clock }
	fund(t, st, n, 700, types.OutputFeaturesPlain, 5)
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	if st.st.SyncedAt != clock.Unix() {
		t.Fatalf("SyncedAt %d", st.st.SyncedAt)
	}
	clock = clock.Add(24 * time.Hour)
	if _, err := st.Sync(&tipNode{fakeNode: n, tip: func() uint64 { return 100 + 2*8640 }}); !errors.Is(err, ErrTipJump) {
		t.Fatalf("two days of blocks in one day: %v", err)
	}
	if _, err := st.Sync(&tipNode{fakeNode: n, tip: func() uint64 { return 100 + 8640 + tipAllowanceSlack }}); err != nil {
		t.Fatalf("exactly what a day allows: %v", err)
	}
}

func TestImplausibleTipIsRefusedEvenOnTheFirstSync(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	fund(t, st, n, 700, types.OutputFeaturesPlain, 5)
	for _, tip := range []uint64{math.MaxUint64, math.MaxUint64 - 3, 1 << 50} {
		_, err := st.Sync(&liarNode{fakeNode: n, tip: tip})
		var te *TipError
		if !errors.As(err, &te) || !errors.Is(err, ErrTipImplausible) {
			t.Fatalf("tip %d: %v", tip, err)
		}
	}
	if st.st.Synced || st.st.Tip != 0 || st.output(st.st.Outputs[0].Commit).Status != StatusUnspent {
		t.Fatalf("a refused sync changed the state: %+v", st.st.Outputs[0])
	}
}

func TestTipJumpNeedsExplicitConfirmationAndFallingIsAccepted(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	clock := time.Unix(1_800_000_000, 0)
	st.now = func() time.Time { return clock }
	fund(t, st, n, 700, types.OutputFeaturesPlain, 5)
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	jump := &tipNode{fakeNode: n, tip: func() uint64 { return 300_000 }}
	_, err := st.Sync(jump)
	var te *TipError
	if !errors.As(err, &te) || !errors.Is(err, ErrTipJump) || !strings.Contains(err.Error(), "--accept-tip 300000") {
		t.Fatalf("jump: %v", err)
	}
	if st.st.Tip != n.tip {
		t.Fatal("a refused jump moved the stored tip")
	}
	if _, err := st.SyncWith(jump, SyncOptions{AcceptTip: 12345}); !errors.Is(err, ErrTipJump) {
		t.Fatalf("a wrong confirmation was accepted: %v", err)
	}
	if _, err := st.SyncWith(jump, SyncOptions{AcceptTip: 300_000}); err != nil {
		t.Fatalf("confirmed jump: %v", err)
	}
	// Time alone also lifts the bound: a day of chain time allows its blocks.
	clock = clock.Add(24 * time.Hour)
	up := &tipNode{fakeNode: n, tip: func() uint64 { return 300_000 + 8000 }}
	if _, err := st.Sync(up); err != nil {
		t.Fatalf("a day of blocks: %v", err)
	}
	// A correct node returning with a lower tip is accepted without ceremony.
	if _, err := st.Sync(n); err != nil {
		t.Fatalf("falling tip refused: %v", err)
	}
	if st.st.Tip != n.tip {
		t.Fatalf("tip %d", st.st.Tip)
	}
}

func TestInconsistentTipsInOneSyncAreRefused(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	fund(t, st, n, 700, types.OutputFeaturesPlain, 5)
	fund(t, st, n, 300, types.OutputFeaturesPlain, 6)
	calls := 0
	jit := &tipNode{fakeNode: n, tip: func() uint64 { calls++; return 100 + uint64(calls)*1000 }}
	if _, err := st.Sync(jit); !errors.Is(err, ErrTipInconsistent) {
		t.Fatalf("%v", err)
	}
}

func TestPresentOutputAboveTheReportedTipIsInconsistent(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	fund(t, st, n, 700, types.OutputFeaturesPlain, 500) // created at height 500, node tip 100
	if _, err := st.Sync(n); !errors.Is(err, ErrTipInconsistent) {
		t.Fatalf("%v", err)
	}
}

func TestStateWithAnAbsurdTipFromAnOlderBuildRecovers(t *testing.T) {
	st := newWalletStore(t, "a")
	o := dummyRecord(1, StatusSpent, 5)
	st.st.Outputs = append(st.st.Outputs, o)
	st.st.Tip, st.st.Synced = math.MaxUint64-2, true
	if err := st.commit(); err != nil {
		t.Fatal(err)
	}
	re, err := reopenErr(st)
	if err != nil {
		t.Fatal(err)
	}
	defer re.Close()
	if re.st.Synced || re.st.Tip != 0 || len(re.st.Outputs) != 1 || re.st.Outputs[0].SpentTip != 0 {
		t.Fatalf("poisoned tip not cleared: tip %d synced %v outputs %d", re.st.Tip, re.st.Synced, len(re.st.Outputs))
	}
}

func TestArchivedSpentKeyComesBackWhenACorrectNodeReturns(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	clock := time.Unix(1_800_000_000, 0)
	st.now = func() time.Time { return clock }
	c := fund(t, st, n, 700, types.OutputFeaturesPlain, 5)
	h := commitHex(c)
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	// A liar says "spent" at a tip, then again a long (local) time later.
	clock = clock.Add(24 * time.Hour)
	l1 := &liarNode{fakeNode: n, tip: 5000}
	if _, err := st.Sync(l1); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * 24 * time.Hour)
	l2 := &liarNode{fakeNode: n, tip: 5000 + pruneDepth + 10}
	rep, err := st.Sync(l2)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Pruned != 1 || st.output(h) != nil || !st.archived(h) {
		t.Fatalf("expected the spend to move to the archive: %+v live=%v", rep, st.output(h) != nil)
	}
	rep, err = st.Sync(n)
	if err != nil || rep.Revived != 1 {
		t.Fatalf("revive: %+v %v", rep, err)
	}
	if o := st.output(h); o == nil || o.Status != StatusUnspent || o.Origin != OriginReceive || o.Features != uint8(types.OutputFeaturesPlain) {
		t.Fatalf("revived record: %+v", o)
	}
	if st.archived(h) {
		t.Fatal("the revived key is still archived")
	}
	if _, err := st.Pay(n, PayParams{Amount: 600, Fee: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestRetiredArchiveEvictsOnlyByLocalAgeAndNeverRefusesPay(t *testing.T) {
	st := newWalletStore(t, "a")
	clock := time.Unix(1_800_000_000, 0)
	st.now = func() time.Time { return clock }
	for i := 0; i < maxRetired; i++ {
		st.st.Archive = append(st.st.Archive, ArchivedReceive{Commit: dummyRecord(i+1, StatusSpent, 1).Commit, Value: 1,
			Blinding: bytes.Repeat([]byte{1}, 32), Reason: archReasonSpent, Archived: clock.Unix() - 3600})
	}
	o := dummyRecord(900000, StatusSpent, 1)
	o.Blinding = bytes.Repeat([]byte{2}, 32)
	if st.archiveOutput(&o, archReasonSpent) {
		t.Fatal("a fresh entry was evicted to make room")
	}
	clock = clock.Add(retiredRetention + time.Hour)
	if !st.archiveOutput(&o, archReasonSpent) {
		t.Fatal("an entry past the retention window was not evictable")
	}
	if len(st.st.Archive) != maxRetired {
		t.Fatalf("archive grew past its bound: %d", len(st.st.Archive))
	}
	if st.receiveArchived() != 0 {
		t.Fatal("retired entries count against the receive quota")
	}
	// The receive quota is untouched: a full retired section never refuses Receive.
	if _, err := st.Receive(fakeOffer(t, 7)); err != nil {
		t.Fatalf("retired entries blocked a receive: %v", err)
	}
}

// ---- item 2 ----------------------------------------------------------------

// Records at their widest, every list at its bound: the file must still be
// written and reopened. The byte bound, not the counts, is what limits a wallet.
func TestWorstCaseStateFitsTheByteBound(t *testing.T) {
	st := newWalletStore(t, "a")
	wide := func(i int) string { return fmt.Sprintf("02%064x", i) }
	blind := bytes.Repeat([]byte{0xfe}, 32)
	st.st.Outputs = nil
	for i := 0; i < maxLoadRecords; i++ {
		st.st.Outputs = append(st.st.Outputs, OutputRecord{Commit: wide(i + 1), Value: math.MaxInt64, Blinding: blind, Features: 255,
			Status: StatusUnspent, Origin: OriginCoinbase, Height: math.MaxUint64, MaturesAt: math.MaxUint64,
			TxID: strings.Repeat("f", 32), LockedBy: strings.Repeat("f", 32), BlockHash: strings.Repeat("f", 64),
			ChainSpent: true, SpentTip: math.MaxUint64, Created: math.MaxInt64})
	}
	n := len(st.st.Outputs)
	for i := 0; i < maxArchived+maxRetired; i++ {
		a := ArchivedReceive{Commit: wide(n + i + 1), Value: math.MaxInt64, Blinding: blind, TxID: strings.Repeat("f", 32), Created: math.MaxInt64}
		if i >= maxArchived {
			a.Origin, a.Features, a.Height, a.Reason, a.Archived = OriginCoinbase, 255, math.MaxUint64, archReasonCandidate, math.MaxInt64
		}
		st.st.Archive = append(st.st.Archive, a)
	}
	for i := 0; i < maxSentTxs; i++ {
		st.st.Sent = append(st.st.Sent, SentTx{TxID: strings.Repeat("e", 32), Tx: bytes.Repeat([]byte{0xff}, 30000),
			Resp: strings.Repeat("f", 64), Inputs: []string{wide(1), wide(2), wide(3), wide(4)}, Submitted: true, Created: math.MaxInt64})
	}
	for i := 0; i < maxContexts; i++ {
		st.st.Contexts = append(st.st.Contexts, TxContext{TxID: strings.Repeat("d", 32), Offer: bytes.Repeat([]byte{0xff}, 20000),
			XS: blind, KS: blind, Created: math.MaxInt64})
		st.st.Suspect = append(st.st.Suspect, strings.Repeat("d", 32))
	}
	plain, err := json.Marshal(&st.st)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("worst-case plaintext %.2f MiB of the %d MiB bound", float64(len(plain))/(1<<20), maxStatePlain>>20)
	if len(plain) > maxStatePlain*9/10 {
		t.Fatalf("worst case %d bytes leaves under 10%% headroom below maxStatePlain %d", len(plain), maxStatePlain)
	}
	if err := st.commit(); err != nil {
		t.Fatalf("a state within every count bound could not be written: %v", err)
	}
	fi, err := os.Stat(st.path)
	if err != nil || fi.Size() > maxStateFileBytes {
		t.Fatalf("file %v bytes, bound %d: %v", fi.Size(), maxStateFileBytes, err)
	}
	re, err := reopenErr(st)
	if err != nil {
		t.Fatalf("a written state could not be reopened: %v", err)
	}
	re.Close()
}

func TestPayAtTheSoftCapWithRealisticRecordsNeverHitsTheByteBound(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
	for i := 0; i < maxOutputRecords-1; i++ {
		o := dummyRecord(1000+i, StatusUnspent, 0)
		o.Blinding, o.BlockHash, o.Height, o.MaturesAt = bytes.Repeat([]byte{7}, 32), strings.Repeat("a", 64), 123456789, 123456799
		st.st.Outputs = append(st.st.Outputs, o)
	}
	if err := st.commit(); err != nil {
		t.Fatal(err)
	}
	// Imports and receives stop at the soft cap; payments keep working, repeatedly.
	if _, err := st.Receive(fakeOffer(t, 3)); !errors.Is(err, ErrStateFull) {
		t.Fatalf("receive at the soft cap: %v", err)
	}
	for i := 0; i < 3; i++ {
		offer, err := st.Pay(n, PayParams{Amount: 10, Fee: 1})
		if err != nil {
			t.Fatalf("payment %d: %v", i, err)
		}
		if err := st.Cancel(hex.EncodeToString(offer.TxID[:]), false); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConsolidateMergesSmallOutputsEvenWhenTheWalletIsFull(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	for _, v := range []int64{10, 20, 30, 40, 50, 60} {
		fund(t, st, n, v, types.OutputFeaturesPlain, 5)
	}
	for i := 0; i < maxOutputRecords-6; i++ { // full: 10000 not-final records, all worth more than the small ones
		o := dummyRecord(1000+i, StatusUnspent, 0)
		o.Value = 1_000_000
		st.st.Outputs = append(st.st.Outputs, o)
	}
	if err := st.commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Receive(fakeOffer(t, 3)); !errors.Is(err, ErrStateFull) {
		t.Fatalf("setup: wallet is not full: %v", err)
	}
	res, err := st.Consolidate(n, 1)
	if err != nil {
		t.Fatalf("consolidate at the cap: %v", err)
	}
	if res.Amount != 99 {
		t.Fatalf("merged %d, want 10+20+30+40-1 = 99", res.Amount)
	}
	if got := st.nonFinal(); got != maxOutputRecords-3 {
		t.Fatalf("not-final records %d, want %d", got, maxOutputRecords-3)
	}
	n.mine()
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	if b := st.Balance(); b.Spendable != 50+60+99 {
		t.Fatalf("balance %+v", b)
	}
	if _, err := st.Consolidate(n, 1); err != nil { // two big outputs and the merged one remain
		t.Fatalf("second round: %v", err)
	}
}

func TestConsolidateRefusesWhenThereIsNothingToMerge(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	fund(t, st, n, 100, types.OutputFeaturesPlain, 5)
	if _, err := st.Consolidate(n, 1); err == nil {
		t.Fatal("consolidated a single output")
	}
	if len(st.st.Contexts) != 0 {
		t.Fatal("a refused consolidation left a payment behind")
	}
}

func TestImportCoinbaseFillsToTheCapAndPaymentsStillWork(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
	fillDummies(t, st, maxOutputRecords-1-5, StatusPending, 0)
	cs, err := OpenCoinbaseStore(tmpFile(t, "cb.json"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := cs.Allocate(uint64(i+1), 50); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := st.ImportCoinbase(cs.path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Imported != 5 || rep.Skipped != 5 {
		t.Fatalf("import report %+v", rep)
	}
	if _, err := st.Pay(n, PayParams{Amount: 500, Fee: 1}); err != nil {
		t.Fatalf("a full wallet could not pay: %v", err)
	}
}

// ---- item 3: see TestRestoredBackupCannotSign... and the next test ---------

func TestCancelAfterRestoreChangeIsArchivedAndRevivesOnChain(t *testing.T) {
	// Covered end to end by TestCancelAfterRestoreKeepsChangeForAMinedTx; this one
	// pins the stored form: the archive entry opens to the change commitment.
	n := newFakeNode()
	st := newWalletStore(t, "a")
	fund(t, st, n, 1000, types.OutputFeaturesPlain, 5)
	offer, err := st.Pay(n, PayParams{Amount: 600, Fee: 10})
	if err != nil {
		t.Fatal(err)
	}
	id := hex.EncodeToString(offer.TxID[:])
	st.st.Suspect = append(st.st.Suspect, id)
	if err := st.Cancel(id, false); err != nil {
		t.Fatal(err)
	}
	if len(st.st.Archive) != 1 || st.st.Archive[0].Reason != archReasonChange {
		t.Fatalf("archive %+v", st.st.Archive)
	}
	a := st.st.Archive[0]
	if err := checkOpening(&OutputRecord{Commit: a.Commit, Value: a.Value, Blinding: a.Blinding}); err != nil {
		t.Fatalf("the archived change key does not open its commitment: %v", err)
	}
	// An ordinary (not suspect) cancel still erases the never-signed change.
	offer2, err := st.Pay(n, PayParams{Amount: 600, Fee: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Cancel(hex.EncodeToString(offer2.TxID[:]), false); err != nil {
		t.Fatal(err)
	}
	if len(st.st.Archive) != 1 {
		t.Fatal("a cancel of a never-signed payment archived its change")
	}
}

// ---- item 4 ----------------------------------------------------------------

func TestCancelReceiveArchivesFreesTheQuotaAndTheKeyRevives(t *testing.T) {
	old := maxPendingReceives
	maxPendingReceives = 1
	defer func() { maxPendingReceives = old }()
	d := newDuo(t, 1000)
	offer, err := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := d.r.Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.r.Receive(fakeOffer(t, 9)); !errors.Is(err, ErrTooManyPending) {
		t.Fatalf("quota: %v", err)
	}
	id := hex.EncodeToString(offer.TxID[:])
	if err := d.r.CancelReceive(id); err != nil {
		t.Fatal(err)
	}
	if d.r.output(commitHex(resp.RecvOutput.Commit)) != nil || !d.r.archived(commitHex(resp.RecvOutput.Commit)) {
		t.Fatal("the receive was not moved to the archive")
	}
	if _, err := d.r.Receive(offer); !errors.Is(err, ErrReplay) {
		t.Fatalf("a cancelled offer can be answered again: %v", err)
	}
	if _, err := d.r.Receive(fakeOffer(t, 9)); err != nil {
		t.Fatalf("quota not freed: %v", err)
	}
	if err := d.r.CancelReceive(strings.Repeat("0", 32)); err == nil {
		t.Fatal("cancelled something that is not there")
	}
	// The sender had the response all along and finishes the payment anyway.
	if _, err := d.s.Finalize(d.node, resp); err != nil {
		t.Fatal(err)
	}
	d.node.mine()
	rep, err := d.r.Sync(d.node)
	if err != nil || rep.Revived != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if b := d.r.Balance(); b.Spendable != 600 {
		t.Fatalf("the cancelled receive's funds are not spendable: %+v", b)
	}
	if err := d.r.CancelReceive(id); err == nil {
		t.Fatal("cancelled a confirmed receive")
	}
}

func TestStuckChangeAndReorgedCandidatesAreArchivedNotKeptForever(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	clock := time.Unix(1_800_000_000, 0)
	st.now = func() time.Time { return clock }
	// (a) pending change of a payment that never reached a block.
	ch := fund(t, st, n, 300, types.OutputFeaturesPlain, 5)
	co := st.output(commitHex(ch))
	co.Status, co.Origin, co.Created, co.TxID, co.BlockHash, co.Height = StatusPending, OriginChange, clock.Unix(), strings.Repeat("a", 32), "", 0
	delete(n.utxo, ch)
	// (b) a coinbase whose block left the chain: keeps its claimed height.
	cb := fund(t, st, n, 500, types.OutputFeaturesCoinbase, 7)
	delete(n.utxo, cb)
	n.blocks[7] = fmt.Sprintf("%064x", 999) // not the block it was seen in
	if err := st.commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Sync(n); err != nil {
		t.Fatal(err)
	}
	if o := st.output(commitHex(cb)); o == nil || o.Status != StatusPending || o.Height != 7 {
		t.Fatalf("reorged coinbase: %+v", o)
	}
	clock = clock.Add(31 * 24 * time.Hour)
	n.tip = 7 + pruneDepth + 10
	if _, err := st.SyncWith(n, SyncOptions{AcceptTip: n.tip}); err != nil {
		t.Fatal(err)
	}
	if st.output(commitHex(ch)) != nil || !st.archived(commitHex(ch)) {
		t.Fatal("stale change not archived")
	}
	if st.output(commitHex(cb)) != nil || !st.archived(commitHex(cb)) {
		t.Fatal("reorged candidate not archived")
	}
	for _, a := range st.st.Archive {
		if len(a.Blinding) != 32 || bytes.Equal(a.Blinding, make([]byte, 32)) {
			t.Fatal("an archived key is empty")
		}
	}
}

func tmpFile(t *testing.T, name string) string { return t.TempDir() + string(os.PathSeparator) + name }

func TestAStoreThatCannotReloadRefusesToWriteOnStaleMemory(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX file permissions and a non-root user")
	}
	st := newWalletStore(t, "a")
	st.writeHook = func() error { return errors.New("injected write failure") }
	if err := os.Chmod(st.path, 0); err != nil { // the reload after the failure cannot read the file
		t.Fatal(err)
	}
	if err := st.commit(); err == nil {
		t.Fatal("injected failure not reported")
	}
	if st.broken == nil {
		t.Fatal("a failed reload was swallowed")
	}
	st.writeHook = nil
	if err := os.Chmod(st.path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.commit(); err == nil || !strings.Contains(err.Error(), "memory may differ") {
		t.Fatalf("wrote on memory that may be stale: %v", err)
	}
	if st.broken != nil {
		t.Fatal("a successful reload did not clear the marker")
	}
	if err := st.commit(); err != nil {
		t.Fatalf("store did not recover: %v", err)
	}
}

func TestUpgradeBackupIsNeverOverwritten(t *testing.T) {
	p := tmpFile(t, "w.json")
	w, _ := NewRandom()
	defer w.Close()
	writeV1Keystore(t, p, w, testPass)
	first, _ := os.ReadFile(p)
	bak, err := BackupBeforeUpgrade(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BackupBeforeUpgrade(p); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(bak)
	if !bytes.Equal(got, first) {
		t.Fatal("the first backup was overwritten")
	}
}

func TestRPCNodeSeparatesPolicyRefusalFromRejection(t *testing.T) {
	for _, c := range []struct {
		code    int
		policy  bool
		reject  bool
		message string
	}{{-32013, true, false, "conflict"}, {-32010, false, true, "bad sig"}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"jsonrpc":"2.0","error":{"code":%d,"message":%q},"id":1}`, c.code, c.message)
		}))
		n, _ := NewRPCNode(srv.URL, "")
		tx := &types.Transaction{Inputs: []types.Input{{}}, Outputs: []types.Output{{RangeProof: make([]byte, 10)}}, Kernels: []types.Kernel{{ExcessSig: make([]byte, 65)}}}
		err := n.Submit(tx)
		srv.Close()
		if errors.Is(err, ErrPolicyRefused) != c.policy || errors.Is(err, ErrRejected) != c.reject {
			t.Fatalf("code %d: policy=%v rejected=%v err=%v", c.code, errors.Is(err, ErrPolicyRefused), errors.Is(err, ErrRejected), err)
		}
	}
}

func TestPolicyRefusalMessageDoesNotAdviseForceCancel(t *testing.T) {
	d := newDuo(t, 1000)
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	resp, _ := d.r.Receive(offer)
	d.node.submitErr = fmt.Errorf("%w: conflict", ErrPolicyRefused)
	_, err := d.s.Finalize(d.node, resp)
	if err == nil || !errors.Is(err, ErrPolicyRefused) || strings.Contains(err.Error(), "cancel --force") || !strings.Contains(err.Error(), "do NOT cancel") {
		t.Fatalf("%v", err)
	}
	d.node.submitErr = fmt.Errorf("%w: invalid", ErrRejected)
	_, err = d.s.Finalize(d.node, resp)
	if err == nil || !strings.Contains(err.Error(), "cancel --force") || !strings.Contains(err.Error(), "pays twice") {
		t.Fatalf("%v", err)
	}
}

func TestSyncReportCarriesTheTrustNotice(t *testing.T) {
	n := newFakeNode()
	st := newWalletStore(t, "a")
	rep, err := st.Sync(n)
	if err != nil || !strings.Contains(rep.Notice, "answers of the node") {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestRolledBackErrorDoesNotTellToPayAgainBlindly(t *testing.T) {
	if !strings.Contains(ErrRolledBack.Error(), "sync first") {
		t.Fatal(ErrRolledBack)
	}
}
