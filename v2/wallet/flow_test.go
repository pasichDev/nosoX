package wallet

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
)

func TestPayReceiveFinalizeHappyPath(t *testing.T) {
	node := newFakeNode()
	sender, receiver := newWalletStore(t, "s"), newWalletStore(t, "r")
	fund(t, sender, node, 1000, types.OutputFeaturesPlain, 5)

	offer, err := sender.Pay(node, PayParams{Amount: 600, Fee: 10, Memo: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if offer.Change == nil {
		t.Fatal("expected change")
	}
	resp, err := receiver.Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	res, err := sender.Finalize(node, resp)
	if err != nil {
		t.Fatal(err)
	}
	if res.Resubmitted || len(node.submits) != 1 {
		t.Fatalf("unexpected submit state: %+v %d", res, len(node.submits))
	}
	tx, err := DecodeTx(node.submits[0])
	if err != nil {
		t.Fatal(err)
	}
	k := tx.Kernels[0]
	if !v2crypto.SchnorrVerify(k.Excess, types.KernelSigningMessage(types.NetworkMagicTestnet, &k), k.ExcessSig) {
		t.Fatal("kernel signature does not verify")
	}
	node.mine()
	if _, err := sender.Sync(node); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Sync(node); err != nil {
		t.Fatal(err)
	}
	if b := sender.Balance(); b.Spendable != 390 || b.Locked != 0 || b.Pending != 0 {
		t.Fatalf("sender balance %+v", b)
	}
	if b := receiver.Balance(); b.Spendable != 600 {
		t.Fatalf("receiver balance %+v", b)
	}
	if len(sender.Contexts()) != 0 {
		t.Fatal("nonce context survived finalize")
	}
}

// ---- helpers -------------------------------------------------------------

func cloneSlate(t testing.TB, s *Slate) *Slate {
	t.Helper()
	raw, err := s.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	c, err := UnmarshalSlate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func randomPoint(t testing.TB) types.Commitment {
	t.Helper()
	k, err := randomScalar()
	if err != nil {
		t.Fatal(err)
	}
	p, err := pointOf(&k)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func shiftByG(t testing.TB, p types.Commitment) types.Commitment {
	t.Helper()
	one := [32]byte{31: 1}
	g, err := v2crypto.PublicFromScalar(one[:])
	if err != nil {
		t.Fatal(err)
	}
	q, err := v2crypto.PointAdd(p, g)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func otherOutput(t testing.TB, value int64) types.Output {
	t.Helper()
	o, r, err := newOutput(value)
	if err != nil {
		t.Fatal(err)
	}
	r.Zero()
	return o
}

type duo struct {
	node *fakeNode
	s, r *Store
}

func newDuo(t *testing.T, funds ...int64) *duo {
	d := &duo{node: newFakeNode(), s: newWalletStore(t, "s"), r: newWalletStore(t, "r")}
	for _, v := range funds {
		fund(t, d.s, d.node, v, types.OutputFeaturesPlain, 5)
	}
	return d
}

func (d *duo) mustNotSubmit(t *testing.T) {
	t.Helper()
	if len(d.node.submits) != 0 {
		t.Fatalf("a transaction was emitted: %d submits", len(d.node.submits))
	}
}

// ---- funds and selection ---------------------------------------------------

func TestZeroChangeOmitsChangeOutput(t *testing.T) {
	d := newDuo(t, 610)
	offer, err := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	if err != nil {
		t.Fatal(err)
	}
	if offer.Change != nil {
		t.Fatal("change output present for zero change")
	}
	resp, err := d.r.Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.s.Finalize(d.node, resp); err != nil {
		t.Fatal(err)
	}
	tx, _ := DecodeTx(d.node.submits[0])
	if len(tx.Outputs) != 1 {
		t.Fatalf("outputs: %d", len(tx.Outputs))
	}
	d.node.mine()
	if _, err := d.s.Sync(d.node); err != nil {
		t.Fatal(err)
	}
	if b := d.s.Balance(); b.Spendable+b.Locked+b.Pending != 0 {
		t.Fatalf("sender should be empty: %+v", b)
	}
}

func TestInsufficientFundsChangesNothing(t *testing.T) {
	d := newDuo(t, 100, 200)
	before := d.s.Balance()
	if _, err := d.s.Pay(d.node, PayParams{Amount: 300, Fee: 1}); err == nil || !errorsIs(err, ErrInsufficientFunds) {
		t.Fatalf("want ErrInsufficientFunds, got %v", err)
	}
	if d.s.Balance() != before || len(d.s.Contexts()) != 0 {
		t.Fatal("failed Pay changed state")
	}
	for _, p := range []PayParams{{Amount: 0}, {Amount: -5}, {Amount: 1, Fee: 1 << 63}, {Amount: 1<<63 - 1, Fee: 1}, {Amount: 1, LockHeight: MaxLockHeight + 1}} {
		if _, err := d.s.Pay(d.node, p); err == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
}

func TestImmatureCoinbaseIsNotSpendable(t *testing.T) {
	node := newFakeNode()
	s, r := newWalletStore(t, "s"), newWalletStore(t, "r")
	// Created at tip-58: first spendable by block tip+2, so immature for tip+1.
	fund(t, s, node, 1000, types.OutputFeaturesCoinbase, node.tip-58)
	if _, err := s.Pay(node, PayParams{Amount: 100, Fee: 1}); !errorsIs(err, ErrInsufficientFunds) {
		t.Fatalf("immature coinbase selected: %v", err)
	}
	node.tip++ // now the next block (tip+1) is exactly created+60
	offer, err := s.Pay(node, PayParams{Amount: 100, Fee: 1})
	if err != nil {
		t.Fatalf("mature coinbase refused: %v", err)
	}
	resp, err := r.Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Finalize(node, resp); err != nil {
		t.Fatalf("node refused a mature spend: %v", err)
	}
}

func TestNodeWithoutOutputSkipsStaleRecord(t *testing.T) {
	d := newDuo(t, 1000)
	d.node.mu.Lock()
	for c := range d.node.utxo {
		delete(d.node.utxo, c)
	}
	d.node.mu.Unlock()
	if _, err := d.s.Pay(d.node, PayParams{Amount: 10, Fee: 1}); !errorsIs(err, ErrInsufficientFunds) {
		t.Fatalf("spent output selected: %v", err)
	}
}

func TestDoubleSelectIsImpossible(t *testing.T) {
	d := newDuo(t, 500, 500)
	o1, err := d.s.Pay(d.node, PayParams{Amount: 400, Fee: 1})
	if err != nil {
		t.Fatal(err)
	}
	o2, err := d.s.Pay(d.node, PayParams{Amount: 400, Fee: 1})
	if err != nil {
		t.Fatal(err)
	}
	if o1.Inputs[0].Commit == o2.Inputs[0].Commit {
		t.Fatal("same output offered in two payments")
	}
	if _, err := d.s.Pay(d.node, PayParams{Amount: 1, Fee: 1}); !errorsIs(err, ErrInsufficientFunds) {
		t.Fatalf("third payment should lack funds, got %v", err)
	}
	if b := d.s.Balance(); b.Locked != 1000 || b.Spendable != 0 {
		t.Fatalf("balance: %+v", b)
	}
}

func TestTooManyInputs(t *testing.T) {
	d := newDuo(t, 100, 100, 100, 100, 100)
	if _, err := d.s.Pay(d.node, PayParams{Amount: 450, Fee: 1}); !errorsIs(err, ErrTooManyInputs) {
		t.Fatalf("want ErrTooManyInputs, got %v", err)
	}
	if len(d.s.Contexts()) != 0 {
		t.Fatal("state changed")
	}
	// Four inputs are fine.
	if _, err := d.s.Pay(d.node, PayParams{Amount: 390, Fee: 1}); err != nil {
		t.Fatal(err)
	}
}

// ---- tampering ---------------------------------------------------------------

func TestTamperedOfferNeverYieldsATransaction(t *testing.T) {
	d := newDuo(t, 1000)
	foreign := otherOutput(t, 5)
	stranger := fundedCommit(t)
	offer, err := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10, Memo: "m"})
	if err != nil {
		t.Fatal(err)
	}
	mut := map[string]func(s *Slate){
		"amount up":      func(s *Slate) { s.Amount++ },
		"amount down":    func(s *Slate) { s.Amount-- },
		"fee up":         func(s *Slate) { s.Fee++ },
		"fee down":       func(s *Slate) { s.Fee-- },
		"lock":           func(s *Slate) { s.LockHeight++ },
		"memo":           func(s *Slate) { s.Memo = "other" },
		"change commit":  func(s *Slate) { s.Change = &foreign },
		"change proof":   func(s *Slate) { c := *s.Change; c.RangeProof = foreign.RangeProof; s.Change = &c },
		"change dropped": func(s *Slate) { s.Change = nil },
		"input swapped":  func(s *Slate) { s.Inputs[0].Commit = stranger },
		"input features": func(s *Slate) { s.Inputs[0].Features = types.OutputFeaturesCoinbase },
		"input extra":    func(s *Slate) { s.Inputs = append(s.Inputs, types.Input{Commit: stranger}) },
		"sender excess":  func(s *Slate) { s.SenderExc = shiftByG(t, s.SenderExc) },
		"sender nonce":   func(s *Slate) { s.SenderNon = randomPoint(t) },
		"txid":           func(s *Slate) { s.TxID[3] ^= 0x40 },
	}
	for name, m := range mut {
		t.Run(name, func(t *testing.T) {
			bad := cloneSlate(t, offer)
			m(bad)
			recv := newWalletStore(t, "r")
			resp, err := recv.Receive(bad)
			if err != nil {
				t.Logf("receiver rejected: %v", err)
				return // receiver caught it
			}
			_, err = d.s.Finalize(d.node, resp)
			if err == nil {
				t.Fatal("sender finalized a tampered offer")
			}
			t.Logf("sender rejected: %v", err)
			d.mustNotSubmit(t)
		})
	}
	// The genuine flow still works: failed attempts did not burn the nonce.
	resp, err := d.r.Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.s.Finalize(d.node, resp); err != nil {
		t.Fatalf("genuine finalize after tamper attempts: %v", err)
	}
}

func fundedCommit(t testing.TB) types.Commitment {
	t.Helper()
	r, _ := randomScalar()
	b := r.Bytes()
	c, err := v2crypto.PedersenCommit(77, b[:])
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTamperedResponseNeverYieldsATransaction(t *testing.T) {
	d := newDuo(t, 1000)
	offer, err := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := d.r.Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	// A second, independent receiver answers the same offer with its own nonce.
	resp2, err := newWalletStore(t, "r2").Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	foreign := otherOutput(t, 600)
	garbage := foreign
	garbage.RangeProof = append([]byte(nil), foreign.RangeProof...)
	garbage.RangeProof[len(garbage.RangeProof)/2] ^= 0x01
	stranger := fundedCommit(t)
	k, _ := randomScalar()
	randScalar := k.Bytes()
	plusOne := func(b [32]byte) [32]byte {
		var s, one secp.ModNScalar
		s.SetBytes(&b)
		one.SetInt(1)
		s.Add(&one)
		return s.Bytes()
	}
	mut := map[string]func(s *Slate){
		"amount":            func(s *Slate) { s.Amount++ },
		"fee":               func(s *Slate) { s.Fee++ },
		"lock":              func(s *Slate) { s.LockHeight++ },
		"memo":              func(s *Slate) { s.Memo = "x" },
		"txid":              func(s *Slate) { s.TxID[0] ^= 1 },
		"input swapped":     func(s *Slate) { s.Inputs[0].Commit = stranger },
		"change commit":     func(s *Slate) { s.Change = &foreign },
		"change dropped":    func(s *Slate) { s.Change = nil },
		"sender excess":     func(s *Slate) { s.SenderExc = randomPoint(t) },
		"sender nonce":      func(s *Slate) { s.SenderNon = randomPoint(t) },
		"recv output":       func(s *Slate) { s.RecvOutput = &foreign },
		"recv proof":        func(s *Slate) { o := *s.RecvOutput; o.RangeProof = garbage.RangeProof; s.RecvOutput = &o },
		"recv proof other":  func(s *Slate) { o := *s.RecvOutput; o.RangeProof = foreign.RangeProof; s.RecvOutput = &o },
		"recv = change":     func(s *Slate) { c := *s.Change; s.RecvOutput = &c },
		"recv = input":      func(s *Slate) { o := *s.RecvOutput; o.Commit = s.Inputs[0].Commit; s.RecvOutput = &o },
		"wrong P_r":         func(s *Slate) { s.RecvExc = shiftByG(t, s.RecvExc) },
		"random P_r":        func(s *Slate) { s.RecvExc = randomPoint(t) },
		"wrong R_r":         func(s *Slate) { s.RecvNon = randomPoint(t) },
		"forged partial":    func(s *Slate) { s.RecvPartial = randScalar },
		"partial plus one":  func(s *Slate) { s.RecvPartial = plusOne(s.RecvPartial) },
		"partial = 1":       func(s *Slate) { s.RecvPartial = [32]byte{31: 1} },
		"partial of other":  func(s *Slate) { s.RecvPartial = resp2.RecvPartial },
		"nonce of other":    func(s *Slate) { s.RecvNon = resp2.RecvNon },
		"mixed responses":   func(s *Slate) { s.RecvNon, s.RecvPartial = resp2.RecvNon, resp2.RecvPartial },
		"offer as response": func(s *Slate) { s.Stage = StageOffer },
	}
	for name, m := range mut {
		t.Run(name, func(t *testing.T) {
			bad := cloneSlateLoose(t, resp)
			m(bad)
			_, err := d.s.Finalize(d.node, bad)
			if err == nil {
				t.Fatal("tampered response finalized")
			}
			t.Logf("rejected: %v", err)
			d.mustNotSubmit(t)
			if len(d.s.Contexts()) != 1 {
				t.Fatal("a rejected response destroyed the nonce context")
			}
		})
	}
	// Genuine response still finalizes after every failed attempt.
	if _, err := d.s.Finalize(d.node, resp); err != nil {
		t.Fatalf("genuine finalize after tamper attempts: %v", err)
	}
	// The other receiver's response for the same session is now refused.
	if _, err := d.s.Finalize(d.node, resp2); err == nil {
		t.Fatal("second response for a finalized session accepted")
	}
	if len(d.node.submits) != 1 {
		t.Fatalf("submits: %d", len(d.node.submits))
	}
}

// cloneSlateLoose copies a slate field by field without structural validation,
// so mutations that Validate would reject still reach Finalize.
func cloneSlateLoose(t testing.TB, s *Slate) *Slate {
	c := *s
	c.Inputs = append([]types.Input(nil), s.Inputs...)
	if s.Change != nil {
		ch := *s.Change
		c.Change = &ch
	}
	if s.RecvOutput != nil {
		ro := *s.RecvOutput
		c.RecvOutput = &ro
	}
	return &c
}

func TestTamperedFinalTransactionRejectedByNode(t *testing.T) {
	d := newDuo(t, 1000)
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	resp, _ := d.r.Receive(offer)
	if _, err := d.s.Finalize(d.node, resp); err != nil {
		t.Fatal(err)
	}
	good, _ := DecodeTx(d.node.submits[0])
	foreign := otherOutput(t, 5)
	for name, m := range map[string]func(tx *types.Transaction){
		"fee":      func(tx *types.Transaction) { tx.Kernels[0].Fee++ },
		"lock":     func(tx *types.Transaction) { tx.Kernels[0].LockHeight++ },
		"excess":   func(tx *types.Transaction) { tx.Kernels[0].Excess = shiftByG(t, tx.Kernels[0].Excess) },
		"output":   func(tx *types.Transaction) { tx.Outputs[0] = foreign },
		"sig":      func(tx *types.Transaction) { tx.Kernels[0].ExcessSig[40] ^= 1 },
		"no input": func(tx *types.Transaction) { tx.Inputs = nil },
	} {
		raw, _ := EncodeTx(good)
		tx, _ := DecodeTx(raw)
		m(tx)
		n2 := newFakeNode()
		n2.utxo = d.node.utxo
		n2.seen = d.node.seen
		// Reset the pool view of the original node: a fresh node sees only the mutated tx.
		if err := n2.Submit(tx); err == nil {
			t.Errorf("node accepted tx with tampered %s", name)
		}
	}
}

// ---- idempotence, replay, cancel ---------------------------------------------

func TestFinalizeTwiceEmitsTheSameSignature(t *testing.T) {
	d := newDuo(t, 1000)
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	resp, _ := d.r.Receive(offer)
	r1, err := d.s.Finalize(d.node, resp)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := d.s.Finalize(d.node, resp)
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Resubmitted || r1.TxHash != r2.TxHash {
		t.Fatalf("second finalize: %+v vs %+v", r1, r2)
	}
	if len(d.node.submits) != 2 || !bytes.Equal(d.node.submits[0], d.node.submits[1]) {
		t.Fatal("resubmission was not byte-identical")
	}
	// Also across a process restart.
	d.s = reopen(t, d.s)
	r3, err := d.s.Finalize(d.node, resp)
	if err != nil || r3.TxHash != r1.TxHash || !bytes.Equal(d.node.submits[2], d.node.submits[0]) {
		t.Fatalf("finalize after restart: %+v %v", r3, err)
	}
	if len(d.s.Contexts()) != 0 {
		t.Fatal("nonce context present after finalize")
	}
}

func TestDifferentResponseAfterFinalizeRejected(t *testing.T) {
	d := newDuo(t, 1000)
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	resp1, _ := d.r.Receive(offer)
	resp2, _ := newWalletStore(t, "r2").Receive(offer)
	if _, err := d.s.Finalize(d.node, resp1); err != nil {
		t.Fatal(err)
	}
	if _, err := d.s.Finalize(d.node, resp2); !errorsIs(err, ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
	if len(d.node.submits) != 1 {
		t.Fatal("second response caused a submission")
	}
}

func TestReceiverReplayRejectedDurably(t *testing.T) {
	d := newDuo(t, 1000)
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	if _, err := d.r.Receive(offer); err != nil {
		t.Fatal(err)
	}
	if _, err := d.r.Receive(offer); !errorsIs(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
	d.r = reopen(t, d.r)
	if _, err := d.r.Receive(offer); !errorsIs(err, ErrReplay) {
		t.Fatalf("replay after restart: %v", err)
	}
	if got := len(d.r.Outputs()); got != 1 {
		t.Fatalf("receiver tracks %d outputs", got)
	}
}

func TestCancelDestroysNonceAndUnlocks(t *testing.T) {
	d := newDuo(t, 1000)
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	resp, _ := d.r.Receive(offer)
	txid := hexID(offer.TxID)
	if err := d.s.Cancel(txid, false); err != nil {
		t.Fatal(err)
	}
	if b := d.s.Balance(); b.Spendable != 1000 || b.Locked != 0 || b.Pending != 0 {
		t.Fatalf("cancel did not restore funds: %+v", b)
	}
	if len(d.s.Contexts()) != 0 || len(d.s.Outputs()) != 1 {
		t.Fatalf("cancel left state: ctx=%d outputs=%d", len(d.s.Contexts()), len(d.s.Outputs()))
	}
	for i := 0; i < 2; i++ { // in memory, then after a restart (durable)
		if len(d.s.Contexts()) != 0 {
			t.Fatal("context survived cancel on disk")
		}
		if _, err := d.s.Finalize(d.node, resp); !errorsIs(err, ErrUnknownTx) {
			t.Fatalf("finalize after cancel: %v", err)
		}
		d.s = reopen(t, d.s)
	}
	d.mustNotSubmit(t)
	if err := d.s.Cancel(txid, false); !errorsIs(err, ErrUnknownTx) {
		t.Fatalf("double cancel: %v", err)
	}
	// A new payment uses a fresh nonce and a fresh session.
	again, err := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	if err != nil {
		t.Fatal(err)
	}
	if again.SenderNon == offer.SenderNon || again.TxID == offer.TxID {
		t.Fatal("nonce or session reused after cancel")
	}
	if _, err := d.s.Finalize(d.node, resp); err == nil {
		t.Fatal("old response finalized against a new payment")
	}
}

func hexID(id [16]byte) string { return hex.EncodeToString(id[:]) }

func TestNoncesAreUniqueAcrossPayments(t *testing.T) {
	d := newDuo(t, 100, 100, 100, 100)
	seen := map[types.Commitment]bool{}
	for i := 0; i < 4; i++ {
		o, err := d.s.Pay(d.node, PayParams{Amount: 50, Fee: 1})
		if err != nil {
			t.Fatal(err)
		}
		if seen[o.SenderNon] {
			t.Fatal("sender nonce repeated")
		}
		seen[o.SenderNon] = true
	}
}

func TestCancelAfterSigningNeedsForceAndKeepsChange(t *testing.T) {
	d := newDuo(t, 1000)
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	resp, _ := d.r.Receive(offer)
	d.node.submitErr = errors.New("connection refused")
	if _, err := d.s.Finalize(d.node, resp); err == nil {
		t.Fatal("expected submit failure")
	}
	txid := hexID(offer.TxID)
	if err := d.s.Cancel(txid, false); err == nil {
		t.Fatal("cancel of a signed tx without --force")
	}
	if err := d.s.Cancel(txid, true); err != nil {
		t.Fatal(err)
	}
	b := d.s.Balance()
	if b.Spendable != 1000 || b.Locked != 0 {
		t.Fatalf("the input must be released and spendable again: %+v", b)
	}
	if b.Pending != 390 {
		t.Fatalf("change must stay tracked as pending, got %+v", b)
	}
	if len(d.s.SentTxIDs()) != 0 {
		t.Fatal("sent record kept after forced cancel")
	}
}

// ---- crash consistency --------------------------------------------------------

func TestPayWithheldWhenPersistenceFails(t *testing.T) {
	d := newDuo(t, 1000)
	d.s.writeHook = func() error { return errors.New("disk full") }
	if s, err := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10}); err == nil || s != nil {
		t.Fatalf("slate emitted without durable state: %v", err)
	}
	d.s.writeHook = nil
	if b := d.s.Balance(); b.Spendable != 1000 || b.Locked != 0 || len(d.s.Contexts()) != 0 || len(d.s.Outputs()) != 1 {
		t.Fatalf("in-memory state ran ahead of disk: %+v", b)
	}
	if _, err := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10}); err != nil {
		t.Fatal(err)
	}
}

func TestCrashBetweenPersistAndEmit(t *testing.T) {
	d := newDuo(t, 1000)
	offer, err := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	if err != nil {
		t.Fatal(err)
	}
	_ = offer // the process dies before the slate reaches anybody
	d.s = reopen(t, d.s)
	if got := d.s.Contexts(); len(got) != 1 || got[0] != hexID(offer.TxID) {
		t.Fatalf("context not durable: %v", got)
	}
	if b := d.s.Balance(); b.Locked != 1000 {
		t.Fatalf("inputs not locked after restart: %+v", b)
	}
	if _, err := d.s.Pay(d.node, PayParams{Amount: 1, Fee: 1}); !errorsIs(err, ErrInsufficientFunds) {
		t.Fatalf("locked inputs reselected: %v", err)
	}
	// The user can still complete the original payment from the lost slate's txid
	// (they would re-run receive on a re-displayed slate) or cancel it by id.
	if err := d.s.Cancel(hexID(offer.TxID), false); err != nil {
		t.Fatal(err)
	}
	if b := d.s.Balance(); b.Spendable != 1000 {
		t.Fatalf("funds not released: %+v", b)
	}
}

func TestFinalizeStateWriteFailureDoesNotBurnNonce(t *testing.T) {
	d := newDuo(t, 1000)
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	resp, _ := d.r.Receive(offer)
	d.s.writeHook = func() error { return errors.New("io error") }
	if _, err := d.s.Finalize(d.node, resp); err == nil {
		t.Fatal("finalize succeeded without durable state")
	}
	d.mustNotSubmit(t)
	d.s.writeHook = nil
	if len(d.s.Contexts()) != 1 || len(d.s.SentTxIDs()) != 0 {
		t.Fatal("state diverged from disk")
	}
	if _, err := d.s.Finalize(d.node, resp); err != nil {
		t.Fatalf("retry after write failure: %v", err)
	}
}

func TestCrashAfterSigningBeforeSubmit(t *testing.T) {
	d := newDuo(t, 1000)
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	resp, _ := d.r.Receive(offer)
	d.node.submitErr = errors.New("connection reset")
	if _, err := d.s.Finalize(d.node, resp); err == nil {
		t.Fatal("expected failure")
	}
	// Restart: no nonce on disk, signed tx stored.
	d.s = reopen(t, d.s)
	if len(d.s.Contexts()) != 0 || len(d.s.SentTxIDs()) != 1 {
		t.Fatalf("ctx=%v sent=%v", d.s.Contexts(), d.s.SentTxIDs())
	}
	d.node.submitErr = nil
	res, err := d.s.Finalize(d.node, resp)
	if err != nil || !res.Resubmitted {
		t.Fatalf("resubmit: %+v %v", res, err)
	}
	if len(d.node.submits) != 2 || !bytes.Equal(d.node.submits[0], d.node.submits[1]) {
		t.Fatal("signature changed between attempts")
	}
	d.node.mine()
	if _, err := d.s.Sync(d.node); err != nil {
		t.Fatal(err)
	}
	if _, err := d.r.Sync(d.node); err != nil {
		t.Fatal(err)
	}
	if d.r.Balance().Spendable != 600 || d.s.Balance().Spendable != 390 {
		t.Fatalf("balances: %+v / %+v", d.s.Balance(), d.r.Balance())
	}
}

// ---- receiver-side validation -----------------------------------------------

func TestReceiverRejectsBadOffers(t *testing.T) {
	d := newDuo(t, 1000)
	offer, _ := d.s.Pay(d.node, PayParams{Amount: 600, Fee: 10})
	garbage := *offer.Change
	garbage.RangeProof = append([]byte(nil), garbage.RangeProof...)
	garbage.RangeProof[10] ^= 0xff
	bad := cloneSlateLoose(t, offer)
	bad.Change = &garbage
	if _, err := d.r.Receive(bad); err == nil {
		t.Fatal("invalid change range proof accepted")
	}
	zero := cloneSlateLoose(t, offer)
	zero.Amount = 0
	if _, err := d.r.Receive(zero); err == nil {
		t.Fatal("zero amount accepted")
	}
	huge := cloneSlateLoose(t, offer)
	huge.Fee = 1 << 63
	if _, err := d.r.Receive(huge); err == nil {
		t.Fatal("overflowing fee accepted")
	}
	resp := cloneSlateLoose(t, offer)
	resp.Stage = StageResponse
	if _, err := d.r.Receive(resp); err == nil {
		t.Fatal("response accepted as offer")
	}
	if got := len(d.r.Outputs()); got != 0 {
		t.Fatalf("receiver recorded %d outputs for rejected offers", got)
	}
}

func TestFinalizeUnknownSession(t *testing.T) {
	d := newDuo(t, 1000)
	other := newDuo(t, 1000)
	offer, _ := other.s.Pay(other.node, PayParams{Amount: 5, Fee: 1})
	resp, _ := other.r.Receive(offer)
	if _, err := d.s.Finalize(d.node, resp); !errorsIs(err, ErrUnknownTx) {
		t.Fatalf("unknown session: %v", err)
	}
}

func errorsIs(err, target error) bool { return errors.Is(err, target) }

func TestPayingYourselfFromOneWallet(t *testing.T) {
	node := newFakeNode()
	w := newWalletStore(t, "self")
	fund(t, w, node, 1000, types.OutputFeaturesPlain, 5)
	offer, err := w.Pay(node, PayParams{Amount: 300, Fee: 10})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := w.Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Finalize(node, resp); err != nil {
		t.Fatalf("self payment: %v", err)
	}
	node.mine()
	if _, err := w.Sync(node); err != nil {
		t.Fatal(err)
	}
	if b := w.Balance(); b.Spendable != 990 || b.Pending != 0 || b.Locked != 0 {
		t.Fatalf("balance after self payment: %+v", b)
	}
	// The exception is narrow: an unrelated tracked output is still a collision.
	w2 := newDuo(t, 1000)
	o2, _ := w2.s.Pay(w2.node, PayParams{Amount: 300, Fee: 10})
	r2, _ := w2.r.Receive(o2)
	fund := r2.RecvOutput.Commit
	w2.s.st.Outputs = append(w2.s.st.Outputs, OutputRecord{Commit: commitHex(fund), Value: 300, Blinding: make([]byte, 32), Status: StatusUnspent, Origin: OriginCoinbase})
	if _, err := w2.s.Finalize(w2.node, r2); err == nil {
		t.Fatal("a pre-existing tracked output with the receiver's commitment was accepted")
	}
}
