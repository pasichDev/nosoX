package wallet

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
)

// Two-party Mimblewimble payment protocol.
//
//	round 1  Pay      sender:   selects inputs, builds change, x_s = r_change - sum(r_in),
//	                            P_s = x_s*G, fresh nonce k_s, R_s = k_s*G. Persists
//	                            (x_s, k_s, input locks) BEFORE the slate is returned.
//	round 2  Receive  receiver: adds output a*H + r_r*G, x_r = r_r, fresh k_r; E = P_s+P_r,
//	                            R = R_s+R_r, e = challenge, s_r = k_r + e*x_r. Records the
//	                            output as pending BEFORE the response is returned.
//	round 3  Finalize sender:   re-verifies everything, s_s = k_s + e*x_s, s = s_s+s_r,
//	                            verifies the aggregate with SchnorrVerify, persists the final
//	                            transaction while ERASING k_s, then submits.
//
// Nonce rule: a nonce k_s exists on disk only between Pay and the single atomic
// write that stores the final signature. After that write k_s is gone, so it
// can never sign a second message; a retry resubmits the stored signature.
//
// Variable-time paths (see docs/wallet.md): every scalar multiplication of G or
// H (P = x*G, R = k*G, Pedersen commitments, range proofs, partial-signature
// verification) is variable-time. Scalar +,-,* mod n on secrets uses
// secp256k1.ModNScalar, which is constant-time.

// Errors returned by payment operations.
var (
	ErrInsufficientFunds = errors.New("wallet: insufficient spendable funds")
	ErrTooManyInputs     = errors.New("wallet: amount needs more than the maximum number of inputs; consolidate outputs first")
	ErrUnknownTx         = errors.New("wallet: unknown transaction (never offered, already cancelled, or not ours)")
	ErrTampered          = errors.New("wallet: slate does not match the payment this wallet offered")
	ErrReplay            = errors.New("wallet: slate was already processed")
	ErrNetwork           = errors.New("wallet: slate is for a different network")
	ErrRolledBack        = errors.New("wallet: this wallet state was restored from an older copy; the payment cannot be signed safely, sync first: the payment may already have been signed and mined before the restore. Cancel it only afterwards, and pay again only if it is not on chain")
	ErrArchiveFull       = errors.New("wallet: too many expired unconfirmed receives are archived; they are kept because the sender may still mine them")
	ErrPolicyRefused     = errors.New("wallet: node did not admit the transaction right now (relay policy)")
	ErrTooManyPending    = errors.New("wallet: too many unconfirmed incoming payments; sync, wait for confirmations, or `wallet cancel-receive <txid>` (the key is kept)")
)

// ---- scalar and point helpers -------------------------------------------

func randomScalar() (secp.ModNScalar, error) {
	var s secp.ModNScalar
	for i := 0; i < 64; i++ {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return s, err
		}
		over := s.SetBytes(&b)
		Zeroize(b[:])
		if over == 0 && !s.IsZero() {
			return s, nil
		}
	}
	s.Zero()
	return s, errors.New("wallet: could not sample a scalar")
}

func scalarFromBytes(b []byte) (secp.ModNScalar, error) {
	var s secp.ModNScalar
	if len(b) != 32 || s.SetByteSlice(b) {
		return s, errors.New("wallet: non-canonical scalar")
	}
	return s, nil
}

func pointOf(s *secp.ModNScalar) ([33]byte, error) {
	b := s.Bytes()
	defer Zeroize(b[:])
	return v2crypto.PublicFromScalar(b[:])
}

// newOutput builds a plain output of the given value with a fresh blinding
// factor and range proof.
func newOutput(value int64) (types.Output, secp.ModNScalar, error) {
	r, err := randomScalar()
	if err != nil {
		return types.Output{}, r, err
	}
	rb := r.Bytes()
	defer Zeroize(rb[:])
	commit, err := v2crypto.PedersenCommit(value, rb[:])
	if err != nil {
		r.Zero()
		return types.Output{}, r, err
	}
	proof, err := v2crypto.ProveRange(commit, rb[:], value)
	if err != nil {
		r.Zero()
		return types.Output{}, r, err
	}
	return types.Output{Features: types.OutputFeaturesPlain, Commit: commit, RangeProof: proof}, r, nil
}

func kernelHeader(fee, lock uint64, excess types.Commitment) types.Kernel {
	return types.Kernel{Features: types.KernelFeaturesPlain, Fee: fee, LockHeight: lock, Excess: excess}
}

// challenge returns the Schnorr challenge for the aggregate (R, E) over the
// kernel id, plus that id (the signed message).
func challenge(magic uint32, R, E types.Commitment, fee, lock uint64) ([32]byte, []byte) {
	k := kernelHeader(fee, lock, E)
	msg := types.KernelSigningMessage(magic, &k)
	return v2crypto.SchnorrChallengeScalar(R, E, msg), msg
}

// deriveNonce returns the sender's nonce k_s = HMAC-SHA256(state key, label ||
// x_s || slate context || fresh randomness || counter) reduced to a non-zero
// scalar. Mixing a secret, the slate context and fresh randomness means a
// failing or repeating RNG alone cannot repeat a nonce, and nonces of two
// different slates are unrelated. It does NOT make the nonce a function of the
// receiver's later response (R_s is published in the offer first), which is
// why rollback is handled by the generation check in the store.
func deriveNonce(key []byte, xs *secp.ModNScalar, context []byte) (secp.ModNScalar, error) {
	var k secp.ModNScalar
	fresh := make([]byte, 32)
	defer Zeroize(fresh)
	if _, err := rand.Read(fresh); err != nil {
		return k, err
	}
	xb := xs.Bytes()
	defer Zeroize(xb[:])
	for ctr := byte(0); ctr < 255; ctr++ {
		m := hmac.New(sha256.New, key)
		m.Write([]byte("noso-wallet-sender-nonce/v1"))
		m.Write(xb[:])
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(context)))
		m.Write(l[:])
		m.Write(context)
		m.Write(fresh)
		m.Write([]byte{ctr})
		sum := m.Sum(nil)
		var b [32]byte
		copy(b[:], sum)
		Zeroize(sum)
		over := k.SetBytes(&b)
		Zeroize(b[:])
		if over == 0 && !k.IsZero() {
			return k, nil
		}
	}
	k.Zero()
	return k, errors.New("wallet: could not derive a nonce")
}

// nonceContext is the public slate data the nonce is bound to.
func nonceContext(txid [16]byte, amount int64, fee, lock uint64, inputs []types.Input, change *types.Output, Ps types.Commitment) []byte {
	b := append([]byte(nil), txid[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(amount))
	b = binary.BigEndian.AppendUint64(b, fee)
	b = binary.BigEndian.AppendUint64(b, lock)
	for _, in := range inputs {
		b = append(b, in.Commit[:]...)
	}
	if change != nil {
		b = append(b, change.Commit[:]...)
	}
	return append(b, Ps[:]...)
}

// excessBalances verifies sum(outputs) - sum(inputs) + fee*H == E.
func excessBalances(inputs []types.Input, outputs []types.Output, fee uint64, E types.Commitment) error {
	if fee > math.MaxInt64 {
		return errors.New("wallet: fee overflow")
	}
	var pos, neg [][33]byte
	for _, o := range outputs {
		pos = append(pos, o.Commit)
	}
	for _, in := range inputs {
		neg = append(neg, in.Commit)
	}
	neg = append(neg, E)
	if fee > 0 {
		feeH, err := v2crypto.PedersenCommit(int64(fee), make([]byte, 32))
		if err != nil {
			return err
		}
		pos = append(pos, feeH)
	}
	ok, err := v2crypto.PedersenSumZero(pos, neg, 0)
	if err != nil {
		return fmt.Errorf("wallet: commitment sum: %w", err)
	}
	if !ok {
		return errors.New("wallet: commitments do not balance against the excess")
	}
	return nil
}

func slateOutputs(s *Slate) []types.Output {
	var outs []types.Output
	if s.Change != nil {
		outs = append(outs, *s.Change)
	}
	if s.RecvOutput != nil {
		outs = append(outs, *s.RecvOutput)
	}
	return outs
}

func newTxID(s *Store) ([16]byte, error) {
	var id [16]byte
	for i := 0; i < 8; i++ {
		if _, err := rand.Read(id[:]); err != nil {
			return id, err
		}
		h := hex.EncodeToString(id[:])
		if _, c := s.context(h); c == nil {
			if _, t := s.sent(h); t == nil {
				return id, nil
			}
		}
	}
	return id, errors.New("wallet: could not allocate a transaction id")
}

// ---- round 1: Pay --------------------------------------------------------

// PayParams describes a payment.
type PayParams struct {
	Amount     int64
	Fee        uint64
	LockHeight uint64
	Memo       string
	// Consolidate builds a payment to the wallet itself that merges up to
	// types.MaxBlockInputs of the smallest spendable outputs into one (Amount is
	// ignored: it is the inputs minus Fee). Use Store.Consolidate.
	Consolidate bool
}

// MinRelayFee is the smallest fee a default-policy node relays for a payment
// with the given number of inputs and outputs (one kernel). A fee below it is
// signed and stored but refused by every node's mempool.
func MinRelayFee(inputs, outputs int) uint64 {
	size := types.EstimateTxSize(inputs, outputs, 1, types.MaxRangeProofBytes, 65)
	return types.MinRelayFee(types.DefaultRelayFeeRate, size)
}

// DefaultFee is the fee used when none is given: the relay minimum for the
// largest payment this wallet builds (types.MaxBlockInputs inputs, receiver and
// change outputs), so it clears the relay floor whatever inputs are selected.
func DefaultFee() uint64 { return MinRelayFee(types.MaxBlockInputs, 2) }

const maxSelectionQueries = 128

type selected struct {
	rec  *OutputRecord
	feat types.OutputFeatures
}

// Pay builds the offer slate (round 1). The offered inputs are locked and the
// nonce context is made durable before the slate is returned; if persistence
// fails no slate is returned.
func (s *Store) Pay(node Node, p PayParams) (*Slate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.Consolidate {
		p.Amount = 1 // replaced once the inputs are known
	}
	if p.Amount <= 0 {
		return nil, errors.New("wallet: amount must be positive")
	}
	if p.Fee > math.MaxInt64 || uint64(p.Amount) > math.MaxInt64-p.Fee {
		return nil, errors.New("wallet: amount+fee overflow")
	}
	if p.LockHeight > MaxLockHeight {
		return nil, errors.New("wallet: lock height out of range")
	}
	if len(s.st.Contexts) >= maxContexts {
		return nil, errors.New("wallet: too many in-flight payments; cancel or finish some")
	}
	magic, err := s.bindNetwork(node)
	if err != nil {
		return nil, err
	}
	// Make room BEFORE anything is selected or locked: a Pay that cannot record
	// its change output must fail cleanly, not brick the state file. A payment
	// is never refused by the soft record limit that rations imports and
	// receives: it consumes at least one input, so it cannot grow the set of
	// outputs that still matter.
	s.pruneLocked(s.st.Tip)
	if err := s.ensureSlot(); err != nil {
		return nil, err
	}
	need := p.Amount + int64(p.Fee)
	if p.Consolidate {
		need = math.MaxInt64 // never reached: selection stops at MaxBlockInputs
	}

	// Candidate order: largest first, deterministic.
	var cands []*OutputRecord
	for i := range s.st.Outputs {
		if s.st.Outputs[i].Status == StatusUnspent {
			cands = append(cands, &s.st.Outputs[i])
		}
	}
	// Outputs believed mature (per the last sync) are tried first so a long run
	// of immature coinbases cannot starve the query budget; every candidate is
	// still checked against the node before it is used.
	immatureHint := func(o *OutputRecord) bool { return s.st.Synced && o.MaturesAt > addSat(s.st.Tip, 1) }
	sort.SliceStable(cands, func(i, j int) bool {
		if hi, hj := immatureHint(cands[i]), immatureHint(cands[j]); hi != hj {
			return !hi
		}
		if cands[i].Value != cands[j].Value {
			if p.Consolidate {
				return cands[i].Value < cands[j].Value // merge the smallest first
			}
			return cands[i].Value > cands[j].Value
		}
		return cands[i].Commit < cands[j].Commit
	})

	var picked []selected
	var total, immature, shallow int64
	queries := 0
	for _, rec := range cands {
		if total >= need {
			break
		}
		if len(picked) == types.MaxBlockInputs {
			if p.Consolidate {
				break
			}
			return nil, ErrTooManyInputs
		}
		if queries >= maxSelectionQueries {
			break
		}
		queries++
		c, err := parseCommit(rec.Commit)
		if err != nil {
			return nil, err
		}
		info, err := node.UTXO(c)
		if err != nil {
			return nil, fmt.Errorf("wallet: checking %s on the node: %w", rec.Commit[:16], err)
		}
		if !info.Present {
			continue // stale record; `wallet sync` repairs it
		}
		if info.Features == types.OutputFeaturesCoinbase && !info.Mature {
			immature += rec.Value
			continue
		}
		if !s.deep(info) {
			shallow += rec.Value
			continue // not yet buried deep enough to spend safely
		}
		if rec.Value > math.MaxInt64-total {
			return nil, errors.New("wallet: balance overflow")
		}
		// The stored opening must reproduce the commitment before we commit to it.
		if err := checkOpening(rec); err != nil {
			return nil, err
		}
		total += rec.Value
		picked = append(picked, selected{rec: rec, feat: info.Features})
	}
	if p.Consolidate {
		if len(picked) < 2 {
			return nil, errors.New("wallet: fewer than two spendable outputs to merge")
		}
		if total <= int64(p.Fee) {
			return nil, errors.New("wallet: the outputs to merge are worth no more than the fee")
		}
		p.Amount, need = total-int64(p.Fee), total
	}
	if total < need {
		if immature > 0 {
			return nil, fmt.Errorf("%w (%d units are in immature coinbase outputs)", ErrInsufficientFunds, immature)
		}
		if shallow > 0 {
			return nil, fmt.Errorf("%w (%d units are not yet %d blocks deep)", ErrInsufficientFunds, shallow, s.minConf)
		}
		return nil, ErrInsufficientFunds
	}

	// x_s = r_change - sum(r_in).
	var xs secp.ModNScalar
	defer xs.Zero()
	var inputs []types.Input
	for _, sel := range picked {
		r, err := scalarFromBytes(sel.rec.Blinding)
		if err != nil {
			return nil, err
		}
		xs.Add(&r) // accumulate sum(r_in), negate below
		r.Zero()
		c, _ := parseCommit(sel.rec.Commit)
		inputs = append(inputs, types.Input{Features: sel.feat, Commit: c})
	}
	xs.Negate()

	change := total - need
	var changeOut *types.Output
	var changeRec *OutputRecord
	var changeScalar secp.ModNScalar
	defer changeScalar.Zero()
	if change > 0 {
		o, r, err := newOutput(change)
		if err != nil {
			return nil, err
		}
		changeOut, changeScalar = &o, r
		xs.Add(&r)
		rb := r.Bytes()
		changeRec = &OutputRecord{Commit: commitHex(o.Commit), Value: change, Blinding: append([]byte(nil), rb[:]...),
			Features: uint8(types.OutputFeaturesPlain), Status: StatusPending, Origin: OriginChange}
		Zeroize(rb[:])
	}
	if xs.IsZero() {
		return nil, errors.New("wallet: degenerate excess; retry")
	}
	Ps, err := pointOf(&xs)
	if err != nil {
		return nil, err
	}
	txid, err := newTxID(s)
	if err != nil {
		return nil, err
	}
	ks, err := deriveNonce(s.key, &xs, nonceContext(txid, p.Amount, p.Fee, p.LockHeight, inputs, changeOut, Ps))
	if err != nil {
		return nil, err
	}
	defer ks.Zero()
	Rs, err := pointOf(&ks)
	if err != nil {
		return nil, err
	}
	slate := &Slate{Stage: StageOffer, Magic: magic, TxID: txid, Amount: p.Amount, Fee: p.Fee, LockHeight: p.LockHeight,
		Inputs: inputs, Change: changeOut, SenderExc: Ps, SenderNon: Rs, Memo: p.Memo}
	offer, err := slate.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if _, err := slate.Encode(); err != nil { // size check before anything is persisted
		return nil, err
	}

	// Durable BEFORE the slate leaves this function.
	id := hex.EncodeToString(txid[:])
	xb, kb := xs.Bytes(), ks.Bytes()
	ctx := TxContext{TxID: id, Offer: offer, XS: append([]byte(nil), xb[:]...), KS: append([]byte(nil), kb[:]...), Created: s.now().Unix()}
	Zeroize(xb[:])
	Zeroize(kb[:])
	for _, sel := range picked {
		sel.rec.Status = StatusLocked
		sel.rec.LockedBy = id
		sel.rec.Features = uint8(sel.feat)
	}
	if changeRec != nil {
		changeRec.TxID = id
		changeRec.Created = s.now().Unix()
		s.st.Outputs = append(s.st.Outputs, *changeRec)
	}
	s.st.Contexts = append(s.st.Contexts, ctx)
	if err := s.commit(); err != nil {
		if errors.Is(err, ErrWrittenUnconfirmed) {
			return nil, fmt.Errorf("wallet: payment state is written but its durability is unconfirmed, slate withheld (cancel %s to release the inputs): %w", id, err)
		}
		return nil, fmt.Errorf("wallet: could not persist payment state, slate withheld: %w", err)
	}
	return slate, nil
}

func checkOpening(rec *OutputRecord) error {
	c, err := v2crypto.PedersenCommit(rec.Value, rec.Blinding)
	if err != nil || hex.EncodeToString(c[:]) != rec.Commit {
		return fmt.Errorf("wallet: output %s does not open to its stored value", rec.Commit[:16])
	}
	return nil
}

// ---- round 2: Receive ----------------------------------------------------

// Receive turns an offer into a response (round 2). The new output is recorded
// as pending before the response is returned.
func (s *Store) Receive(offer *Slate) (*Slate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receiveLocked(offer, false)
}

// receiveSelf answers an offer this wallet made itself (consolidation). It is
// exempt from the receive rations: such a payment shrinks the set of outputs.
func (s *Store) receiveSelf(offer *Slate) (*Slate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if offer == nil {
		return nil, slateErr("expected an offer slate")
	}
	if _, ctx := s.context(hex.EncodeToString(offer.TxID[:])); ctx == nil {
		return nil, ErrUnknownTx
	}
	return s.receiveLocked(offer, true)
}

func (s *Store) receiveLocked(offer *Slate, self bool) (*Slate, error) {
	if offer == nil || offer.Stage != StageOffer {
		return nil, slateErr("expected an offer slate")
	}
	if err := offer.Validate(); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(offer.TxID[:])
	for i := range s.st.Outputs {
		if s.st.Outputs[i].Origin == OriginReceive && s.st.Outputs[i].TxID == id {
			return nil, ErrReplay
		}
	}
	for i := range s.st.Archive { // an archived receive still remembers its session
		if s.st.Archive[i].TxID == id {
			return nil, ErrReplay
		}
	}
	if s.st.Magic == 0 {
		return nil, errors.New("wallet: network unknown; run `wallet sync` against a node (or pass the node address to receive) so the wallet can pin its network")
	}
	if offer.Magic != s.st.Magic {
		return nil, fmt.Errorf("%w (slate %08x, wallet %08x)", ErrNetwork, offer.Magic, s.st.Magic)
	}
	s.pruneLocked(s.st.Tip)
	if self {
		if err := s.ensureSlot(); err != nil {
			return nil, err
		}
	} else if err := s.roomFor(1); err != nil {
		return nil, err
	}
	pending := 0
	for i := range s.st.Outputs {
		if s.st.Outputs[i].Origin == OriginReceive && s.st.Outputs[i].Status == StatusPending {
			pending++
		}
	}
	if !self && pending >= maxPendingReceives {
		return nil, ErrTooManyPending
	}
	if !self && s.receiveArchived() >= maxArchived {
		return nil, ErrArchiveFull
	}
	if offer.Change != nil && !v2crypto.VerifyRange(offer.Change.Commit, offer.Change.RangeProof) {
		return nil, slateErr("change output range proof invalid")
	}

	out, rr, err := newOutput(offer.Amount)
	if err != nil {
		return nil, err
	}
	defer rr.Zero()
	Pr, err := pointOf(&rr) // x_r = r_r
	if err != nil {
		return nil, err
	}
	kr, err := randomScalar()
	if err != nil {
		return nil, err
	}
	defer kr.Zero()
	Rr, err := pointOf(&kr)
	if err != nil {
		return nil, err
	}
	E, err := v2crypto.PointAdd(offer.SenderExc, Pr)
	if err != nil {
		return nil, slateErr("degenerate excess")
	}
	R, err := v2crypto.PointAdd(offer.SenderNon, Rr)
	if err != nil {
		return nil, slateErr("degenerate nonce")
	}
	resp := *offer
	resp.Stage = StageResponse
	resp.RecvOutput = &out
	resp.RecvExc, resp.RecvNon = Pr, Rr
	// The whole equation must already balance: otherwise the sender could not
	// produce a valid transaction and we would hold a phantom output.
	if err := excessBalances(resp.Inputs, slateOutputs(&resp), resp.Fee, E); err != nil {
		return nil, slateErr("%v", err)
	}
	e, _ := challenge(resp.Magic, R, E, resp.Fee, resp.LockHeight)
	es, err := scalarFromBytes(e[:])
	if err != nil {
		return nil, err
	}
	sr := kr
	var t secp.ModNScalar
	t.Mul2(&es, &rr)
	sr.Add(&t)
	t.Zero()
	if sr.IsZero() {
		return nil, errors.New("wallet: degenerate partial signature; retry")
	}
	srb := sr.Bytes()
	resp.RecvPartial = srb
	sr.Zero()
	Zeroize(srb[:])
	if !v2crypto.VerifyPartialSchnorr(resp.RecvPartial, Rr, Pr, e) {
		return nil, errors.New("wallet: own partial signature failed verification")
	}
	if err := resp.Validate(); err != nil {
		return nil, err
	}

	rb := rr.Bytes()
	rec := OutputRecord{Commit: commitHex(out.Commit), Value: offer.Amount, Blinding: append([]byte(nil), rb[:]...),
		Features: uint8(types.OutputFeaturesPlain), Status: StatusPending, Origin: OriginReceive, TxID: id, Created: s.now().Unix()}
	Zeroize(rb[:])
	if s.output(rec.Commit) != nil || s.archived(rec.Commit) {
		return nil, errors.New("wallet: output commitment collision")
	}
	s.st.Outputs = append(s.st.Outputs, rec)
	if err := s.commit(); err != nil {
		if errors.Is(err, ErrWrittenUnconfirmed) {
			return nil, fmt.Errorf("wallet: received output is written but its durability is unconfirmed, response withheld: %w", err)
		}
		return nil, fmt.Errorf("wallet: could not persist received output, response withheld: %w", err)
	}
	return &resp, nil
}

// ---- round 3: Finalize ---------------------------------------------------

// FinalizeResult describes a finalized transaction.
type FinalizeResult struct {
	TxID        string // slate session id
	TxHash      string // types.TransactionID of the final transaction
	Excess      string // hex kernel excess of the final transaction
	Amount      int64
	Fee         uint64
	Resubmitted bool // the stored signed transaction was resubmitted; no new signature
	Warning     string
}

func respDigest(resp *Slate) (string, error) {
	raw, err := resp.MarshalBinary()
	if err != nil {
		return "", err
	}
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:]), nil
}

// Finalize completes the payment from the receiver's response and submits it.
func (s *Store) Finalize(node Node, resp *Slate) (*FinalizeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if resp == nil || resp.Stage != StageResponse {
		return nil, slateErr("expected a response slate")
	}
	if err := resp.Validate(); err != nil {
		return nil, err
	}
	magic, err := s.bindNetwork(node)
	if err != nil {
		return nil, err
	}
	if resp.Magic != magic {
		return nil, fmt.Errorf("%w (slate %08x, node %08x)", ErrNetwork, resp.Magic, magic)
	}
	id := hex.EncodeToString(resp.TxID[:])
	digest, err := respDigest(resp)
	if err != nil {
		return nil, err
	}

	// Already signed: never sign again, only resubmit the stored transaction.
	if _, sent := s.sent(id); sent != nil {
		if sent.Resp != digest {
			return nil, fmt.Errorf("%w: a different response was already used to sign this transaction", ErrTampered)
		}
		tx, err := DecodeTx(sent.Tx)
		if err != nil {
			return nil, err
		}
		// "Only after it is durable is anything submitted": the earlier write may
		// have been left unconfirmed (ErrWrittenUnconfirmed), so make the state
		// durable again before the transaction leaves this process.
		if err := s.commit(); err != nil {
			return nil, fmt.Errorf("wallet: the signed transaction %s is stored but the state could not be made durable; nothing was submitted, retry: %w", id, err)
		}
		return s.submit(node, sent.TxID, tx, resp, true)
	}

	_, ctx := s.context(id)
	if ctx == nil {
		return nil, ErrUnknownTx
	}
	if s.isSuspect(id) {
		return nil, ErrRolledBack
	}
	offer, err := UnmarshalSlate(ctx.Offer)
	if err != nil {
		return nil, fmt.Errorf("wallet: stored offer corrupt: %w", err)
	}
	if !offerEqual(offer, resp) {
		return nil, ErrTampered
	}

	// Receiver output: valid proof, unique commitment.
	ro := resp.RecvOutput
	if !v2crypto.VerifyRange(ro.Commit, ro.RangeProof) {
		return nil, slateErr("receiver output range proof invalid")
	}
	if resp.Change != nil && resp.Change.Commit == ro.Commit {
		return nil, slateErr("receiver output duplicates change")
	}
	for _, in := range resp.Inputs {
		if in.Commit == ro.Commit {
			return nil, slateErr("receiver output duplicates an input")
		}
	}
	// Unique among the wallet's own outputs. The one legitimate match is the
	// pending record created by Receive when this wallet pays itself.
	if rec := s.output(commitHex(ro.Commit)); rec != nil && (rec.Origin != OriginReceive || rec.TxID != id || rec.Status != StatusPending) {
		return nil, slateErr("receiver output already tracked by this wallet")
	}

	E, err := v2crypto.PointAdd(resp.SenderExc, resp.RecvExc)
	if err != nil {
		return nil, slateErr("degenerate excess")
	}
	R, err := v2crypto.PointAdd(resp.SenderNon, resp.RecvNon)
	if err != nil {
		return nil, slateErr("degenerate nonce")
	}
	outs := slateOutputs(resp)
	// The excess must be exactly what the commitments dictate.
	if err := excessBalances(resp.Inputs, outs, resp.Fee, E); err != nil {
		return nil, slateErr("%v", err)
	}
	e, kmsg := challenge(resp.Magic, R, E, resp.Fee, resp.LockHeight)
	if !v2crypto.VerifyPartialSchnorr(resp.RecvPartial, resp.RecvNon, resp.RecvExc, e) {
		return nil, slateErr("receiver partial signature invalid")
	}

	// Our partial. Stored secrets must reproduce the public values we offered.
	xs, err := scalarFromBytes(ctx.XS)
	if err != nil {
		return nil, err
	}
	defer xs.Zero()
	ks, err := scalarFromBytes(ctx.KS)
	if err != nil {
		return nil, err
	}
	defer ks.Zero()
	if p, err := pointOf(&xs); err != nil || p != resp.SenderExc {
		return nil, errors.New("wallet: stored excess scalar does not match the offer")
	}
	if p, err := pointOf(&ks); err != nil || p != resp.SenderNon {
		return nil, errors.New("wallet: stored nonce scalar does not match the offer")
	}
	es, err := scalarFromBytes(e[:])
	if err != nil {
		return nil, err
	}
	srs, err := scalarFromBytes(resp.RecvPartial[:])
	if err != nil {
		return nil, err
	}
	var ss secp.ModNScalar
	defer ss.Zero()
	ss.Mul2(&es, &xs)
	ss.Add(&ks)  // s_s = k_s + e*x_s
	ss.Add(&srs) // s = s_s + s_r
	if ss.IsZero() {
		return nil, errors.New("wallet: degenerate aggregate signature")
	}
	sb := ss.Bytes()
	sig := make([]byte, 65)
	copy(sig[:33], R[:])
	copy(sig[33:], sb[:])
	Zeroize(sb[:])
	if !v2crypto.SchnorrVerify(E, kmsg, sig) {
		return nil, errors.New("wallet: aggregate signature failed verification; nothing was released")
	}

	k := kernelHeader(resp.Fee, resp.LockHeight, E)
	k.ExcessSig = sig
	tx := &types.Transaction{Inputs: resp.Inputs, Outputs: outs, Kernels: []types.Kernel{k}}
	raw, err := EncodeTx(tx)
	if err != nil {
		return nil, err
	}

	// ONE atomic write: erase the nonce context, store the signed transaction,
	// commit the inputs as spent. Only after this is durable does anything leave.
	if len(s.st.Sent) >= maxSentTxs {
		if !s.pruneSent() {
			return nil, errors.New("wallet: too many unconfirmed transactions")
		}
	}
	inputHex := make([]string, len(resp.Inputs))
	for i, in := range resp.Inputs {
		inputHex[i] = commitHex(in.Commit)
		if rec := s.output(inputHex[i]); rec != nil {
			rec.Status = StatusSpent
			rec.LockedBy = id
		}
	}
	ci, _ := s.context(id)
	Zeroize(s.st.Contexts[ci].XS)
	Zeroize(s.st.Contexts[ci].KS)
	s.st.Contexts = append(s.st.Contexts[:ci], s.st.Contexts[ci+1:]...)
	s.st.Sent = append(s.st.Sent, SentTx{TxID: id, Tx: raw, Resp: digest, Inputs: inputHex, Created: s.now().Unix()})
	if err := s.commit(); err != nil {
		if errors.Is(err, ErrWrittenUnconfirmed) {
			return nil, fmt.Errorf("wallet: the signed transaction %s is stored but its durability is unconfirmed; nothing was released. Re-run finalize with the same slate to submit it: %w", id, err)
		}
		return nil, fmt.Errorf("wallet: could not persist the signed transaction; nothing was released: %w", err)
	}
	return s.submit(node, id, tx, resp, false)
}

// pruneSent drops the oldest confirmed signed transaction; false if none.
func (s *Store) pruneSent() bool {
	for i := range s.st.Sent {
		if s.st.Sent[i].Submitted && s.sentConfirmedLocked(&s.st.Sent[i]) {
			s.st.Sent = append(s.st.Sent[:i], s.st.Sent[i+1:]...)
			return true
		}
	}
	return false
}

func (s *Store) sentConfirmedLocked(t *SentTx) bool {
	for _, h := range t.Inputs {
		if o := s.output(h); o == nil || o.Status != StatusSpent || !o.ChainSpent {
			return false
		}
	}
	return true
}

func (s *Store) submit(node Node, id string, tx *types.Transaction, resp *Slate, resubmit bool) (*FinalizeResult, error) {
	hash := types.TransactionID(tx)
	res := &FinalizeResult{TxID: id, TxHash: hex.EncodeToString(hash[:]), Excess: commitHex(tx.Kernels[0].Excess), Amount: resp.Amount, Fee: resp.Fee, Resubmitted: resubmit}
	if err := node.Submit(tx); err != nil {
		switch {
		case errors.Is(err, ErrPolicyRefused):
			return res, fmt.Errorf("wallet: transaction %s is signed and stored; the node did not admit it right now (%w). It may still be mined: do NOT cancel it. Re-run finalize with the same slate later", id, err)
		case errors.Is(err, ErrRejected):
			return res, fmt.Errorf("wallet: transaction %s is signed and stored but the node rejected it (%w); re-run finalize with the same slate to retry. Only if it can never be mined, `wallet cancel --force` releases the inputs (cancelling a transaction that is later mined pays twice)", id, err)
		}
		return res, fmt.Errorf("wallet: transaction %s is signed and stored but was not accepted (%w); re-run finalize with the same slate to retry", id, err)
	}
	if i, t := s.sent(id); t != nil && !t.Submitted {
		t.Submitted = true
		_ = i
		if err := s.commit(); err != nil {
			res.Warning = "transaction accepted by the node but marking it submitted failed: " + err.Error()
		}
	}
	return res, nil
}

// ---- cancel --------------------------------------------------------------

// Cancel abandons a payment. Before signing it unlocks the inputs, drops the
// change output and destroys the nonce context. After signing (the
// transaction was stored) it requires force: the inputs are released but the
// change output stays tracked as pending, because the transaction may still be
// mined from some node's mempool.
func (s *Store) Cancel(txid string, force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, err := hex.DecodeString(txid); err != nil || len(b) != 16 {
		return errors.New("wallet: bad transaction id")
	}
	if ci, ctx := s.context(txid); ctx != nil {
		for i := range s.st.Outputs {
			o := &s.st.Outputs[i]
			if o.LockedBy == txid && o.Status == StatusLocked {
				o.Status, o.LockedBy = StatusUnspent, ""
				if o.Height == 0 && o.BlockHash == "" {
					o.Status = StatusPending // its block left the chain while it was locked
				}
			}
		}
		suspect := s.isSuspect(txid)
		s.st.Suspect = removeString(s.st.Suspect, txid)
		kept := s.st.Outputs[:0]
		for _, o := range s.st.Outputs {
			if o.Origin == OriginChange && o.TxID == txid && o.Status == StatusPending {
				if !suspect {
					// Never signed: the change belongs to a transaction that
					// cannot exist any more.
					Zeroize(o.Blinding)
					continue
				}
				// A restored backup: this payment may have been signed and mined
				// in the timeline that was rolled back, and then this change is
				// real money. Keep the key (archive; if that is impossible, keep
				// the live record). Sync revives it if the transaction is on chain.
				if s.archiveOutput(&o, archReasonChange) {
					Zeroize(o.Blinding)
					continue
				}
			}
			kept = append(kept, o)
		}
		s.st.Outputs = kept
		Zeroize(s.st.Contexts[ci].XS)
		Zeroize(s.st.Contexts[ci].KS)
		s.st.Contexts = append(s.st.Contexts[:ci], s.st.Contexts[ci+1:]...)
		return s.commit()
	}
	if si, sent := s.sent(txid); sent != nil {
		if !force {
			return errors.New("wallet: transaction is already signed; the nonce is already destroyed. Use --force to release its inputs (it may still be mined)")
		}
		for i := range s.st.Outputs {
			o := &s.st.Outputs[i]
			if o.LockedBy == txid && o.Status == StatusSpent && !o.ChainSpent {
				o.Status, o.LockedBy = StatusUnspent, ""
			}
		}
		s.st.Sent = append(s.st.Sent[:si], s.st.Sent[si+1:]...)
		return s.commit()
	}
	return ErrUnknownTx
}

// ---- import --------------------------------------------------------------

// ImportReport summarizes an import-coinbase run.
type ImportReport struct {
	Imported  int
	Duplicate int
	Invalid   int
	Files     int // coinbase files read (the live file plus archived rotations)
	Skipped   int // not imported because the wallet holds the maximum number of unfinished outputs; the keys stay in the file you imported from. Run `wallet consolidate`, sync, and import again
}

// CoinbaseArchives lists the archived rotations of a coinbases file
// ("<path>.<unixnano>.<n>", written by CoinbaseStore when a file fills up),
// oldest first. They are complete, importable coinbase files: a wallet that
// reads only the live file misses every key in them.
func CoinbaseArchives(path string) ([]string, error) {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type arch struct {
		name string
		ts   int64
		n    int64
	}
	var found []arch
	for _, e := range ents {
		rest, ok := strings.CutPrefix(e.Name(), base+".")
		if !ok || !e.Type().IsRegular() {
			continue
		}
		tsS, nS, ok := strings.Cut(rest, ".")
		if !ok {
			continue
		}
		ts, err1 := strconv.ParseInt(tsS, 10, 64)
		n, err2 := strconv.ParseInt(nS, 10, 64)
		if err1 != nil || err2 != nil || ts < 0 || n < 0 {
			continue
		}
		found = append(found, arch{filepath.Join(dir, e.Name()), ts, n})
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].ts != found[j].ts {
			return found[i].ts < found[j].ts
		}
		return found[i].n < found[j].n
	})
	out := make([]string, len(found))
	for i, f := range found {
		out[i] = f.name
	}
	return out, nil
}

// ImportCoinbase brings in miner reward keys from a coinbases.json file AND
// from every archived rotation of it beside it ("coinbases.json.<ts>.<n>"). A
// missing live file is fine when archives exist (the miner may have crashed
// right after rotating). Each record's commitment is recomputed from (amount,
// blinding) and must match. Imported outputs are pending until `sync` finds
// them on chain; records for candidate blocks that never landed simply stay
// pending.
func (s *Store) ImportCoinbase(path string) (ImportReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var rep ImportReport
	archives, err := CoinbaseArchives(path)
	if err != nil {
		return rep, err
	}
	files := archives
	if _, err := os.Lstat(path); err == nil {
		files = append(files, path)
	} else if !os.IsNotExist(err) || len(archives) == 0 {
		return rep, err
	}
	s.pruneLocked(s.st.Tip)
	for _, f := range files {
		if err := s.importCoinbaseFileLocked(f, &rep); err != nil {
			s.reload() // nothing from this run is written
			return rep, err
		}
		rep.Files++
	}
	if rep.Imported == 0 {
		return rep, nil
	}
	return rep, s.commit()
}

func (s *Store) importCoinbaseFileLocked(path string, rep *ImportReport) error {
	raw, err := readBoundedSecret(path)
	if err != nil {
		return err
	}
	defer Zeroize(raw)
	var recs []CoinbaseRecord
	dec := jsonDecoderStrict(raw)
	if err := dec.Decode(&recs); err != nil {
		return fmt.Errorf("wallet: coinbases file %s: %w", path, err)
	}
	if len(recs) > 10000 {
		return errors.New("wallet: too many coinbase records")
	}
	nonFinal := s.nonFinal()
	for i := range recs {
		rec := &recs[i]
		func() {
			defer Zeroize(rec.Blinding[:])
			if rec.Amount <= 0 || !v2crypto.ValidPublicPoint(rec.Commit) {
				rep.Invalid++
				return
			}
			want, err := v2crypto.PedersenCommit(rec.Amount, rec.Blinding[:])
			if err != nil || want != rec.Commit {
				rep.Invalid++
				return
			}
			h := hex.EncodeToString(rec.Commit[:])
			if s.output(h) != nil {
				rep.Duplicate++
				return
			}
			if nonFinal >= maxOutputRecords || len(s.st.Outputs) >= maxLoadRecords-1 {
				rep.Skipped++
				return
			}
			nonFinal++
			s.st.Outputs = append(s.st.Outputs, OutputRecord{Commit: h, Value: rec.Amount, Blinding: append([]byte(nil), rec.Blinding[:]...),
				Features: uint8(types.OutputFeaturesCoinbase), Status: StatusPending, Origin: OriginCoinbase, Height: rec.Height, Created: s.now().Unix()})
			rep.Imported++
		}()
	}
	return nil
}

func jsonDecoderStrict(raw []byte) *json.Decoder {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec
}

func removeString(l []string, v string) []string {
	out := l[:0]
	for _, x := range l {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// bindNetwork asks the node for its network magic and pins the wallet to it on
// first contact; a later mismatch is a hard error (the wallet never mixes
// networks).
func (s *Store) bindNetwork(node Node) (uint32, error) {
	magic, err := node.NetworkMagic()
	if err != nil {
		return 0, fmt.Errorf("wallet: reading the node's network: %w", err)
	}
	if magic == 0 {
		return 0, errors.New("wallet: node reported no network")
	}
	if s.st.Magic != 0 && s.st.Magic != magic {
		return 0, fmt.Errorf("%w (wallet is bound to %08x, node is %08x)", ErrNetwork, s.st.Magic, magic)
	}
	if s.st.Magic == 0 {
		s.st.Magic = magic
		if err := s.commit(); err != nil && !errors.Is(err, ErrWrittenUnconfirmed) {
			return 0, err
		}
	}
	return magic, nil
}

// SetNetwork pins the wallet to the network magic (used by `wallet receive`
// when it is given a node, and by tests).
func (s *Store) SetNetwork(magic uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if magic == 0 {
		return errors.New("wallet: zero network magic")
	}
	if s.st.Magic != 0 && s.st.Magic != magic {
		return ErrNetwork
	}
	if s.st.Magic == magic {
		return nil
	}
	s.st.Magic = magic
	return s.commit()
}

// ---- consolidation ---------------------------------------------------------

// Consolidate merges up to types.MaxBlockInputs of the smallest spendable
// outputs into one, paying the wallet itself, in one call: offer, answer and
// finalize. It frees room in a wallet that is full of small outputs (a miner's
// coinbases). Run it repeatedly (outputs it creates become spendable after the
// confirmation depth). On a failure before signing the payment is cancelled.
func (s *Store) Consolidate(node Node, fee uint64) (*FinalizeResult, error) {
	offer, err := s.Pay(node, PayParams{Fee: fee, Consolidate: true, Memo: "consolidate"})
	if err != nil {
		return nil, err
	}
	id := hex.EncodeToString(offer.TxID[:])
	resp, err := s.receiveSelf(offer)
	if err != nil {
		if cerr := s.Cancel(id, false); cerr != nil {
			err = fmt.Errorf("%w (and cancelling %s failed: %v)", err, id, cerr)
		}
		return nil, err
	}
	res, err := s.Finalize(node, resp)
	if err != nil && res != nil {
		// Signed but not accepted: the slate was never shown, so "re-run finalize"
		// is not available. The payment only pays this wallet, and every key it
		// involves (the merged output's included) is kept either way.
		err = fmt.Errorf("consolidation %s is signed and stored but the node did not accept it: %w. It pays only yourself: `wallet cancel <wallet> %s --force` releases the inputs and you can run consolidate again", res.TxID, err, res.TxID)
	}
	return res, err
}
