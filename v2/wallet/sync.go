package wallet

import (
	"fmt"

	"github.com/pasichDev/nosoX/v2/types"
)

// SyncTrustNotice is attached to every report: confirmations are the node's
// word.
const SyncTrustNotice = "Confirmations, balances and spent/unspent status are the answers of the node you synced with. A node you do not control can report a payment as confirmed that is not, or hide one that is. Wait for confirmations from a node you run before handing over goods."

// SyncReport counts what a sync changed.
type SyncReport struct {
	Tip         uint64
	Confirmed   int      // pending -> unspent (buried at least the confirmation depth)
	Shallow     int      // on chain but not yet deep enough to count as confirmed
	Spent       int      // seen spent on chain
	Restored    int      // spent/unspent state rolled back by a reorg
	Reorged     int      // outputs whose creating block left the chain
	ReorgedTxs  []string // signed transactions that left the chain; finalize again to resubmit
	Unconfirmed int
	Pruned      int    // finished records moved to the archive (spent for pruneDepth blocks, stale candidates, abandoned change); keys are kept
	Notice      string // what the numbers rest on
	Archived    int    // expired unconfirmed receives moved to the archive (kept, not deleted)
	Revived     int    // archived receives that appeared on chain and became live records again
}

// Sync reconciles tracked outputs with the node. It is not monotonic: a reorg
// can move outputs backwards (confirmed -> pending, spent -> unspent) and the
// next sync moves them forward again. State is written once at the end, and not
// at all if the node could not be queried completely.
//
// Privacy: the node learns every commitment queried. Records that can no
// longer change (spent on chain for pruneDepth blocks) are not queried, so the
// node is asked only about outputs that are pending, unspent, locked, or spent
// too recently to be final.
func (s *Store) Sync(node Node) (*SyncReport, error) { return s.SyncWith(node, SyncOptions{}) }

// SyncOptions tunes Sync.
type SyncOptions struct {
	// AcceptTip confirms a tip far above the previous sync (see checkTip). Zero
	// means no confirmation.
	AcceptTip uint64
}

// archiveQueryBudget bounds how many archive entries one sync asks about; the
// rest are asked on later syncs (the archive is walked round-robin).
const archiveQueryBudget = 1024

// SyncWith is Sync with options.
func (s *Store) SyncWith(node Node, opt SyncOptions) (*SyncReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rep := &SyncReport{Notice: SyncTrustNotice}
	if _, err := s.bindNetwork(node); err != nil {
		return nil, err
	}
	var lowTip, highTip uint64
	haveTip := false
	note := func(info UTXOInfo) error {
		if info.Present && info.Height > info.Tip {
			return &TipError{Err: ErrTipInconsistent, Reported: info.Tip, Previous: s.st.Tip}
		}
		if !haveTip || info.Tip < lowTip {
			lowTip = info.Tip
		}
		if !haveTip || info.Tip > highTip {
			highTip = info.Tip
		}
		haveTip = true
		return nil
	}

	// Archived receives: the sender may mine the finished transaction long
	// after the live record expired. Ask the node about each one and bring any
	// that appeared back as a live pending record (the loop below then treats
	// it like any other). Nothing is mutated before every answer is in.
	var revive []int
	if n := len(s.st.Archive); n > 0 {
		budget := min(n, archiveQueryBudget)
		start := s.st.ArchiveCursor % n
		for k := 0; k < budget; k++ {
			i := (start + k) % n
			c, err := parseCommit(s.st.Archive[i].Commit)
			if err != nil {
				return nil, err
			}
			info, err := node.UTXO(c)
			if err != nil {
				return nil, fmt.Errorf("wallet: sync: %w", err)
			}
			if err := note(info); err != nil {
				return nil, err
			}
			if info.Present {
				revive = append(revive, i)
			}
		}
		s.st.ArchiveCursor = (start + budget) % n
	}
	if len(revive) > 0 {
		room := maxLoadRecords - len(s.st.Outputs)
		if len(revive) > room {
			revive = revive[:max(room, 0)] // the rest stay archived until there is room
		}
		revived := map[int]bool{}
		for _, i := range revive {
			a := &s.st.Archive[i]
			s.st.Outputs = append(s.st.Outputs, OutputRecord{Commit: a.Commit, Value: a.Value,
				Blinding: append([]byte(nil), a.Blinding...), Features: uint8(types.OutputFeaturesPlain),
				Status: StatusPending, Origin: OriginReceive, TxID: a.TxID, Created: s.now().Unix()})
			if a.retired() { // a retired key returns as what it was, not as a receive
				o := &s.st.Outputs[len(s.st.Outputs)-1]
				o.Origin, o.Features, o.Height = a.Origin, a.Features, a.Height
			}
			revived[i] = true
			rep.Revived++
		}
		keptArch := s.st.Archive[:0]
		for i, a := range s.st.Archive {
			if revived[i] {
				Zeroize(a.Blinding)
				continue
			}
			keptArch = append(keptArch, a)
		}
		for i := len(keptArch); i < len(s.st.Archive); i++ {
			s.st.Archive[i] = ArchivedReceive{}
		}
		s.st.Archive = keptArch
	}

	skip := func(o *OutputRecord) bool { // final: nothing a node could tell us changes it
		return o.Status == StatusSpent && o.ChainSpent && o.SpentTip > 0 && s.st.Synced && reachesDepth(s.st.Tip, o.SpentTip, pruneDepth)
	}
	observed := make([]UTXOInfo, len(s.st.Outputs))
	for i := range s.st.Outputs {
		if skip(&s.st.Outputs[i]) {
			continue
		}
		c, err := parseCommit(s.st.Outputs[i].Commit)
		if err != nil {
			s.reload()
			return nil, err
		}
		info, err := node.UTXO(c)
		if err != nil {
			s.reload() // drop revived archive entries: nothing is written
			return nil, fmt.Errorf("wallet: sync: %w", err)
		}
		if err := note(info); err != nil {
			s.reload()
			return nil, err
		}
		observed[i] = info
	}
	// Horizons are measured against the LOWEST tip any answer reported.
	tip := s.st.Tip // nothing queried, nothing learned
	if haveTip {
		tip = lowTip
		if err := s.checkTip(lowTip, highTip, opt.AcceptTip); err != nil {
			s.reload() // drop revived archive entries: nothing is written
			return nil, err
		}
	}
	now := s.now()
	drop := make([]bool, len(s.st.Outputs))

	for i := range s.st.Outputs {
		o := &s.st.Outputs[i]
		if skip(o) {
			continue
		}
		info := observed[i]
		if info.Present {
			if uint8(info.Features) != o.Features {
				o.Features = uint8(info.Features)
			}
			o.MaturesAt, o.BlockHash = info.MaturesAt, info.BlockHash
			if info.Height > 0 {
				o.Height = info.Height
			}
			wasChainSpent := o.ChainSpent
			o.ChainSpent, o.SpentTip = false, 0
			switch o.Status {
			case StatusPending:
				if s.deep(info) {
					o.Status = StatusUnspent
					rep.Confirmed++
				} else {
					rep.Shallow++
				}
			case StatusSpent:
				if o.LockedBy == "" || !s.knowsTx(o.LockedBy) {
					// A reorg un-spent it, or the transaction that spent it
					// is gone from our records (pruned, then reorged out).
					o.Status, o.LockedBy = StatusUnspent, ""
					rep.Restored++
				} else if wasChainSpent {
					// Our signed tx had confirmed and has now left the chain.
					rep.Restored++
					if _, t := s.sent(o.LockedBy); t != nil && t.Submitted {
						t.Submitted = false
						rep.ReorgedTxs = appendUnique(rep.ReorgedTxs, o.LockedBy)
					}
				} else {
					rep.Unconfirmed++
				}
			}
			continue
		}
		// Absent from the UTXO set.
		switch o.Status {
		case StatusPending:
			// Not on chain (yet). Candidates and unconfirmed receives that never
			// landed are archived (never deleted) once final.
			switch {
			case o.Origin == OriginCoinbase && o.Height > 0 && reachesDepth(tip, o.Height, pruneDepth):
				// A candidate the chain never took. Still never deleted: a node
				// saying "absent" is not proof the block cannot exist.
				if s.archiveOutput(o, archReasonCandidate) {
					drop[i] = true
					rep.Pruned++
				}
			case o.Origin == OriginReceive && o.Created > 0 && now.Sub(timeFromUnix(o.Created)) > pendingReceiveTTL:
				// Never delete: the key may still control money. Archive it
				// (kept encrypted, matched on every sync); if the archive is
				// full the live record stays.
				if s.archiveOutput(o, "") {
					drop[i] = true
					rep.Archived++
				}
			case o.Origin == OriginChange && o.Created > 0 && now.Sub(timeFromUnix(o.Created)) > pendingReceiveTTL && !s.hasContext(o.TxID):
				// Change of a payment that never reached a block (cancelled
				// after signing, or its input was spent elsewhere). Kept.
				if s.archiveOutput(o, archReasonChange) {
					drop[i] = true
					rep.Pruned++
				}
			}
		case StatusSpent:
			if o.ChainSpent {
				break
			}
			// Spent by our transaction and no longer an output: confirmed spent,
			// unless the block that created it was reorged out (then it is not
			// spent, merely missing). A record whose creating block is unknown
			// (it was cleared by a reorg) cannot be judged: leave it unconfirmed.
			if o.BlockHash == "" {
				rep.Unconfirmed++
				break
			}
			if reorged, err := s.createdBlockGone(node, o); err != nil {
				s.reload()
				return nil, fmt.Errorf("wallet: sync: %w", err)
			} else if reorged {
				rep.Reorged++
				break
			}
			o.ChainSpent, o.SpentTip = true, tip
			rep.Spent++
		case StatusUnspent, StatusLocked:
			// Either spent on chain, or the block that created it was reorged out.
			reorged, err := s.createdBlockGone(node, o)
			if err != nil {
				s.reload() // drop the in-place edits made so far: nothing is written
				return nil, fmt.Errorf("wallet: sync: %w", err)
			}
			switch {
			case reorged && o.Status == StatusLocked:
				// Still reserved by a live payment: keep the reservation, forget
				// where it was mined. It must not become selectable again.
				o.Height, o.BlockHash, o.MaturesAt, o.ChainSpent = 0, "", 0, false
				rep.Reorged++
			case reorged:
				o.Status, o.BlockHash, o.MaturesAt = StatusPending, "", 0
				if o.Origin != OriginCoinbase {
					o.Height = 0 // a coinbase keeps its claimed height, so a candidate that never lands can be archived
				}
				o.ChainSpent = false
				rep.Reorged++
			case o.Status == StatusUnspent:
				o.Status, o.ChainSpent, o.SpentTip = StatusSpent, true, tip
				rep.Spent++
			}
			// A locked input that vanished stays locked: cancel the payment.
		}
	}
	for i := range s.st.Outputs {
		o := &s.st.Outputs[i]
		if o.Status == StatusSpent && o.ChainSpent && o.SpentTip == 0 {
			o.SpentTip = tip // records from before the prune horizon existed
		}
	}
	for i := range s.st.Sent {
		t := &s.st.Sent[i]
		if !t.Submitted && s.sentConfirmedLocked(t) {
			t.Submitted = true // it reached a block through some other node
		}
	}
	kept := s.st.Outputs[:0]
	for i, o := range s.st.Outputs {
		if drop[i] {
			Zeroize(o.Blinding) // the archive holds its own copy
			continue
		}
		kept = append(kept, o)
	}
	for i := len(kept); i < len(s.st.Outputs); i++ {
		s.st.Outputs[i] = OutputRecord{}
	}
	s.st.Outputs = kept
	_, moved := s.pruneCount(tip)
	rep.Pruned += moved
	s.st.Tip, s.st.Synced, s.st.SyncedAt = tip, true, now.Unix()
	rep.Tip = tip
	if err := s.commit(); err != nil {
		return nil, err
	}
	return rep, nil
}

// createdBlockGone reports whether the block that created o (as last seen) is no
// longer canonical. Records without a known block are not judged gone.
func (s *Store) createdBlockGone(node Node, o *OutputRecord) (bool, error) {
	if o.BlockHash == "" || o.Height == 0 {
		return false, nil
	}
	h, ok, err := node.BlockHash(o.Height)
	if err != nil {
		return false, err
	}
	return !ok || h != o.BlockHash, nil
}

// hasContext reports whether a live nonce context exists for txid.
func (s *Store) hasContext(txid string) bool { _, c := s.context(txid); return c != nil }

// knowsTx reports whether txid names a live context or a stored signed transaction.
func (s *Store) knowsTx(txid string) bool {
	if _, c := s.context(txid); c != nil {
		return true
	}
	_, t := s.sent(txid)
	return t != nil
}

func appendUnique(l []string, v string) []string {
	for _, x := range l {
		if x == v {
			return l
		}
	}
	return append(l, v)
}
