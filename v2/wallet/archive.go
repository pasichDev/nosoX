package wallet

import "errors"

// Reasons an output was moved to the archive. "" is an unconfirmed receive that
// outlived pendingReceiveTTL (the sender may still mine it).
const (
	archReasonSpent     = "spent"     // seen spent on chain pruneDepth blocks ago, on a node's word
	archReasonCandidate = "candidate" // coinbase candidate that never landed
	archReasonChange    = "change"    // change of a payment that was abandoned or never seen
)

func (a *ArchivedReceive) retired() bool { return a.Reason != "" }

// archiveCounts returns how many receive and retired entries the archive holds.
func (s *Store) archiveCounts() (recv, retired int) {
	for i := range s.st.Archive {
		if s.st.Archive[i].retired() {
			retired++
		} else {
			recv++
		}
	}
	return
}

// receiveArchived is the number of archived unconfirmed receives.
func (s *Store) receiveArchived() int { r, _ := s.archiveCounts(); return r }

// archiveOutput copies o (blinding included) to the archive. It returns false
// when that section is full; the caller then keeps the live record, so nothing
// is ever deleted for lack of room. Retired entries are evicted only to make
// room, oldest first, and only when older than retiredRetention by the local
// clock (never because of anything a node said).
func (s *Store) archiveOutput(o *OutputRecord, reason string) bool {
	recv, retired := s.archiveCounts()
	if reason == "" {
		if recv >= maxArchived {
			return false
		}
	} else if retired >= maxRetired && !s.evictOldRetired() {
		return false
	}
	e := ArchivedReceive{Commit: o.Commit, Value: o.Value, Blinding: append([]byte(nil), o.Blinding...),
		TxID: o.TxID, Created: o.Created, Reason: reason, Archived: s.now().Unix()}
	if reason != "" {
		e.Origin, e.Features, e.Height = o.Origin, o.Features, o.Height
	}
	s.st.Archive = append(s.st.Archive, e)
	return true
}

// evictOldRetired drops the oldest retired entry that is older than
// retiredRetention. It reports whether room was made.
func (s *Store) evictOldRetired() bool {
	now := s.now().Unix()
	oldest := -1
	for i := range s.st.Archive {
		a := &s.st.Archive[i]
		if !a.retired() || a.Archived <= 0 || now-a.Archived < int64(retiredRetention.Seconds()) {
			continue
		}
		if oldest < 0 || a.Archived < s.st.Archive[oldest].Archived {
			oldest = i
		}
	}
	if oldest < 0 {
		return false
	}
	Zeroize(s.st.Archive[oldest].Blinding)
	s.st.Archive = append(s.st.Archive[:oldest], s.st.Archive[oldest+1:]...)
	return true
}

// CancelReceive abandons an unconfirmed incoming payment: the live pending
// record is moved to the archive (its key is kept: the sender may still hold a
// finished transaction and mine it), which frees a slot in the pending quota.
// The offer cannot be answered again.
func (s *Store) CancelReceive(txid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.st.Outputs {
		o := &s.st.Outputs[i]
		if o.Origin != OriginReceive || o.TxID != txid {
			continue
		}
		if o.Status != StatusPending {
			return errors.New("wallet: that payment is already confirmed on chain; there is nothing to cancel")
		}
		if !s.archiveOutput(o, "") {
			return ErrArchiveFull
		}
		Zeroize(o.Blinding)
		s.st.Outputs = append(s.st.Outputs[:i], s.st.Outputs[i+1:]...)
		return s.commit()
	}
	return errors.New("wallet: no unconfirmed incoming payment with that id")
}
