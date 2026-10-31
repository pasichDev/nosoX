package wallet

import (
	"errors"
	"fmt"
	"time"

	"github.com/pasichDev/noso-go/v2/types"
)

// The tip a node reports is the node's word. It drives which records count as
// buried, so it is bounded before it is believed:
//
//   - every answer of one sync must agree within tipSpread blocks, and the
//     horizons are measured against the LOWEST one;
//   - it cannot exceed what the elapsed chain time allows (the fastest plausible
//     block interval is a twelfth of the target) since a fixed reference date;
//   - it cannot rise faster than that since the previous sync, unless the user
//     names the new tip (`wallet sync --accept-tip`);
//   - falling is accepted (a correct node returning after a lying one must work).
//
// These checks are a second line. The first is that no key is ever destroyed on
// a tip: finished records move to the encrypted archive.
const (
	tipSpread = 64
	// minBlockSeconds is the fastest block interval a node may claim.
	minBlockSeconds uint64 = uint64(types.TargetBlockTimeSeconds) / 12
	// tipAllowanceSlack is added to the blocks the elapsed time allows.
	tipAllowanceSlack = 64
	// unknownElapsed stands in for the time since the last sync when a state
	// written by an older build has no timestamp.
	unknownElapsed = 30 * 24 * time.Hour
)

// plausibilityEpoch is a date before the network existed; chain time is
// measured from it, which only makes the bound looser.
var plausibilityEpoch = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// Tip errors. A TipError wraps one of them.
var (
	ErrTipImplausible  = errors.New("wallet: the node reports a chain height that is impossible")
	ErrTipInconsistent = errors.New("wallet: the node's answers disagree about the chain height")
	ErrTipJump         = errors.New("wallet: the node reports a chain height far above the last sync")
)

// TipError carries the heights involved.
type TipError struct {
	Err      error
	Reported uint64
	Previous uint64
}

func (e *TipError) Error() string {
	if errors.Is(e.Err, ErrTipJump) {
		return fmt.Sprintf("%v (reported %d, last sync %d). Nothing was changed. If this node is yours and the jump is real, repeat with --accept-tip %d", e.Err, e.Reported, e.Previous, e.Reported)
	}
	return fmt.Sprintf("%v (reported %d). Nothing was changed", e.Err, e.Reported)
}
func (e *TipError) Unwrap() error { return e.Err }

// maxPlausibleTip is the highest height a node could honestly report at now.
func maxPlausibleTip(now time.Time) uint64 {
	if now.Before(plausibilityEpoch) {
		return 1 << 20
	}
	return uint64(now.Sub(plausibilityEpoch)/time.Second)/minBlockSeconds + 1<<20
}

// checkTip validates the heights seen in one sync. low and high are the lowest
// and highest tip reported; accept is the user-confirmed tip (0 = none).
func (s *Store) checkTip(low, high, accept uint64) error {
	now := s.now()
	if high > maxPlausibleTip(now) {
		return &TipError{Err: ErrTipImplausible, Reported: high, Previous: s.st.Tip}
	}
	if high-low > tipSpread {
		return &TipError{Err: ErrTipInconsistent, Reported: high, Previous: s.st.Tip}
	}
	if !s.st.Synced {
		return nil
	}
	elapsed := unknownElapsed
	if s.st.SyncedAt > 0 {
		elapsed = now.Sub(time.Unix(s.st.SyncedAt, 0))
		if elapsed < 0 {
			elapsed = 0
		}
	}
	allowed := addSat(s.st.Tip, addSat(uint64(elapsed/time.Second)/minBlockSeconds, tipAllowanceSlack))
	if low > allowed {
		if accept != 0 && absDiff(accept, high) <= tipSpread {
			return nil
		}
		return &TipError{Err: ErrTipJump, Reported: high, Previous: s.st.Tip}
	}
	return nil
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// sanitizeTip repairs a state that holds an impossible tip (written by a build
// without these checks after a lying node): the tip is forgotten and the next
// sync starts afresh. It reports whether it changed anything.
func (s *Store) sanitizeTip() bool {
	if s.st.Tip <= maxPlausibleTip(s.now()) {
		return false
	}
	s.st.Tip, s.st.Synced, s.st.SyncedAt = 0, false, 0
	for i := range s.st.Outputs {
		s.st.Outputs[i].SpentTip = 0
	}
	return true
}
