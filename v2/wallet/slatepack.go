package wallet

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
)

// A slate is the message exchanged between sender and receiver to build one
// two-party Mimblewimble transaction. Format version 3 (prefix "SLATEPACK3.")
// adds the network magic to version 2; version 1 (Ed25519 intent) and version 2
// slates are rejected.
//
//	Stage 1 (offer):    sender -> receiver
//	Stage 2 (response): receiver -> sender
//
// There is no third slate: the sender finalizes locally and submits the
// transaction to a node.
//
// The wire form is a fixed binary layout (see Slate.MarshalBinary) wrapped in
// unpadded base64url. Decoding is bounded and strict: every count is capped
// before allocation, points must be valid non-identity curve points, scalars
// canonical and non-zero, and trailing bytes are an error.

// SlateStage tracks where the slate is in the 2-message handshake.
type SlateStage uint8

const (
	StageOffer    SlateStage = 1
	StageResponse SlateStage = 2
)

const (
	// SlateVersion is the only supported slate format version.
	SlateVersion = 3
	// SlatePrefix starts every encoded slate.
	SlatePrefix        = "SLATEPACK3."
	legacySlatePrefix  = "SLATEPACK1."
	legacySlatePrefix2 = "SLATEPACK2."

	// MaxSlateEncoded bounds the text form (a full response slate is ~40 KB).
	MaxSlateEncoded = 64 << 10
	// MaxSlateMemo bounds the free-text memo in bytes.
	MaxSlateMemo = 256
	// MaxLockHeight caps a requested kernel lock height as a sanity bound.
	MaxLockHeight = uint64(1) << 40
	// MaxSlateInputs: a transaction may spend at most MaxBlockInputs outputs.
	MaxSlateInputs = types.MaxBlockInputs
)

// Slate is the exchanged object. Sender fields are fixed by the offer; the
// receiver adds the Recv* fields. The slate never carries a secret.
type Slate struct {
	Stage      SlateStage
	TxID       [16]byte // random session id chosen by the sender
	Magic      uint32   // network magic the kernel signature is bound to
	Amount     int64    // value the receiver's output will hold
	Fee        uint64   // kernel fee, paid by the sender
	LockHeight uint64   // kernel lock height
	Inputs     []types.Input
	Change     *types.Output // sender's change output, nil when change is zero
	SenderExc  types.Commitment
	SenderNon  types.Commitment
	Memo       string

	// Response-only.
	RecvOutput  *types.Output
	RecvExc     types.Commitment
	RecvNon     types.Commitment
	RecvPartial [32]byte
}

// ErrSlate is wrapped by slate validation failures.
var ErrSlate = errors.New("wallet: invalid slate")

func slateErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrSlate, fmt.Sprintf(format, a...))
}

// canonicalScalar reports whether b is a non-zero scalar below the group order.
func canonicalScalar(b [32]byte) bool {
	var s secp.ModNScalar
	return s.SetBytes(&b) == 0 && !s.IsZero()
}

// validateOffer checks the sender-side fields shared by both stages.
func (s *Slate) validateOffer() error {
	if s.Magic == 0 {
		return slateErr("missing network magic")
	}
	if s.Amount <= 0 {
		return slateErr("amount must be positive")
	}
	if s.Fee > math.MaxInt64 || uint64(s.Amount) > math.MaxInt64-s.Fee {
		return slateErr("amount+fee overflow")
	}
	if s.LockHeight > MaxLockHeight {
		return slateErr("lock height out of range")
	}
	if len(s.Inputs) == 0 || len(s.Inputs) > MaxSlateInputs {
		return slateErr("input count")
	}
	seen := map[types.Commitment]bool{}
	for _, in := range s.Inputs {
		if seen[in.Commit] || !v2crypto.ValidPublicPoint(in.Commit) || !validOutputFeatures(in.Features) {
			return slateErr("bad or duplicate input")
		}
		seen[in.Commit] = true
	}
	if s.Change != nil {
		if s.Change.Features != types.OutputFeaturesPlain || !v2crypto.ValidPublicPoint(s.Change.Commit) || seen[s.Change.Commit] || len(s.Change.RangeProof) == 0 {
			return slateErr("bad change output")
		}
	}
	if !v2crypto.ValidPublicPoint(s.SenderExc) || !v2crypto.ValidPublicPoint(s.SenderNon) {
		return slateErr("bad sender point")
	}
	if len(s.Memo) > MaxSlateMemo || !utf8.ValidString(s.Memo) {
		return slateErr("bad memo")
	}
	for _, r := range s.Memo {
		if r < 0x20 || r == 0x7f {
			return slateErr("control character in memo")
		}
	}
	return nil
}

// Validate performs the structural checks (no proof or signature verification).
func (s *Slate) Validate() error {
	if s == nil {
		return slateErr("nil")
	}
	if err := s.validateOffer(); err != nil {
		return err
	}
	switch s.Stage {
	case StageOffer:
		if s.RecvOutput != nil || s.RecvExc != (types.Commitment{}) || s.RecvNon != (types.Commitment{}) || s.RecvPartial != ([32]byte{}) {
			return slateErr("offer carries receiver data")
		}
	case StageResponse:
		o := s.RecvOutput
		if o == nil || o.Features != types.OutputFeaturesPlain || !v2crypto.ValidPublicPoint(o.Commit) || len(o.RangeProof) == 0 {
			return slateErr("bad receiver output")
		}
		if !v2crypto.ValidPublicPoint(s.RecvExc) || !v2crypto.ValidPublicPoint(s.RecvNon) || !canonicalScalar(s.RecvPartial) {
			return slateErr("bad receiver point or scalar")
		}
	default:
		return slateErr("unknown stage %d", s.Stage)
	}
	return nil
}

// MarshalBinary returns the fixed binary layout.
func (s *Slate) MarshalBinary() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	b := []byte{SlateVersion, byte(s.Stage)}
	b = append(b, s.TxID[:]...)
	b = binary.BigEndian.AppendUint32(b, s.Magic)
	b = binary.BigEndian.AppendUint64(b, uint64(s.Amount))
	b = binary.BigEndian.AppendUint64(b, s.Fee)
	b = binary.BigEndian.AppendUint64(b, s.LockHeight)
	b = append(b, byte(len(s.Inputs)))
	for _, in := range s.Inputs {
		b = appendInput(b, in)
	}
	if s.Change != nil {
		b = append(b, 1)
		var err error
		if b, err = appendOutput(b, *s.Change); err != nil {
			return nil, err
		}
	} else {
		b = append(b, 0)
	}
	b = append(b, s.SenderExc[:]...)
	b = append(b, s.SenderNon[:]...)
	if s.Stage == StageResponse {
		b = append(b, s.RecvExc[:]...)
		b = append(b, s.RecvNon[:]...)
		b = append(b, s.RecvPartial[:]...)
		var err error
		if b, err = appendOutput(b, *s.RecvOutput); err != nil {
			return nil, err
		}
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(s.Memo)))
	return append(b, s.Memo...), nil
}

// UnmarshalSlate parses and validates the binary layout.
func UnmarshalSlate(raw []byte) (*Slate, error) {
	r := &reader{b: raw}
	if v := r.u8(); r.err == nil && v != SlateVersion {
		return nil, slateErr("unsupported version %d", v)
	}
	s := &Slate{Stage: SlateStage(r.u8())}
	copy(s.TxID[:], r.take(16))
	s.Magic = r.u32()
	s.Amount = int64(r.u64())
	s.Fee = r.u64()
	s.LockHeight = r.u64()
	n := int(r.u8())
	if r.err == nil && (n == 0 || n > MaxSlateInputs) {
		return nil, slateErr("input count")
	}
	for i := 0; i < n && r.err == nil; i++ {
		s.Inputs = append(s.Inputs, r.input())
	}
	switch r.u8() {
	case 0:
	case 1:
		o := r.output()
		s.Change = &o
	default:
		if r.err == nil {
			r.err = slateErr("bad change flag")
		}
	}
	s.SenderExc = r.point()
	s.SenderNon = r.point()
	if s.Stage == StageResponse {
		s.RecvExc = r.point()
		s.RecvNon = r.point()
		copy(s.RecvPartial[:], r.take(32))
		o := r.output()
		s.RecvOutput = &o
	}
	ml := int(r.u16())
	if r.err == nil && ml > MaxSlateMemo {
		return nil, slateErr("memo too long")
	}
	s.Memo = string(r.take(ml))
	if r.err != nil {
		return nil, r.err
	}
	if len(r.b) != 0 {
		return nil, slateErr("trailing bytes")
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Encode wraps the slate as "SLATEPACK3." + unpadded base64url.
func (s *Slate) Encode() (string, error) {
	raw, err := s.MarshalBinary()
	if err != nil {
		return "", err
	}
	out := SlatePrefix + base64.RawURLEncoding.EncodeToString(raw)
	if len(out) > MaxSlateEncoded {
		return "", slateErr("encoded size limit")
	}
	return out, nil
}

// Decode parses a Slatepack string produced by Encode. Surrounding whitespace
// is ignored; anything else non-canonical is an error. Version 1 slates are
// rejected explicitly.
func Decode(text string) (*Slate, error) {
	text = strings.TrimSpace(text)
	if len(text) > MaxSlateEncoded {
		return nil, slateErr("encoded size limit")
	}
	if strings.HasPrefix(text, legacySlatePrefix) || strings.HasPrefix(text, legacySlatePrefix2) {
		return nil, slateErr("slates of format version 1 and 2 are no longer supported")
	}
	if !strings.HasPrefix(text, SlatePrefix) {
		return nil, slateErr("missing %s prefix", SlatePrefix)
	}
	body := text[len(SlatePrefix):]
	for i := 0; i < len(body); i++ {
		c := body[i]
		// Go's base64 decoder silently skips CR/LF; the text form is canonical.
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return nil, slateErr("non-canonical character in slate text")
		}
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil {
		return nil, slateErr("base64: %v", err)
	}
	return UnmarshalSlate(raw)
}

// offerEqual reports whether the sender-owned fields of a and b are identical.
func offerEqual(a, b *Slate) bool {
	if a.TxID != b.TxID || a.Magic != b.Magic || a.Amount != b.Amount || a.Fee != b.Fee || a.LockHeight != b.LockHeight ||
		a.SenderExc != b.SenderExc || a.SenderNon != b.SenderNon || a.Memo != b.Memo || len(a.Inputs) != len(b.Inputs) {
		return false
	}
	for i := range a.Inputs {
		if a.Inputs[i] != b.Inputs[i] {
			return false
		}
	}
	if (a.Change == nil) != (b.Change == nil) {
		return false
	}
	if a.Change != nil && (a.Change.Features != b.Change.Features || a.Change.Commit != b.Change.Commit || !bytes.Equal(a.Change.RangeProof, b.Change.RangeProof)) {
		return false
	}
	return true
}
