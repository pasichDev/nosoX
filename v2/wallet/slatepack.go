package wallet

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"
)

// Slatepack is the asynchronous coordination payload for native MW
// transactions. The interactive 3-step build is:
//
//	1. Sender   → builds a SlateOffer (inputs + change output + partial sig)
//	2. Receiver → adds an output + partial signature → SlateResponse
//	3. Sender   → aggregates signatures and broadcasts → SlateFinal
//
// Each slate is wrapped as Base58 of CBOR-like JSON. The receiver+sender
// exchange the string out-of-band (QR, message, file).
//
// To keep the package small, this module ships the codec and stage
// helpers. The actual MW transaction graph (Pedersen commit balance,
// kernel excess, range proof generation) is delegated to v2/crypto.
// A full interactive negotiation flow is wired up in nosox-cli.

// SlateRole identifies the participant in the protocol.
type SlateRole uint8

const (
	RoleSender   SlateRole = 1
	RoleReceiver SlateRole = 2
)

// SlateStage tracks where the slate is in the 3-step handshake.
type SlateStage uint8

const (
	StageOffer    SlateStage = 1
	StageResponse SlateStage = 2
	StageFinal    SlateStage = 3
)

// Slate is the on-the-wire object exchanged between sender and receiver.
// All Pedersen commits and signatures use compressed-point/Schnorr-ish
// encodings native to v2/crypto and v2/types.
type Slate struct {
	Version    uint16           `json:"v"`
	Stage      SlateStage       `json:"s"`
	Role       SlateRole        `json:"r"`
	TxID       [16]byte         `json:"tid"` // random session id
	Amount     int64            `json:"amt"` // gross amount the receiver receives
	Fee        uint64           `json:"fee"` // kernel fee (split is sender's problem)
	LockHeight uint64           `json:"lh"`  // kernel lock height
	Inputs     []SlateInput     `json:"in,omitempty"`
	Outputs    []SlateOutput    `json:"out,omitempty"`
	PartSigs   []PartialSig     `json:"psigs,omitempty"` // collected partial signatures
	Excess     types.Commitment `json:"exc"`             // running excess sum
	Memo       string           `json:"memo,omitempty"`
}

// SlateInput is a Pedersen commit (with optional legacy fields) the
// sender contributes to the transaction.
type SlateInput struct {
	Commit       types.Commitment     `json:"c"`
	Features     types.OutputFeatures `json:"f"`
	LegacyAddr   string               `json:"la,omitempty"`
	LegacyAmount int64                `json:"lv,omitempty"`
	LegacySig    string               `json:"lsig,omitempty"`
}

// SlateOutput is a Pedersen commit produced by either party.
type SlateOutput struct {
	Commit     types.Commitment     `json:"c"`
	Features   types.OutputFeatures `json:"f"`
	RangeProof []byte               `json:"rp"`
}

// PartialSig is one side's contribution to the aggregated kernel sig.
type PartialSig struct {
	By  SlateRole `json:"by"`
	Sig []byte    `json:"sig"` // Ed25519 signature over the canonical sign-hash
	Pub []byte    `json:"pub"` // signer's Ed25519 public key
}

// NewOfferSlate builds the sender's stage-1 slate. The sender contributes
// inputs that cover (amount + fee) and a change output for the difference;
// the receiver will add an output for the gross amount later.
func NewOfferSlate(amount int64, fee uint64, lockHeight uint64, memo string) *Slate {
	var tid [16]byte
	_, _ = rand.Read(tid[:])
	return &Slate{
		Version:    1,
		Stage:      StageOffer,
		Role:       RoleSender,
		TxID:       tid,
		Amount:     amount,
		Fee:        fee,
		LockHeight: lockHeight,
		Memo:       memo,
	}
}

// SignPartial attaches an Ed25519 partial signature over the canonical
// sign-hash to the slate.
func (s *Slate) SignPartial(role SlateRole, priv ed25519.PrivateKey) error {
	if s == nil || len(priv) != ed25519.PrivateKeySize || (role != RoleSender && role != RoleReceiver) {
		return errors.New("slatepack: invalid signer")
	}
	hash := s.partialSignHash(role)
	sig := ed25519.Sign(priv, hash[:])
	s.PartSigs = append(s.PartSigs, PartialSig{
		By:  role,
		Sig: sig,
		Pub: priv.Public().(ed25519.PublicKey),
	})
	return nil
}

// VerifyPartials checks every collected partial signature.
func (s *Slate) VerifyPartials() bool {
	if s == nil || len(s.PartSigs) == 0 || len(s.PartSigs) > 2 {
		return false
	}
	seen := map[SlateRole]bool{}
	for _, ps := range s.PartSigs {
		if seen[ps.By] || (ps.By != RoleSender && ps.By != RoleReceiver) || len(ps.Pub) != ed25519.PublicKeySize || len(ps.Sig) != ed25519.SignatureSize {
			return false
		}
		seen[ps.By] = true
		hash := s.partialSignHash(ps.By)
		if !ed25519.Verify(ed25519.PublicKey(ps.Pub), hash[:], ps.Sig) {
			return false
		}
	}
	return true
}

// CheckBalance is the Mimblewimble conservation check applied to the
// slate's inputs and outputs.
func (s *Slate) CheckBalance() error {
	if s.Fee > math.MaxInt64 {
		return errors.New("slatepack: fee overflow")
	}
	negative := make([][33]byte, len(s.Inputs))
	for i := range s.Inputs {
		negative[i] = [33]byte(s.Inputs[i].Commit)
	}
	positive := make([][33]byte, len(s.Outputs))
	for i := range s.Outputs {
		positive[i] = [33]byte(s.Outputs[i].Commit)
	}
	zero, err := v2crypto.PedersenSumZero(positive, negative, int64(s.Fee))
	if err != nil {
		return err
	}
	if !zero {
		return errors.New("slatepack: commitment sum imbalanced")
	}
	return nil
}

func (s *Slate) canonicalSignHash() [32]byte {
	copySlate := *s
	copySlate.PartSigs = nil
	body, _ := json.Marshal(copySlate)
	return sha256.Sum256(append([]byte("Noso-v2-Slate-Signature\x00"), body...))
}

func bigUint64(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}

// Encode wraps the slate as a Base58-encoded JSON string with a
// "SLATEPACK1" prefix that nosox-cli looks for when parsing user input.
func (s *Slate) Encode() (string, error) {
	body, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	if len(body) > 90*1024 {
		return "", errors.New("slatepack: size limit")
	}
	// Pre-pend a 1-byte stage so a reader can sort slates without
	// JSON-decoding.
	withHdr := append([]byte{byte(s.Stage)}, body...)
	return "SLATEPACK1." + base58Encode(withHdr), nil
}

// Decode parses a Slatepack string produced by Encode.
func Decode(s string) (*Slate, error) {
	if len(s) > 128*1024 {
		return nil, errors.New("slatepack: encoded size limit")
	}
	if !strings.HasPrefix(s, "SLATEPACK1.") {
		return nil, errors.New("slatepack: missing prefix")
	}
	body, err := base58Decode(strings.TrimPrefix(s, "SLATEPACK1."))
	if err != nil {
		return nil, err
	}
	if len(body) < 2 {
		return nil, errors.New("slatepack: payload too small")
	}
	var slate Slate
	if err := json.Unmarshal(body[1:], &slate); err != nil {
		return nil, fmt.Errorf("slatepack: json: %w", err)
	}
	if slate.Version != 1 || byte(slate.Stage) != body[0] || slate.Stage < StageOffer || slate.Stage > StageFinal || (slate.Role != RoleSender && slate.Role != RoleReceiver) || slate.Amount < 0 || slate.Fee > math.MaxInt64 || len(slate.Inputs) > 64 || len(slate.Outputs) > 64 || len(slate.PartSigs) > 2 || len(slate.Memo) > 4096 {
		return nil, errors.New("slatepack: invalid fields")
	}
	return &slate, nil
}

// ---- Base58 (Noso v1 alphabet for cross-tool consistency) -------------

const slateAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(b []byte) string {
	v := new(big.Int).SetBytes(b)
	zero := new(big.Int)
	mod := new(big.Int)
	base := big.NewInt(58)
	var out []byte
	for v.Sign() > 0 {
		v.QuoRem(v, base, mod)
		out = append(out, slateAlphabet[mod.Int64()])
	}
	// Leading zero bytes become "1"s.
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, slateAlphabet[0])
	}
	_ = zero
	// Reverse.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Decode(s string) ([]byte, error) {
	result := new(big.Int)
	base := big.NewInt(58)
	for _, c := range s {
		idx := strings.IndexRune(slateAlphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("slatepack: bad char %q", c)
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(idx)))
	}
	// Recover leading zero bytes from leading '1's.
	zeros := 0
	for _, c := range s {
		if c != rune(slateAlphabet[0]) {
			break
		}
		zeros++
	}
	out := append(make([]byte, zeros), result.Bytes()...)
	// Avoid silently mapping to base64-like padding.
	_ = base64.StdEncoding
	return out, nil
}

func (s *Slate) partialSignHash(role SlateRole) [32]byte {
	body := s.canonicalSignHash()
	data := append([]byte("Noso-v2-Slate-Participant\x00"), byte(role))
	return sha256.Sum256(append(data, body[:]...))
}
