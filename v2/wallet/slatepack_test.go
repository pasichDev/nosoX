package wallet

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"math"
	"strings"
	"testing"

	"github.com/pasichDev/noso-go/v2/types"
)

// sampleSlates returns a genuine offer and response (real proofs and partials).
func sampleSlates(t testing.TB) (offer, resp *Slate) {
	t.Helper()
	node := newFakeNode()
	sender, receiver := newWalletStore(t, "s"), newWalletStore(t, "r")
	fund(t, sender, node, 1000, types.OutputFeaturesPlain, 5)
	offer, err := sender.Pay(node, PayParams{Amount: 600, Fee: 10, Memo: "lunch"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err = receiver.Receive(offer)
	if err != nil {
		t.Fatal(err)
	}
	return offer, resp
}

func TestSlateRoundTrip(t *testing.T) {
	offer, resp := sampleSlates(t)
	for _, s := range []*Slate{offer, resp} {
		enc, err := s.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(enc, SlatePrefix) {
			t.Fatalf("prefix: %.20s", enc)
		}
		got, err := Decode("  " + enc + "\n")
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		a, _ := s.MarshalBinary()
		b, _ := got.MarshalBinary()
		if !bytes.Equal(a, b) {
			t.Fatal("round trip changed the slate")
		}
		if got.Amount != 600 || got.Fee != 10 || got.Memo != "lunch" {
			t.Fatalf("fields: %+v", got)
		}
	}
	if len(offer.Inputs) != 1 || offer.Change == nil || resp.RecvOutput == nil {
		t.Fatal("unexpected slate shape")
	}
}

func TestSlateRejectsLegacyAndUnknownVersions(t *testing.T) {
	offer, _ := sampleSlates(t)
	raw, _ := offer.MarshalBinary()
	if _, err := Decode("SLATEPACK1." + base64.RawURLEncoding.EncodeToString(raw)); err == nil || !strings.Contains(err.Error(), "version 1") {
		t.Fatalf("legacy prefix accepted or wrong error: %v", err)
	}
	bad := append([]byte(nil), raw...)
	bad[0] = 4
	if _, err := UnmarshalSlate(bad); err == nil {
		t.Fatal("unsupported version byte accepted")
	}
	if _, err := Decode("not-a-slate"); err == nil {
		t.Fatal("missing prefix accepted")
	}
}

func TestSlateStageHeaderMismatchRejected(t *testing.T) {
	offer, resp := sampleSlates(t)
	a, _ := offer.MarshalBinary()
	a[1] = byte(StageResponse) // offer body relabelled as response: receiver data missing
	if _, err := UnmarshalSlate(a); err == nil {
		t.Fatal("offer relabelled as response accepted")
	}
	b, _ := resp.MarshalBinary()
	b[1] = byte(StageOffer) // response relabelled as offer: trailing receiver data
	if _, err := UnmarshalSlate(b); err == nil {
		t.Fatal("response relabelled as offer accepted")
	}
	b[1] = 9
	if _, err := UnmarshalSlate(b); err == nil {
		t.Fatal("unknown stage accepted")
	}
}

func TestSlateEveryTruncationRejected(t *testing.T) {
	offer, resp := sampleSlates(t)
	for _, s := range []*Slate{offer, resp} {
		raw, _ := s.MarshalBinary()
		step := 1
		if len(raw) > 4000 {
			step = 7 // the proof body is opaque; still hit every header boundary below
		}
		for n := 0; n < len(raw); n += step {
			if _, err := UnmarshalSlate(raw[:n]); err == nil {
				t.Fatalf("truncation to %d/%d bytes accepted", n, len(raw))
			}
		}
		for n := len(raw) - 40; n < len(raw); n++ {
			if _, err := UnmarshalSlate(raw[:n]); err == nil {
				t.Fatalf("truncation to %d/%d bytes accepted", n, len(raw))
			}
		}
		if _, err := UnmarshalSlate(append(append([]byte(nil), raw...), 0)); err == nil {
			t.Fatal("trailing byte accepted")
		}
	}
}

func TestSlateOversizeAndNonCanonicalText(t *testing.T) {
	offer, _ := sampleSlates(t)
	enc, _ := offer.Encode()
	if _, err := Decode(enc + strings.Repeat("A", MaxSlateEncoded)); err == nil {
		t.Fatal("oversized slate accepted")
	}
	if _, err := Decode(SlatePrefix + strings.Repeat("A", MaxSlateEncoded)); err == nil {
		t.Fatal("oversized body accepted")
	}
	body := enc[len(SlatePrefix):]
	for _, bad := range []string{
		SlatePrefix + body + "=",                   // padding
		SlatePrefix + body[:10] + "\n" + body[10:], // embedded whitespace
		SlatePrefix + strings.ReplaceAll(body, "-", "+"),
		SlatePrefix + body + "!",
		SlatePrefix,
	} {
		if bad == SlatePrefix+strings.ReplaceAll(body, "-", "+") && !strings.Contains(body, "-") {
			continue
		}
		if _, err := Decode(bad); err == nil {
			t.Fatalf("non-canonical text accepted: %.40s...", bad)
		}
	}
}

func TestSlateRejectsBadFieldValues(t *testing.T) {
	_, resp := sampleSlates(t)
	raw, _ := resp.MarshalBinary()
	put64 := func(off int, v uint64) []byte {
		b := append([]byte(nil), raw...)
		binary.BigEndian.PutUint64(b[off:], v)
		return b
	}
	cases := map[string][]byte{
		"zero amount":      put64(22, 0),
		"negative amount":  put64(22, 1<<63),
		"fee over int64":   put64(30, math.MaxUint64),
		"amount+fee wraps": put64(30, math.MaxInt64),
		"lock too large":   put64(38, MaxLockHeight+1),
	}
	for name, b := range cases {
		if _, err := UnmarshalSlate(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// input count 0 and 5
	for _, n := range []byte{0, 5, 255} {
		b := append([]byte(nil), raw...)
		b[46] = n
		if _, err := UnmarshalSlate(b); err == nil {
			t.Errorf("input count %d accepted", n)
		}
	}
	// Malformed points: bad prefix, identity, x not on the curve. SenderExc sits
	// right after the change output; locate it from the struct instead of offsets.
	mutatePoint := func(name string, get func(s *Slate) *types.Commitment, vals ...[33]byte) {
		for i, v := range vals {
			s := *resp
			p := get(&s)
			*p = v
			if _, err := s.MarshalBinary(); err == nil {
				t.Errorf("%s variant %d accepted by encoder", name, i)
			}
		}
	}
	notOnCurve := [33]byte{0x02}
	notOnCurve[32] = 5 // x = 5 is not a secp256k1 abscissa
	badPrefix := resp.SenderExc
	badPrefix[0] = 0x05
	identity := [33]byte{}
	for name, get := range map[string]func(s *Slate) *types.Commitment{
		"sender excess": func(s *Slate) *types.Commitment { return &s.SenderExc },
		"sender nonce":  func(s *Slate) *types.Commitment { return &s.SenderNon },
		"recv excess":   func(s *Slate) *types.Commitment { return &s.RecvExc },
		"recv nonce":    func(s *Slate) *types.Commitment { return &s.RecvNon },
	} {
		mutatePoint(name, get, notOnCurve, badPrefix, identity)
	}
	// Non-canonical scalars: zero, n, n+1, 2^256-1.
	n := [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41}
	n1 := n
	n1[31]++
	max := [32]byte{}
	for i := range max {
		max[i] = 0xff
	}
	for name, v := range map[string][32]byte{"zero": {}, "n": n, "n+1": n1, "max": max} {
		s := *resp
		s.RecvPartial = v
		if _, err := s.MarshalBinary(); err == nil {
			t.Errorf("scalar %s accepted", name)
		}
	}
	// Memo rules.
	for name, memo := range map[string]string{"control": "a\x00b", "newline": "a\nb", "invalid utf8": "\xff\xfe", "too long": strings.Repeat("x", MaxSlateMemo+1)} {
		s := *resp
		s.Memo = memo
		if _, err := s.MarshalBinary(); err == nil {
			t.Errorf("memo %s accepted", name)
		}
	}
	// Duplicate input.
	d := *resp
	d.Inputs = append(append([]types.Input(nil), d.Inputs...), d.Inputs[0])
	if _, err := d.MarshalBinary(); err == nil {
		t.Error("duplicate input accepted")
	}
	// Change colliding with an input.
	c := *resp
	ch := *c.Change
	ch.Commit = c.Inputs[0].Commit
	c.Change = &ch
	if _, err := c.MarshalBinary(); err == nil {
		t.Error("change equal to input accepted")
	}
}

func TestSlateBindsEverySenderField(t *testing.T) {
	offer, _ := sampleSlates(t)
	base, _ := offer.MarshalBinary()
	mut := []func(s *Slate){
		func(s *Slate) { s.Amount++ },
		func(s *Slate) { s.Fee++ },
		func(s *Slate) { s.LockHeight++ },
		func(s *Slate) { s.Memo += "x" },
		func(s *Slate) { s.TxID[0] ^= 1 },
		func(s *Slate) { s.Inputs[0].Features = types.OutputFeaturesCoinbase },
	}
	for i, m := range mut {
		s := *offer
		s.Inputs = append([]types.Input(nil), offer.Inputs...)
		m(&s)
		raw, err := s.MarshalBinary()
		if err != nil {
			continue
		}
		if bytes.Equal(raw, base) {
			t.Errorf("mutation %d does not change the encoding", i)
		}
		if offerEqual(offer, &s) {
			t.Errorf("mutation %d not detected by offerEqual", i)
		}
	}
}

func TestTxCodecStrict(t *testing.T) {
	node := newFakeNode()
	sender, receiver := newWalletStore(t, "s"), newWalletStore(t, "r")
	fund(t, sender, node, 1000, types.OutputFeaturesPlain, 5)
	offer, _ := sender.Pay(node, PayParams{Amount: 500, Fee: 1})
	resp, _ := receiver.Receive(offer)
	if _, err := sender.Finalize(node, resp); err != nil {
		t.Fatal(err)
	}
	raw := node.submits[0]
	tx, err := DecodeTx(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := EncodeTx(tx)
	if !bytes.Equal(raw, again) {
		t.Fatal("tx codec not canonical")
	}
	for n := 0; n < len(raw); n += 13 {
		if _, err := DecodeTx(raw[:n]); err == nil {
			t.Fatalf("truncated tx (%d) accepted", n)
		}
	}
	if _, err := DecodeTx(append(append([]byte(nil), raw...), 7)); err == nil {
		t.Fatal("trailing byte accepted")
	}
	bad := append([]byte(nil), raw...)
	bad[0] = 9
	if _, err := DecodeTx(bad); err == nil {
		t.Fatal("bad version accepted")
	}
	bad = append([]byte(nil), raw...)
	bad[1] = 200 // absurd input count
	if _, err := DecodeTx(bad); err == nil {
		t.Fatal("huge input count accepted")
	}
	if _, err := DecodeTx(make([]byte, MaxEncodedTxBytes+1)); err == nil {
		t.Fatal("oversize tx accepted")
	}
	tx.Kernels[0].ExcessSig = tx.Kernels[0].ExcessSig[:64]
	if _, err := EncodeTx(tx); err == nil {
		t.Fatal("short kernel signature encoded")
	}
}
