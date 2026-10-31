package wallet

import "testing"

// FuzzSlatepackDecode feeds arbitrary strings to Decode. It must never panic,
// and anything it accepts must re-encode to an identical slate (a malicious
// peer cannot smuggle a non-canonical form past the sender).
func FuzzSlatepackDecode(f *testing.F) {
	offer, resp := sampleSlates(f)
	for _, s := range []*Slate{offer, resp} {
		good, err := s.Encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(good)
		f.Add(good[:len(good)/2])
	}
	f.Add("SLATEPACK2.")
	f.Add("SLATEPACK1.garbage")
	f.Add("SLATEPACK2.AAAA")
	f.Add("not-a-slatepack")
	f.Add("")
	f.Fuzz(func(t *testing.T, input string) {
		s, err := Decode(input)
		if err != nil {
			return
		}
		enc, err := s.Encode()
		if err != nil {
			t.Fatalf("accepted slate does not re-encode: %v", err)
		}
		s2, err := Decode(enc)
		if err != nil {
			t.Fatalf("re-encoded slate rejected: %v", err)
		}
		a, _ := s.MarshalBinary()
		b, _ := s2.MarshalBinary()
		if string(a) != string(b) {
			t.Fatal("round trip not stable")
		}
	})
}

// FuzzTxDecode: the transaction codec is the RPC's input boundary.
func FuzzTxDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{txCodecVersion, 0, 0, 0})
	f.Add([]byte{txCodecVersion, 255, 255, 255})
	f.Fuzz(func(t *testing.T, raw []byte) {
		tx, err := DecodeTx(raw)
		if err != nil {
			return
		}
		back, err := EncodeTx(tx)
		if err != nil || string(back) != string(raw) {
			t.Fatalf("accepted tx is not canonical: %v", err)
		}
	})
}
