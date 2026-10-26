package wallet

import "testing"

// FuzzSlatepackDecode feeds arbitrary strings to Decode and asserts no
// panic. Crashes here would mean a malicious receiver can DoS the
// sender by sending a malformed slate.
func FuzzSlatepackDecode(f *testing.F) {
	// Seed: a known-good slatepack so the fuzzer has somewhere to start.
	s := NewOfferSlate(1_000_000, 100, 0, "fuzz seed")
	s.TxID = [16]byte{1, 2, 3, 4} // fixed initial corpus identity
	good, _ := s.Encode()
	f.Add(good)
	f.Add("SLATEPACK1.")
	f.Add("SLATEPACK1.garbage")
	f.Add("not-a-slatepack")
	f.Add("")
	f.Fuzz(func(t *testing.T, input string) {
		// We don't assert correctness; we just ensure Decode never panics.
		// Errors are expected for malformed inputs.
		_, _ = Decode(input)
	})
}
