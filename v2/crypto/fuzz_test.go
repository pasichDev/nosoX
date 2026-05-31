package crypto

import "testing"

// FuzzVerifyRangeBorromean checks that the verifier handles any byte
// payload without panicking. A crash here would let a malicious miner
// brick verifying nodes via crafted range proofs.
func FuzzVerifyRangeBorromean(f *testing.F) {
	// Seed with a legitimate proof.
	var blind [32]byte
	blind[0] = 1
	c, _ := PedersenCommit(42, blind[:])
	if proof, err := ProveRangeBorromean(c, blind[:], 42); err == nil {
		f.Add(proof)
	}
	f.Add([]byte{})
	f.Add([]byte{2})
	f.Fuzz(func(t *testing.T, raw []byte) {
		var commit [33]byte
		commit[0] = 0x02
		// VerifyRange must return false (never panic) on garbage.
		_ = VerifyRangeBorromean(commit, raw)
	})
}

// FuzzSchnorrVerify is the matching harness for Schnorr signatures.
func FuzzSchnorrVerify(f *testing.F) {
	// Seed.
	x := [32]byte{1}
	pub, _ := PublicFromScalar(x[:])
	sig, _ := SchnorrSign(x[:], []byte("seed"))
	f.Add(pub[:], []byte("seed"), sig)
	f.Add([]byte{}, []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, pubBytes, msg, sig []byte) {
		var p [33]byte
		if len(pubBytes) >= 33 {
			copy(p[:], pubBytes[:33])
		} else {
			copy(p[:], pubBytes)
		}
		_ = SchnorrVerify(p, msg, sig)
	})
}
