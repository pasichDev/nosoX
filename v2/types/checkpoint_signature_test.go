package types

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestDevModeAcceptsAnything(t *testing.T) {
	// When no LauncherPubkey is baked in, the verifier returns nil
	// regardless of the signature state.
	if err := VerifyCheckpointList(nil, nil, []Checkpoint{}); err != nil {
		t.Errorf("dev-mode (nil pubkey) errored: %v", err)
	}
	if err := VerifyCheckpointList(nil, []byte("garbage"), []Checkpoint{{Height: 1}}); err != nil {
		t.Errorf("dev-mode with junk sig errored: %v", err)
	}
}

func TestSignedCheckpointsRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	list := []Checkpoint{
		{Height: 1000, Hash: Hash{0x11}},
		{Height: 2000, Hash: Hash{0x22}},
		{Height: 3000, Hash: Hash{0x33}},
	}
	hash := CanonicalCheckpointHash(list)
	sig := ed25519.Sign(priv, hash[:])
	if err := VerifyCheckpointList(pub, sig, list); err != nil {
		t.Fatalf("legit signed list rejected: %v", err)
	}
}

func TestMissingSigRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyCheckpointList(pub, nil, []Checkpoint{{Height: 1}}); err != ErrUnsignedCheckpoints {
		t.Fatalf("missing sig should give ErrUnsignedCheckpoints, got %v", err)
	}
}

func TestTamperedListRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	list := []Checkpoint{{Height: 1000, Hash: Hash{0x11}}}
	hash := CanonicalCheckpointHash(list)
	sig := ed25519.Sign(priv, hash[:])
	// Tamper: add a fake checkpoint to the list before verification.
	tampered := append(list, Checkpoint{Height: 9999, Hash: Hash{0xff}})
	if err := VerifyCheckpointList(pub, sig, tampered); err != ErrBadCheckpointSig {
		t.Fatalf("tampered list should give ErrBadCheckpointSig, got %v", err)
	}
}

func TestCanonicalHashOrderIndependent(t *testing.T) {
	a := []Checkpoint{{Height: 100, Hash: Hash{1}}, {Height: 200, Hash: Hash{2}}}
	b := []Checkpoint{{Height: 200, Hash: Hash{2}}, {Height: 100, Hash: Hash{1}}}
	if CanonicalCheckpointHash(a) != CanonicalCheckpointHash(b) {
		t.Fatal("canonical hash should be order-independent (sorted by height)")
	}
}
