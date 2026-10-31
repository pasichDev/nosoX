package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/pasichDev/noso-go/v2/types"
)

func TestTrustedCheckpointsEmptySetStarts(t *testing.T) {
	for _, magic := range []uint32{types.NetworkMagicMainnet, types.NetworkMagicTestnet} {
		got, err := trustedCheckpoints(magic, nil, nil, nil, nil)
		if err != nil || len(got) != 0 {
			t.Fatalf("empty set: %v %v", got, err)
		}
	}
	// The real baked values must pass today (no checkpoints exist yet).
	if err := types.VerifyBakedCheckpoints(); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedCheckpoints(types.NetworkMagicTestnet, types.LauncherPubkey, types.MainnetCheckpointsSig, types.MainnetCheckpoints, types.TestnetCheckpoints); err != nil {
		t.Fatal(err)
	}
}

func TestTrustedCheckpointsRefusesBadSets(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	list := []types.Checkpoint{{Height: 10, Hash: types.Hash{1}}}
	hash := types.CanonicalCheckpointHash(list)
	sig := ed25519.Sign(priv, hash[:])

	got, err := trustedCheckpoints(types.NetworkMagicMainnet, pub, sig, list, nil)
	if err != nil || len(got) != 1 {
		t.Fatalf("valid signed set refused: %v", err)
	}
	if got, err = trustedCheckpoints(types.NetworkMagicTestnet, pub, sig, list, nil); err != nil || len(got) != 0 {
		t.Fatalf("testnet must not pin the mainnet list: %v %v", got, err)
	}
	bad := append([]byte(nil), sig...)
	bad[0] ^= 1
	if _, err := trustedCheckpoints(types.NetworkMagicTestnet, pub, bad, list, nil); !errors.Is(err, types.ErrBadCheckpointSig) {
		t.Fatalf("bad signature accepted: %v", err)
	}
	if _, err := trustedCheckpoints(types.NetworkMagicTestnet, pub, nil, list, nil); !errors.Is(err, types.ErrUnsignedCheckpoints) {
		t.Fatalf("missing signature accepted: %v", err)
	}
	tampered := []types.Checkpoint{{Height: 10, Hash: types.Hash{2}}}
	if _, err := trustedCheckpoints(types.NetworkMagicTestnet, pub, sig, tampered, nil); !errors.Is(err, types.ErrBadCheckpointSig) {
		t.Fatalf("tampered list accepted: %v", err)
	}
	if _, err := trustedCheckpoints(types.NetworkMagicTestnet, ed25519.PublicKey{1, 2, 3}, sig, list, nil); err == nil {
		t.Fatal("malformed launcher key accepted (or panicked)")
	}
	if _, err := trustedCheckpoints(types.NetworkMagicTestnet, nil, nil, list, nil); err == nil {
		t.Fatal("unsigned non-empty list without launcher key accepted")
	}
}
