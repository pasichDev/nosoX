package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/pasichDev/nosoX/v2/types"
)

// trustedCheckpoints validates the baked-in checkpoint set and returns the
// list to pin for the given network. It is the daemon's startup gate: an error
// means the binary must not run.
//
//   - An empty baked list with no launcher key is valid (nothing is pinned).
//   - A launcher key requires a signature that verifies over the mainnet list.
//   - A non-empty mainnet list without a launcher key is refused, so an
//     unsigned list can never be pinned by accident.
//
// The signature covers MainnetCheckpoints only; it is checked on every
// network because it vouches for the binary, not for the network in use.
func trustedCheckpoints(magic uint32, pub ed25519.PublicKey, sig []byte, mainnet, testnet []types.Checkpoint) ([]types.Checkpoint, error) {
	if err := types.VerifyCheckpointList(pub, sig, mainnet); err != nil {
		return nil, fmt.Errorf("checkpoints: %w", err)
	}
	if len(mainnet) > 0 && pub == nil {
		return nil, errors.New("checkpoints: baked mainnet checkpoints without a launcher key")
	}
	if magic == types.NetworkMagicMainnet {
		return mainnet, nil
	}
	return testnet, nil
}
