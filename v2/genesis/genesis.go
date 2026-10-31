// Package genesis builds NosoX's first block. Genesis is deliberately empty:
// it carries no allocations, so every coin in circulation is issued through
// a mined coinbase. Two nodes with the same network parameters derive the
// same genesis without any external input.
package genesis

import (
	"errors"
	"time"

	"github.com/pasichDev/noso-go/v2/types"
)

// Config controls genesis generation. Sensible defaults are exposed via
// Default().
type Config struct {
	// NetworkMagic distinguishes mainnet/testnet/devnet.
	NetworkMagic uint32
	// Timestamp anchors the genesis block. Defaults to a fixed value so
	// independent runs produce identical hashes.
	Timestamp int64
	// InitialDifficulty sets the floor for the first DifficultyWindow
	// blocks before LWMA-3 takes over.
	InitialDifficulty uint64
}

// Default returns the canonical mainnet genesis config.
func Default() Config {
	return Config{
		NetworkMagic:      types.NetworkMagicMainnet,
		Timestamp:         time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Unix(),
		InitialDifficulty: 256, // ~1-in-256 hashes valid; mineable on a Pi instantly
	}
}

// Build constructs the empty genesis block: height 0, zero parent, no inputs,
// outputs or kernels.
func Build(cfg Config) (*types.Block, error) {
	if cfg.Timestamp == 0 {
		cfg.Timestamp = Default().Timestamp
	}
	if cfg.NetworkMagic == 0 {
		// A caller that forgot the field must not silently get mainnet.
		return nil, errors.New("genesis: network magic is required")
	}
	if cfg.InitialDifficulty == 0 {
		cfg.InitialDifficulty = Default().InitialDifficulty
	}
	block := &types.Block{Header: types.BlockHeader{
		Version:      types.BlockVersion,
		NetworkMagic: cfg.NetworkMagic,
		Timestamp:    cfg.Timestamp,
		Difficulty:   cfg.InitialDifficulty,
	}}
	types.SetBlockRoots(block)
	return block, nil
}

// Stats summarizes a built genesis for the RPC and CLI.
type Stats struct {
	GenesisHash  types.Hash
	Difficulty   uint64
	NetworkMagic uint32
}

// Summarize runs Build and returns its identifying values.
func Summarize(cfg Config) (Stats, error) {
	block, err := Build(cfg)
	if err != nil {
		return Stats{}, err
	}
	return Stats{
		GenesisHash:  types.HeaderID(&block.Header),
		Difficulty:   block.Header.Difficulty,
		NetworkMagic: block.Header.NetworkMagic,
	}, nil
}
