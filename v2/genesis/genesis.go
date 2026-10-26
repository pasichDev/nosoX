// Package genesis builds Noso v2's first block from the legacy Pascal
// sumary.psk file. Every non-empty account becomes a Legacy UTXO that
// can be spent (and converted to a native MW output) by signing with
// the original secp256k1 key.
//
// Forkers can call BuildGenesis with their own sumary.psk to bootstrap
// an independent chain that still honors the existing community's
// balances — or pass an empty SummaryStore for a true from-scratch start.
package genesis

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	legacycrypto "github.com/pasichDev/noso-go/internal/crypto"
	"math"
	"os"
	"strconv"
	"time"

	v2crypto "github.com/pasichDev/noso-go/v2/crypto"
	"github.com/pasichDev/noso-go/v2/types"

	"github.com/pasichDev/noso-go/internal/storage"
)

// Config controls genesis generation. Sensible defaults are exposed via
// Default().
type Config struct {
	// SummaryPath is the path to the v1 sumary.psk to airdrop from. If
	// empty, the genesis carries no legacy outputs (true from-scratch
	// fork).
	SummaryPath string
	// GVTsPath is the path to the v1 gvts.psk file. If empty, the
	// genesis carries no inherited GVTs (true from-scratch fork). The
	// canonical NosoX mainnet must always pass this.
	GVTsPath string
	// NetworkMagic distinguishes mainnet/testnet/devnet.
	NetworkMagic uint32
	// Timestamp anchors the genesis block. Defaults to a fixed value
	// so independent runs produce identical hashes for the same input.
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

// Build constructs the genesis block. The returned block contains:
//   - no inputs
//   - N legacy outputs (one per non-empty entry in sumary.psk)
//   - 100 legacy-GVT outputs (one per slot in gvts.psk)
//   - 0 kernels (no spends at genesis)
//
// The genesis block header has Height=0, PrevHash=0, Difficulty as
// configured. The PoW nonce is brute-forced once at network launch and
// then hard-coded into every node's binary.
func Build(cfg Config) (*types.Block, []LegacyOutputInfo, []LegacyGVTInfo, error) {
	if cfg.Timestamp == 0 {
		cfg.Timestamp = Default().Timestamp
	}
	if cfg.NetworkMagic == 0 {
		cfg.NetworkMagic = types.NetworkMagicMainnet
	}
	if cfg.InitialDifficulty == 0 {
		cfg.InitialDifficulty = Default().InitialDifficulty
	}

	var (
		outputs  []types.Output
		info     []LegacyOutputInfo
		gvtInfos []LegacyGVTInfo
	)

	if cfg.SummaryPath != "" {
		if _, err := os.Stat(cfg.SummaryPath); err != nil {
			return nil, nil, nil, fmt.Errorf("genesis: missing snapshot: %w", err)
		}
		store, err := storage.NewSummaryStore(cfg.SummaryPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("genesis: read summary: %w", err)
		}
		recs := store.All()
		seen := map[string]bool{}
		var total int64
		for i := range recs {
			r := recs[i]
			if r.Balance < 0 || seen[r.Hash] || !legacycrypto.IsValidAddress(r.Hash) {
				return nil, nil, nil, fmt.Errorf("genesis: invalid or duplicate snapshot record %d", i)
			}
			seen[r.Hash] = true
			if r.Balance > math.MaxInt64-total {
				return nil, nil, nil, fmt.Errorf("genesis: snapshot supply overflow")
			}
			total += r.Balance
			if r.Balance == 0 {
				continue
			}
			out, oi := newLegacyOutput(r.Hash, r.Balance)
			outputs = append(outputs, out)
			info = append(info, oi)
		}
	}

	// Carry forward all 100 GVTs from v1 gvts.psk. Each becomes a
	// LegacyGVT output identified by its slot number 00..99 plus the
	// original owner's address. Owners can later redeem (spend for
	// GVTBaseValue NOSO) or transfer (preserves identity).
	if cfg.GVTsPath != "" {
		if _, err := os.Stat(cfg.GVTsPath); err != nil {
			return nil, nil, nil, fmt.Errorf("genesis: missing GVT snapshot: %w", err)
		}
		gvts, err := storage.LoadGVTs(cfg.GVTsPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("genesis: read gvts: %w", err)
		}
		seenSlots := map[int]bool{}
		for i := range gvts {
			g := gvts[i]
			if g.Owner == "" {
				continue
			}
			slot, err := strconv.Atoi(g.Number)
			if err != nil || slot < 0 || slot > 99 || seenSlots[slot] || !legacycrypto.IsValidAddress(g.Owner) {
				return nil, nil, nil, fmt.Errorf("genesis: invalid or duplicate GVT record %d", i)
			}
			seenSlots[slot] = true
			out, gi := newLegacyGVTOutput(g.Owner, uint8(slot))
			outputs = append(outputs, out)
			gvtInfos = append(gvtInfos, gi)
		}
	}

	// Build Merkle roots.
	outputRoot := merkleRoot(outputIDs(outputs))
	kernelRoot := zeroHash() // no kernels in genesis

	header := types.BlockHeader{
		Version:           types.BlockVersion,
		NetworkMagic:      cfg.NetworkMagic,
		Height:            0,
		Timestamp:         cfg.Timestamp,
		PrevHash:          types.Hash{}, // zero
		OutputRoot:        outputRoot,
		KernelRoot:        kernelRoot,
		TotalKernelOffset: types.Commitment{}, // zero
		Difficulty:        cfg.InitialDifficulty,
		Nonce:             0, // miners grind this when launching
	}
	block := &types.Block{Header: header, Outputs: outputs}
	types.SetBlockRoots(block)
	return block, info, gvtInfos, nil
}

// LegacyOutputInfo carries the bookkeeping data the wallet needs to
// recognize one of its own legacy outputs. The hash uniquely identifies
// the output in the UTXO set; the address & amount let a wallet display
// it as "your old Noso balance".
type LegacyOutputInfo struct {
	LegacyAddress string
	Amount        int64
	Commit        types.Commitment
	OutputHash    types.Hash
}

// LegacyGVTInfo identifies one inherited v1 GVT (0..99) and its v1
// owner. Wallets use this to display "you own GVT #47" and to
// construct redeem/transfer transactions.
type LegacyGVTInfo struct {
	GVTNumber     uint8
	LegacyAddress string
	Commit        types.Commitment
	OutputHash    types.Hash
}

// newLegacyGVTOutput crafts the Pedersen commitment for a carried-over
// GVT. The commit value is GVTBaseValue (so any future redeem produces
// exactly that many NOSO base units) and the blinding factor is
// deterministically derived from the GVT slot number so independent
// implementations agree.
func newLegacyGVTOutput(owner string, slot uint8) (types.Output, LegacyGVTInfo) {
	blind := sha256.Sum256([]byte(fmt.Sprintf("NosoX legacy GVT blind %02d %s", slot, owner)))
	commit, err := v2crypto.PedersenCommit(types.GVTBaseValue, blind[:])
	if err != nil {
		panic(fmt.Sprintf("genesis: gvt pedersen commit failed: %v", err))
	}
	out := types.Output{
		Features:      types.OutputFeaturesLegacyGVT,
		Commit:        commit,
		LegacyAddress: owner,
		LegacyAmount:  types.GVTBaseValue,
		GVTNumber:     slot,
	}
	return out, LegacyGVTInfo{
		GVTNumber:     slot,
		LegacyAddress: owner,
		Commit:        commit,
		OutputHash:    types.OutputID(&out),
	}
}

// newLegacyOutput crafts a Pedersen commit whose value is the carried
// balance and whose blinding factor is deterministically derived from
// the legacy address. The blinding factor is intentionally public so
// any node can reconstruct the commit; legacy outputs are NOT private —
// privacy starts when the legacy owner spends them.
func newLegacyOutput(legacyAddress string, balance int64) (types.Output, LegacyOutputInfo) {
	// Public blinding factor = SHA-256("NosoX legacy blind " + address).
	blind := sha256.Sum256([]byte("NosoX legacy blind " + legacyAddress))
	commit, err := v2crypto.PedersenCommit(balance, blind[:])
	if err != nil {
		// Should not happen with valid inputs.
		panic(fmt.Sprintf("genesis: pedersen commit failed: %v", err))
	}
	out := types.Output{
		Features:      types.OutputFeaturesLegacy,
		Commit:        commit,
		LegacyAddress: legacyAddress,
		LegacyAmount:  balance,
	}
	id := types.OutputID(&out)
	return out, LegacyOutputInfo{
		LegacyAddress: legacyAddress,
		Amount:        balance,
		Commit:        commit,
		OutputHash:    id,
	}
}

// outputIDs returns the canonical-hash ID for each output.
func outputIDs(outs []types.Output) []types.Hash {
	ids := make([]types.Hash, len(outs))
	for i := range outs {
		ids[i] = types.OutputID(&outs[i])
	}
	return ids
}

// merkleRoot is a simple binary tree over SHA-256 with duplicate-last
// padding (a la Bitcoin). Used as a stable identity for the per-block
// output and kernel sets.
func merkleRoot(leaves []types.Hash) types.Hash {
	if len(leaves) == 0 {
		return zeroHash()
	}
	level := make([]types.Hash, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([]types.Hash, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			var buf [64]byte
			copy(buf[:32], level[i][:])
			copy(buf[32:], level[i+1][:])
			next[i/2] = sha256.Sum256(buf[:])
		}
		level = next
	}
	return level[0]
}

func zeroHash() types.Hash {
	return types.Hash{}
}

// Stats summarizes a built genesis. Useful for the CLI / explorer.
type Stats struct {
	LegacyAccounts int
	LegacyGVTs     int
	TotalCarried   int64
	GVTValue       int64
	OutputRoot     types.Hash
	GenesisHash    types.Hash
	Difficulty     uint64
	NetworkMagic   uint32
}

// Summarize runs Build and returns just the numbers, useful for the CLI.
func Summarize(cfg Config) (Stats, error) {
	block, info, gvts, err := Build(cfg)
	if err != nil {
		return Stats{}, err
	}
	var total int64
	for _, o := range info {
		total += o.Amount
	}
	return Stats{
		LegacyAccounts: len(info),
		LegacyGVTs:     len(gvts),
		TotalCarried:   total,
		GVTValue:       int64(len(gvts)) * types.GVTBaseValue,
		OutputRoot:     block.Header.OutputRoot,
		GenesisHash:    types.HeaderID(&block.Header),
		Difficulty:     block.Header.Difficulty,
		NetworkMagic:   cfg.NetworkMagic,
	}, nil
}

// canonicalNetworkID is a small fingerprint included in some early-block
// kernel commitments so two networks with identical genesis state but
// different magic don't accidentally merge.
func canonicalNetworkID(magic uint32) [4]byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], magic)
	return b
}
