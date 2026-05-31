package chain

import (
	"encoding/binary"

	"github.com/noso-project/noso-go/v2/types"
)

// Store is the persistence backend the Chain delegates to. Two
// implementations: an in-memory store for tests (memStore) and a
// BadgerDB store for production (badgerStore). Both must obey identical
// semantics — write-then-read returns the same bytes — so swapping does
// not change consensus.
type Store interface {
	// Tip returns the current chain tip header. (false if empty.)
	Tip() (types.BlockHeader, bool)
	// HeightOf maps a block hash → height. (false if unknown.)
	HeightOf(types.Hash) (uint64, bool)
	// BlockAt fetches the block at the given height. (error if absent.)
	BlockAt(uint64) (*types.Block, error)
	// BlockByHash fetches a block by its header hash.
	BlockByHash(types.Hash) (*types.Block, error)
	// HasUTXO reports whether the given commitment is currently unspent.
	HasUTXO(types.Commitment) bool
	// UTXOByCommit returns the unspent output for a commitment.
	UTXOByCommit(types.Commitment) (*types.Output, bool)
	// UTXOByLegacyAddress returns the legacy output bound to addr.
	UTXOByLegacyAddress(string) (*types.Output, bool)
	// WriteBlock appends a new block AT TIP+1, applying its UTXO delta.
	WriteBlock(*types.Block) error
	// UndoBlock removes the tip block AND undoes its UTXO delta.
	UndoBlock() error
	// Save flushes any in-flight state to disk.
	Save() error
	// Close releases backend resources (file handles, mmap, etc.).
	Close() error
}

// height key helpers shared by store backends.
func heightKey(prefix byte, h uint64) []byte {
	out := make([]byte, 9)
	out[0] = prefix
	binary.BigEndian.PutUint64(out[1:], h)
	return out
}

func u64ToBytes(v uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, v)
	return out
}

func bytesToU64(b []byte) uint64 {
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
