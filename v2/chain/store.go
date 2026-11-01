package chain

import (
	"encoding/binary"

	"github.com/pasichDev/nosoX/v2/types"
)

// Store is the persistence backend the Chain delegates to. Two
// implementations: an in-memory store for tests (memStore) and a
// BadgerDB store for production (BadgerStore). Both must obey identical
// semantics — write-then-read returns the same bytes — so swapping does
// not change consensus.
type Store interface {
	// Tip returns the current chain tip header. (false if empty.)
	Tip() (types.BlockHeader, bool)
	// HeightOf maps a block hash → height. (false if unknown.)
	HeightOf(types.Hash) (uint64, bool)
	// BlockAt fetches the block at the given height. (error if absent.)
	BlockAt(uint64) (*types.Block, error)
	// UndoAt returns complete spent outputs for a canonical block, as isolated copies.
	UndoAt(uint64) ([]types.Output, error)
	// UndoAtBudget returns only records whose decoded charge fits maxBytes.
	// Memory checks before cloning; persistent stores must bound encoded record
	// allocation before decoding, then check the decoded charge before returning.
	UndoAtBudget(height uint64, maxBytes uint64) ([]types.Output, error)
	// ReplaceSuffix atomically replaces blocks after ancestor; failure preserves state.
	// Like WriteBlock it checks raw consistency and requires prior Chain validation.
	ReplaceSuffix(ancestor uint64, incoming []*types.Block) error
	// BlockByHash fetches a block by its header hash.
	BlockByHash(types.Hash) (*types.Block, error)
	// HasUTXO reports whether the given commitment is currently unspent.
	HasUTXO(types.Commitment) bool
	// HasOutput and HasKernel include spent outputs and all prior kernels.
	HasOutput(types.Commitment) bool
	// OutputHeight returns the height of the block that created the output,
	// whether or not it is still unspent.
	OutputHeight(types.Commitment) (uint64, bool)
	HasKernel(types.Hash) bool
	// UTXOByCommit returns the unspent output for a commitment.
	UTXOByCommit(types.Commitment) (*types.Output, bool)
	// WriteBlock appends at TIP+1 after checking parent and cheap delta/index
	// consistency atomically. It requires prior full Chain consensus validation;
	// signatures, proofs, economics and PoW are not authorized by Store alone.
	WriteBlock(*types.Block) error
	// UndoBlock removes the tip block AND undoes its UTXO delta.
	UndoBlock() error
	// ReplaceChain atomically replaces the complete canonical state. Failure leaves it unchanged.
	ReplaceChain([]*types.Block) error
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
