package chain

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/dgraph-io/badger/v4"

	"github.com/pasichDev/noso-go/v2/types"
)

// BadgerDB key layout (single shared keyspace, prefix-byte tagged):
//
//	'b' || u64(height)            -> gob-encoded *types.Block
//	'h' || sha256(hash)           -> u64(height)
//	'u' || commit_33b             -> gob-encoded types.Output (UTXO)
//	'l' || legacy_address         -> commit_33b (UTXO lookup by address)
//	't'                           -> u64(tip_height)   (singleton)
//
// Blocks, outputs and undo records use gob; heights, commitments and presence
// markers use fixed encodings. The active marker is the durable MVCC fence.
const (
	kBlock      = byte('b')
	kHash       = byte('h')
	kUTXO       = byte('u')
	kLegacy     = byte('l')
	kTip        = byte('t')
	kOutputSeen = byte('o')
	kKernelSeen = byte('k')
	kUndo       = byte('d')
	kActive     = byte('a')
	// A v4 maximum-depth suffix touches fewer than 44*1024+1 distinct keys;
	// trusted genesis touches at most 3*10000+4. One recovery stage is bounded
	// by the larger envelope, not an unbounded union of failed candidates.
	MaxRecoveryKeys = 64 << 10
)

// BadgerStore implements Store on top of Dgraph's BadgerDB key-value
// store. Single-writer semantics; the Chain mutex above already
// serializes mutations.
type BadgerStore struct {
	db     *badger.DB
	mu     sync.Mutex
	active atomic.Uint64
	next   uint64
	dirty  map[string]struct{}
	// readersMu makes registering a snapshot atomic with publishing the fence
	// and advancing Badger's managed discard timestamp. Badger does not track
	// managed readers for the caller.
	readersMu   sync.Mutex
	readers     map[uint64]int
	discard     uint64
	maintenance sync.Mutex
	// fault is test-only; it can fail persistence, never bypass validation.
	fault func(string) error
}

// OpenBadger opens (or creates) the database at dir.
func OpenBadger(dir string) (*BadgerStore, error) {
	opts := badger.DefaultOptions(dir).
		WithLogger(silentBadgerLogger{}).
		WithSyncWrites(true).       // accepted stages and fences survive a process crash
		WithDetectConflicts(false). // mutations are serialized by mu
		WithNumVersionsToKeep(1).
		WithCompactL0OnClose(true)
	return openBadger(opts)
}

func openBadger(opts badger.Options) (*BadgerStore, error) {
	db, err := badger.OpenManaged(opts)
	if err != nil {
		return nil, err
	}
	s := &BadgerStore{db: db, dirty: map[string]struct{}{}, readers: map[uint64]int{}}
	txn := db.NewTransactionAt(math.MaxUint64, false)
	defer txn.Discard()
	item, err := txn.Get([]byte{kActive})
	if errors.Is(err, badger.ErrKeyNotFound) {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		it.Rewind()
		nonempty := it.Valid()
		it.Close()
		if nonempty {
			txn.Discard()
			db.Close()
			return nil, errors.New("badger: old or incomplete schema; explicit reset required")
		}
		// Establish the schema before the first stage, so interrupted genesis
		// initialization is recoverable without confusing it with an old schema.
		fence := db.NewTransactionAt(0, true)
		err = fence.Set([]byte{kActive}, u64ToBytes(1))
		if err == nil {
			err = fence.CommitAt(1, nil)
		}
		fence.Discard()
		if err != nil {
			txn.Discard()
			db.Close()
			return nil, err
		}
		s.active.Store(1)
	} else if err != nil {
		txn.Discard()
		db.Close()
		return nil, err
	} else {
		var ts uint64
		err = item.Value(func(raw []byte) error {
			if len(raw) != 8 {
				return errors.New("badger: corrupt active fence")
			}
			ts = bytesToU64(raw)
			return nil
		})
		if err != nil || ts == 0 || ts != item.Version() {
			txn.Discard()
			db.Close()
			return nil, errors.New("badger: invalid active fence")
		}
		s.active.Store(ts)
	}
	s.next = db.MaxVersion()
	// Recover unpublished keys, including tombstones, before enabling discard.
	// They are newer than active, so a cutoff at active preserves them and the
	// newest committed version needed to restore each key on the next publish.
	s.dirty, err = recoverDirtyKeys(txn, s.active.Load(), MaxRecoveryKeys)
	if err != nil {
		txn.Discard()
		db.Close()
		return nil, err
	}
	txn.Discard()
	s.advanceDiscardLocked()
	return s, nil
}

// recoverDirtyKeys visits the latest unpublished version of each user key,
// including tombstones. Seek(key || 0) moves strictly past all versions of that
// exact key while retaining extension keys (including an exact key || 0).
// This avoids walking every version produced by repeated failed restorations.
func recoverDirtyKeys(txn *badger.Txn, active uint64, limit int) (map[string]struct{}, error) {
	opt := badger.DefaultIteratorOptions
	opt.AllVersions = true
	opt.PrefetchValues = false
	opt.SinceTs = active
	it := txn.NewIterator(opt)
	defer it.Close()
	dirty := make(map[string]struct{})
	for it.Rewind(); it.Valid(); {
		if len(dirty) >= limit {
			return nil, fmt.Errorf("%w: unpublished recovery key count exceeds %d", ErrResourceBudget, limit)
		}
		key := it.Item().KeyCopy(nil)
		dirty[string(key)] = struct{}{}
		it.Seek(append(key, 0))
	}
	return dirty, nil
}

// Close releases resources.
func (s *BadgerStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maintenance.Lock()
	defer s.maintenance.Unlock()
	return s.db.Close()
}

// Reclaim requests one value-log GC attempt. Normal Badger compaction reclaims
// obsolete LSM versions automatically using the reader-safe cutoff; callers
// should invoke Reclaim periodically to reclaim value-log files as well.
// Concurrent attempts are rejected. Cancellation is checked before work and on
// return: Badger's single synchronous GC attempt cannot be interrupted in flight.
func (s *BadgerStore) Reclaim(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.maintenance.TryLock() {
		return badger.ErrRejected
	}
	defer s.maintenance.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	err := s.db.RunValueLogGC(0.5)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, badger.ErrNoRewrite) {
		return nil
	}
	return err
}

// Save calls Sync to make sure outstanding writes are on disk.
func (s *BadgerStore) Save() error { return s.db.Sync() }

func encodeBlock(b *types.Block) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeBlock(raw []byte) (*types.Block, error) {
	var b types.Block
	if err := decodeRecord(raw, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func encodeOutput(o *types.Output) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(o); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeOutput(raw []byte) (*types.Output, error) {
	var o types.Output
	if err := decodeRecord(raw, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

// Tip reads the singleton tip height and the block at that height.
func (s *BadgerStore) Tip() (types.BlockHeader, bool) {
	var header types.BlockHeader
	err := s.view(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte{kTip})
		if err != nil {
			return err
		}
		raw, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		if len(raw) != 8 {
			return errors.New("badger: invalid tip")
		}
		block, err := blockAtTxn(txn, bytesToU64(raw))
		if err == nil {
			header = block.Header
		}
		return err
	})
	return header, err == nil
}
func blockAtTxn(txn *badger.Txn, h uint64) (*types.Block, error) {
	item, err := txn.Get(heightKey(kBlock, h))
	if err != nil {
		return nil, err
	}
	raw, err := item.ValueCopy(nil)
	if err != nil {
		return nil, err
	}
	return decodeBlock(raw)
}

// HeightOf returns the height for a block hash.
func (s *BadgerStore) HeightOf(hash types.Hash) (uint64, bool) {
	var height uint64
	err := s.view(func(txn *badger.Txn) error {
		it, err := txn.Get(append([]byte{kHash}, hash[:]...))
		if err != nil {
			return err
		}
		return it.Value(func(val []byte) error {
			if len(val) != 8 {
				return errors.New("badger: invalid hash index height")
			}
			height = bytesToU64(val)
			return nil
		})
	})
	if err != nil {
		return 0, false
	}
	return height, true
}

// BlockAt returns the block at the given height.
func (s *BadgerStore) BlockAt(h uint64) (*types.Block, error) {
	var raw []byte
	err := s.view(func(txn *badger.Txn) error {
		it, err := txn.Get(heightKey(kBlock, h))
		if err != nil {
			return err
		}
		return it.Value(func(val []byte) error {
			raw = append([]byte(nil), val...)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("badger: block %d: %w", h, err)
	}
	return decodeBlock(raw)
}

// BlockByHash returns a block by hash.
func (s *BadgerStore) BlockByHash(hash types.Hash) (*types.Block, error) {
	var block *types.Block
	err := s.view(func(txn *badger.Txn) error {
		item, err := txn.Get(append([]byte{kHash}, hash[:]...))
		if err != nil {
			return err
		}
		raw, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		if len(raw) != 8 {
			return errors.New("badger: invalid hash index")
		}
		block, err = blockAtTxn(txn, bytesToU64(raw))
		return err
	})
	return block, err
}

// HasUTXO returns whether commit is currently unspent.
func (s *BadgerStore) HasUTXO(commit types.Commitment) bool {
	err := s.view(func(txn *badger.Txn) error {
		_, err := txn.Get(append([]byte{kUTXO}, commit[:]...))
		return err
	})
	return err == nil
}

// hasSeen is used to enforce consensus history uniqueness. Only an explicit
// missing-key result means an identity is unused; every other storage error
// must reject admission rather than silently allowing an output/kernel replay.
func (s *BadgerStore) hasSeen(prefix byte, id []byte) bool {
	err := s.view(func(txn *badger.Txn) error { _, err := txn.Get(append([]byte{prefix}, id...)); return err })
	return !errors.Is(err, badger.ErrKeyNotFound)
}
func (s *BadgerStore) HasOutput(c types.Commitment) bool { return s.hasSeen(kOutputSeen, c[:]) }
func (s *BadgerStore) HasKernel(h types.Hash) bool       { return s.hasSeen(kKernelSeen, h[:]) }

// UTXOByCommit returns the unspent output for a commitment.
func (s *BadgerStore) UTXOByCommit(commit types.Commitment) (*types.Output, bool) {
	var raw []byte
	err := s.view(func(txn *badger.Txn) error {
		it, err := txn.Get(append([]byte{kUTXO}, commit[:]...))
		if err != nil {
			return err
		}
		return it.Value(func(val []byte) error {
			raw = append([]byte(nil), val...)
			return nil
		})
	})
	if err != nil {
		return nil, false
	}
	o, err := decodeOutput(raw)
	if err != nil {
		return nil, false
	}
	return o, true
}

// UTXOByLegacyAddress returns the legacy output for the given address.
func (s *BadgerStore) UTXOByLegacyAddress(addr string) (*types.Output, bool) {
	var out *types.Output
	err := s.view(func(txn *badger.Txn) error {
		item, err := txn.Get(append([]byte{kLegacy}, []byte(addr)...))
		if err != nil {
			return err
		}
		c, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		if len(c) != 33 {
			return errors.New("badger: invalid legacy index")
		}
		item, err = txn.Get(append([]byte{kUTXO}, c...))
		if err != nil {
			return err
		}
		raw, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		out, err = decodeOutput(raw)
		return err
	})
	return out, err == nil
}

// WriteBlock appends b at tip+1 and applies its UTXO delta.
func (s *BadgerStore) WriteBlock(b *types.Block) error {
	if b == nil {
		return errors.New("badger: nil block")
	}
	if err := bodyBounds(b); err != nil {
		return err
	}
	raw, err := encodeBlock(b)
	if err != nil {
		return err
	}
	headerHash := types.HeaderID(&b.Header)
	height := b.Header.Height
	return s.mutate(func(txn *stageTxn) error {
		// All preconditions participate in this transaction's read set. A backend
		// error is not treated as a missing key and cannot authorize a partial delta.
		exists := func(key []byte) (bool, error) {
			_, err := txn.Get(key)
			if errors.Is(err, badger.ErrKeyNotFound) {
				return false, nil
			}
			return err == nil, err
		}
		item, err := txn.Get([]byte{kTip})
		if errors.Is(err, badger.ErrKeyNotFound) {
			if height != 0 || !b.Header.PrevHash.IsZero() {
				return ErrStale
			}
			it := txn.NewIterator(badger.DefaultIteratorOptions)
			it.Rewind()
			for it.Valid() && bytes.Equal(it.Item().Key(), []byte{kActive}) {
				it.Next()
			}
			empty := !it.Valid()
			it.Close()
			if !empty {
				return errors.New("badger: missing tip in nonempty state")
			}
		} else if err != nil {
			return err
		} else {
			var tipHeight uint64
			if err := item.Value(func(raw []byte) error {
				if len(raw) != 8 {
					return errors.New("badger: invalid tip height")
				}
				tipHeight = bytesToU64(raw)
				return nil
			}); err != nil {
				return err
			}
			tipItem, err := txn.Get(heightKey(kBlock, tipHeight))
			if err != nil {
				return err
			}
			var tip *types.Block
			if err := tipItem.Value(func(raw []byte) error { var err error; tip, err = decodeBlock(raw); return err }); err != nil {
				return err
			}
			if tip.Header.Height != tipHeight || tipHeight == ^uint64(0) || height != tipHeight+1 || b.Header.PrevHash != types.HeaderID(&tip.Header) {
				return ErrStale
			}
		}
		for _, key := range [][]byte{heightKey(kBlock, height), append([]byte{kHash}, headerHash[:]...)} {
			present, err := exists(key)
			if err != nil {
				return err
			}
			if present {
				return errors.New("badger: block index already exists")
			}
		}
		spent, err := checkStoreDelta(b, deltaReader{
			output: func(c types.Commitment) (*types.Output, bool, error) {
				item, err := txn.Get(append([]byte{kUTXO}, c[:]...))
				if errors.Is(err, badger.ErrKeyNotFound) {
					return nil, false, nil
				}
				if err != nil {
					return nil, false, err
				}
				var out *types.Output
				if err := item.Value(func(raw []byte) error { var err error; out, err = decodeOutput(raw); return err }); err != nil {
					return nil, false, err
				}
				return out, true, nil
			},
			seenOutput: func(c types.Commitment) (bool, error) { return exists(append([]byte{kOutputSeen}, c[:]...)) },
			seenKernel: func(id types.Hash) (bool, error) { return exists(append([]byte{kKernelSeen}, id[:]...)) },
		})
		if err != nil {
			return err
		}
		if _, err := undoResourceBytes(spent); err != nil {
			return err
		}
		undoRaw, err := encodeUndo(spent)
		if err != nil {
			return err
		}
		if err := txn.Set(heightKey(kUndo, height), undoRaw); err != nil {
			return err
		}
		// Store block + hash index.
		if err := txn.Set(heightKey(kBlock, height), raw); err != nil {
			return err
		}
		if err := txn.Set(append([]byte{kHash}, headerHash[:]...), u64ToBytes(height)); err != nil {
			return err
		}
		// Remove spent inputs.
		for i := range b.Inputs {
			c := b.Inputs[i].Commit
			// Drop legacy index if present.
			out := spent[i]
			if out.Features == types.OutputFeaturesLegacy {
				if err := txn.Delete(append([]byte{kLegacy}, []byte(out.LegacyAddress)...)); err != nil {
					return err
				}
			}
			if err := txn.Delete(append([]byte{kUTXO}, c[:]...)); err != nil {
				return err
			}
		}
		// Add new outputs.
		for i := range b.Outputs {
			out := b.Outputs[i]
			if err := txn.Set(append([]byte{kOutputSeen}, out.Commit[:]...), []byte{1}); err != nil {
				return err
			}
			val, err := encodeOutput(&out)
			if err != nil {
				return err
			}
			if err := txn.Set(append([]byte{kUTXO}, out.Commit[:]...), val); err != nil {
				return err
			}
			if out.Features == types.OutputFeaturesLegacy {
				if err := txn.Set(append([]byte{kLegacy}, []byte(out.LegacyAddress)...), append([]byte(nil), out.Commit[:]...)); err != nil {
					return err
				}
			}
		}
		for _, k := range b.Kernels {
			id := types.KernelID(&k)
			if err := txn.Set(append([]byte{kKernelSeen}, id[:]...), []byte{1}); err != nil {
				return err
			}
		}
		// Bump tip.
		return txn.Set([]byte{kTip}, u64ToBytes(height))
	})
}

// UndoBlock removes the tip block and reverses its UTXO delta. Used for
// reorgs.
func (s *BadgerStore) UndoBlock() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tip, ok := s.Tip()
	if !ok || tip.Height == 0 {
		return errors.New("badger: refuse to undo genesis or empty state")
	}
	return s.replaceSuffixLocked(tip.Height-1, nil)
}

func encodeUndo(outputs []types.Output) ([]byte, error) {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(outputs)
	return buf.Bytes(), err
}
func (s *BadgerStore) UndoAt(h uint64) ([]types.Output, error) {
	return s.UndoAtBudget(h, MaxUndoRecordBytes)
}

// UndoAtBudget bounds raw storage before gob decoding, then charges decoded
// resource bytes before allowing a fork overlay to retain the record.
func (s *BadgerStore) UndoAtBudget(h uint64, maxBytes uint64) ([]types.Output, error) {
	var outputs []types.Output
	err := s.view(func(txn *badger.Txn) error {
		item, err := txn.Get(heightKey(kUndo, h))
		if err != nil {
			return err
		}
		if item.ValueSize() > MaxEncodedUndoBytes {
			return fmt.Errorf("%w: encoded undo record", ErrResourceBudget)
		}
		return item.Value(func(raw []byte) error { return decodeRecord(raw, &outputs) })
	})
	if err == nil {
		var size uint64
		size, err = undoResourceBytes(outputs)
		if err == nil && size > maxBytes {
			err = fmt.Errorf("%w: remaining undo budget", ErrResourceBudget)
		}
	}
	if err != nil {
		return nil, err
	}
	if outputs == nil && err == nil {
		outputs = []types.Output{}
	}
	return outputs, err
}

// stateEntries builds the complete derived state using the same memory-store
// transition as reorg validation. Blocks and all output metadata are preserved.
func stateEntries(blocks []*types.Block) (map[string][]byte, error) {
	staged := newMemStore()
	for _, b := range blocks {
		if b == nil {
			return nil, errors.New("badger: nil block")
		}
		if err := staged.WriteBlock(b); err != nil {
			return nil, err
		}
	}
	entries := map[string][]byte{}
	for h, undo := range staged.undo {
		raw, err := encodeUndo(undo)
		if err != nil {
			return nil, err
		}
		entries[string(heightKey(kUndo, h))] = raw
	}
	for _, b := range staged.orderedBlocks() {
		raw, err := encodeBlock(b)
		if err != nil {
			return nil, err
		}
		entries[string(heightKey(kBlock, b.Header.Height))] = raw
		hash := types.HeaderID(&b.Header)
		entries[string(append([]byte{kHash}, hash[:]...))] = u64ToBytes(b.Header.Height)
	}
	for c := range staged.outputSeen {
		entries[string(append([]byte{kOutputSeen}, c[:]...))] = []byte{1}
	}
	for id := range staged.kernelSeen {
		entries[string(append([]byte{kKernelSeen}, id[:]...))] = []byte{1}
	}
	for c, o := range staged.utxo {
		raw, err := encodeOutput(&o)
		if err != nil {
			return nil, err
		}
		entries[string(append([]byte{kUTXO}, c[:]...))] = raw
	}
	for addr, c := range staged.legacyIdx {
		entries[string(append([]byte{kLegacy}, []byte(addr)...))] = append([]byte(nil), c[:]...)
	}
	if len(blocks) > 0 {
		entries[string([]byte{kTip})] = u64ToBytes(blocks[len(blocks)-1].Header.Height)
	}
	return entries, nil
}

// ReplaceChain is the trusted full-state import path; ordinary reorgs use
// ReplaceSuffix and never enumerate the retained prefix.
func (s *BadgerStore) ReplaceChain(blocks []*types.Block) error {
	entries, err := stateEntries(blocks)
	if err != nil {
		return err
	}
	return s.mutate(func(txn *stageTxn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			key := it.Item().KeyCopy(nil)
			if key[0] == kActive {
				continue
			}
			if _, ok := entries[string(key)]; !ok {
				txn.Delete(key)
			}
		}
		for key, val := range entries {
			txn.Set([]byte(key), val)
		}
		return nil
	})
}

func (s *BadgerStore) ReplaceSuffix(ancestor uint64, incoming []*types.Block) error {
	if len(incoming) > 1024 {
		return ErrTooDeep
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.replaceSuffixLocked(ancestor, incoming)
}
func (s *BadgerStore) replaceSuffixLocked(ancestor uint64, incoming []*types.Block) error {
	fork, err := newForkStore(s, ancestor)
	if err != nil {
		return err
	}
	for _, b := range incoming {
		if err := fork.WriteBlock(b); err != nil {
			return err
		}
	}
	entries, err := suffixEntries(fork.delta())
	if err != nil {
		return err
	}
	return s.publish(entries)
}

func suffixEntries(d *suffixDelta) (map[string][]byte, error) {
	entries := map[string][]byte{}
	for h, b := range d.Blocks {
		var raw []byte
		var err error
		if b != nil {
			raw, err = encodeBlock(b)
		}
		if err != nil {
			return nil, err
		}
		entries[string(heightKey(kBlock, h))] = raw
	}
	for h, undo := range d.Undo {
		var raw []byte
		var err error
		if undo != nil {
			raw, err = encodeUndo(undo)
		}
		if err != nil {
			return nil, err
		}
		entries[string(heightKey(kUndo, h))] = raw
	}
	for hash, h := range d.Hashes {
		var raw []byte
		if h != nil {
			raw = u64ToBytes(*h)
		}
		entries[string(append([]byte{kHash}, hash[:]...))] = raw
	}
	for c, out := range d.UTXOs {
		var raw []byte
		var err error
		if out != nil {
			raw, err = encodeOutput(out)
		}
		if err != nil {
			return nil, err
		}
		entries[string(append([]byte{kUTXO}, c[:]...))] = raw
	}
	for c, present := range d.Outputs {
		var raw []byte
		if present {
			raw = []byte{1}
		}
		entries[string(append([]byte{kOutputSeen}, c[:]...))] = raw
	}
	for h, present := range d.Kernels {
		var raw []byte
		if present {
			raw = []byte{1}
		}
		entries[string(append([]byte{kKernelSeen}, h[:]...))] = raw
	}
	for addr, c := range d.Legacy {
		var raw []byte
		if c != nil {
			raw = append([]byte{}, c[:]...)
		}
		entries[string(append([]byte{kLegacy}, []byte(addr)...))] = raw
	}
	entries[string([]byte{kTip})] = u64ToBytes(d.Tip.Height)
	return entries, nil
}

// A stage reads exclusively from one committed snapshot, while collecting a
// bounded mutation delta. No stage write is exposed before the durable fence.
type stageTxn struct {
	*badger.Txn
	entries map[string][]byte
}

func (t *stageTxn) Set(k, v []byte) error { t.entries[string(k)] = append([]byte{}, v...); return nil }
func (t *stageTxn) Delete(k []byte) error { t.entries[string(k)] = nil; return nil }
func (s *BadgerStore) view(fn func(*badger.Txn) error) error {
	txn, release := s.snapshot()
	defer release()
	return fn(txn)
}

// snapshot pins the active timestamp until the transaction has been discarded.
// Never hold readersMu while doing I/O or invoking a callback: a writer can
// publish while older readers run, without waiting for them or invalidating them.
func (s *BadgerStore) snapshot() (*badger.Txn, func()) {
	s.readersMu.Lock()
	ts := s.active.Load()
	s.readers[ts]++
	txn := s.db.NewTransactionAt(ts, false)
	s.readersMu.Unlock()
	return txn, func() {
		txn.Discard()
		s.readersMu.Lock()
		defer s.readersMu.Unlock()
		s.readers[ts]--
		if s.readers[ts] == 0 {
			delete(s.readers, ts)
		}
		s.advanceDiscardLocked()
	}
}

// Caller holds readersMu, or is still opening this unpublished store. Never
// advance beyond active: failed stages must retain tombstones and recovery data.
func (s *BadgerStore) advanceDiscardLocked() {
	cutoff := s.active.Load()
	for ts := range s.readers {
		if ts < cutoff {
			cutoff = ts
		}
	}
	if cutoff > s.discard {
		s.db.SetDiscardTs(cutoff)
		s.discard = cutoff
	}
}
func (s *BadgerStore) mutate(fn func(*stageTxn) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	txn, release := s.snapshot()
	defer release()
	staged := &stageTxn{Txn: txn, entries: map[string][]byte{}}
	if err := fn(staged); err != nil {
		return err
	}
	return s.publish(staged.entries)
}
func (s *BadgerStore) publish(entries map[string][]byte) error {
	// Retire an abandoned stage as a standalone same-state publication BEFORE
	// touching any new candidate key. Otherwise repeated failed, different
	// candidates would grow the dirty union without bound. A failed restoration
	// can only touch keys that were already dirty.
	if len(s.dirty) != 0 {
		if err := s.restoreDirty(); err != nil {
			return err
		}
	}
	return s.publishStage(entries)
}

func (s *BadgerStore) restoreDirty() error {
	entries := make(map[string][]byte, len(s.dirty))
	err := s.view(func(txn *badger.Txn) error {
		for key := range s.dirty {
			item, err := txn.Get([]byte(key))
			if errors.Is(err, badger.ErrKeyNotFound) {
				entries[key] = nil
				continue
			}
			if err != nil {
				return err
			}
			raw, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			entries[key] = raw
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.publishStage(entries)
}

// publishStage writes one bounded candidate or restoration delta. Caller holds
// mu. Restoration uses this directly so it never recursively merges candidates.
func (s *BadgerStore) publishStage(entries map[string][]byte) error {
	if s.next == math.MaxUint64 {
		return errors.New("badger: storage timestamp exhausted")
	}
	s.next++
	ts := s.next
	wb := s.db.NewWriteBatchAt(ts)
	defer wb.Cancel()
	wb.SetMaxPendingTxns(1)
	count := 0
	var err error
	for key, val := range entries {
		s.dirty[key] = struct{}{}
		if val == nil {
			err = wb.Delete([]byte(key))
		} else {
			err = wb.Set([]byte(key), val)
		}
		if err != nil {
			return err
		}
		count++
		// Force a durable partial stage for deterministic interrupted-write tests.
		if s.fault != nil && count == 1 {
			if err := wb.Flush(); err != nil {
				return err
			}
			if err := s.fault("mid-stage"); err != nil {
				return err
			}
			wb = s.db.NewWriteBatchAt(ts)
			defer wb.Cancel()
			wb.SetMaxPendingTxns(1)
		}
	}
	if err := wb.Flush(); err != nil {
		return err
	}
	if s.fault != nil {
		if err := s.fault("before-publish"); err != nil {
			return err
		}
	}
	fence := s.db.NewTransactionAt(s.active.Load(), true)
	defer fence.Discard()
	if err := fence.Set([]byte{kActive}, u64ToBytes(ts)); err != nil {
		return err
	}
	if err := fence.CommitAt(ts, nil); err != nil {
		return err
	}
	clear(s.dirty)
	s.readersMu.Lock()
	s.active.Store(ts)
	s.advanceDiscardLocked()
	s.readersMu.Unlock()
	return nil
}

func (s *BadgerStore) verifyState(blocks []*types.Block) error {
	entries, err := stateEntries(blocks)
	if err != nil {
		return err
	}
	return s.view(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		count := 0
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			if bytes.Equal(item.Key(), []byte{kActive}) {
				continue
			}
			want, ok := entries[string(item.Key())]
			if !ok {
				return errors.New("badger: unexpected persisted state key")
			}
			if err := item.Value(func(raw []byte) error {
				if !stateValueEqual(item.Key()[0], raw, want) {
					return fmt.Errorf("badger: persisted state differs from verified history at %x", item.Key())
				}
				return nil
			}); err != nil {
				return err
			}
			count++
		}
		if count != len(entries) {
			return errors.New("badger: missing persisted state key")
		}
		return nil
	})
}

func (s *BadgerStore) isEmpty() (bool, error) {
	empty := true
	err := s.view(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		it.Rewind()
		for it.Valid() && bytes.Equal(it.Item().Key(), []byte{kActive}) {
			it.Next()
		}
		empty = !it.Valid()
		return nil
	})
	return empty, err
}

// silentBadgerLogger swallows BadgerDB's chatty info-level output.
type silentBadgerLogger struct{}

func (silentBadgerLogger) Errorf(string, ...interface{})   {}
func (silentBadgerLogger) Warningf(string, ...interface{}) {}
func (silentBadgerLogger) Infof(string, ...interface{})    {}
func (silentBadgerLogger) Debugf(string, ...interface{})   {}

// Gob type identifiers depend on process registration order. Compare decoded
// values for structured records; byte equality is valid for fixed-width indexes.
func stateValueEqual(prefix byte, a, b []byte) bool {
	switch prefix {
	case kBlock:
		x, err := decodeBlock(a)
		if err != nil {
			return false
		}
		y, err := decodeBlock(b)
		return err == nil && reflect.DeepEqual(x, y)
	case kUTXO:
		x, err := decodeOutput(a)
		if err != nil {
			return false
		}
		y, err := decodeOutput(b)
		return err == nil && reflect.DeepEqual(x, y)
	case kUndo:
		var x, y []types.Output
		if decodeRecord(a, &x) != nil || decodeRecord(b, &y) != nil {
			return false
		}
		return reflect.DeepEqual(x, y)
	default:
		return bytes.Equal(a, b)
	}
}
func (s *BadgerStore) storeDeltaReader() deltaReader {
	exists := func(key []byte) (bool, error) {
		var present bool
		err := s.view(func(txn *badger.Txn) error {
			_, err := txn.Get(key)
			if errors.Is(err, badger.ErrKeyNotFound) {
				return nil
			}
			present = err == nil
			return err
		})
		return present, err
	}
	return deltaReader{
		output: func(c types.Commitment) (*types.Output, bool, error) {
			var out *types.Output
			var present bool
			err := s.view(func(txn *badger.Txn) error {
				item, err := txn.Get(append([]byte{kUTXO}, c[:]...))
				if errors.Is(err, badger.ErrKeyNotFound) {
					return nil
				}
				if err != nil {
					return err
				}
				raw, err := item.ValueCopy(nil)
				if err != nil {
					return err
				}
				out, err = decodeOutput(raw)
				present = err == nil
				return err
			})
			return out, present, err
		},
		seenOutput: func(c types.Commitment) (bool, error) { return exists(append([]byte{kOutputSeen}, c[:]...)) },
		seenKernel: func(h types.Hash) (bool, error) { return exists(append([]byte{kKernelSeen}, h[:]...)) },
	}
}

func decodeRecord(raw []byte, dst any) error {
	dec := gob.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("badger: trailing record data")
	}
	return nil
}
