package chain

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"

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
// All values are gob-encoded for forward compatibility; this is intentional
// since Noso v2 records contain dynamic-length fields.
const (
	kBlock      = byte('b')
	kHash       = byte('h')
	kUTXO       = byte('u')
	kLegacy     = byte('l')
	kTip        = byte('t')
	kOutputSeen = byte('o')
	kKernelSeen = byte('k')
)

// BadgerStore implements Store on top of Dgraph's BadgerDB key-value
// store. Single-writer semantics; the Chain mutex above already
// serializes mutations.
type BadgerStore struct {
	db *badger.DB
}

// OpenBadger opens (or creates) the database at dir.
func OpenBadger(dir string) (*BadgerStore, error) {
	opts := badger.DefaultOptions(dir).
		WithLogger(silentBadgerLogger{}).
		WithSyncWrites(true). // accepted transactions must survive a process crash
		WithCompactL0OnClose(true)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &BadgerStore{db: db}, nil
}

// Close releases resources.
func (s *BadgerStore) Close() error { return s.db.Close() }

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
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&b); err != nil {
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
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&o); err != nil {
		return nil, err
	}
	return &o, nil
}

// Tip reads the singleton tip height and the block at that height.
func (s *BadgerStore) Tip() (types.BlockHeader, bool) {
	var h uint64
	err := s.db.View(func(txn *badger.Txn) error {
		it, err := txn.Get([]byte{kTip})
		if err != nil {
			return err
		}
		return it.Value(func(val []byte) error {
			h = bytesToU64(val)
			return nil
		})
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return types.BlockHeader{}, false
	}
	if err != nil {
		return types.BlockHeader{}, false
	}
	b, err := s.BlockAt(h)
	if err != nil {
		return types.BlockHeader{}, false
	}
	return b.Header, true
}

// HeightOf returns the height for a block hash.
func (s *BadgerStore) HeightOf(hash types.Hash) (uint64, bool) {
	var height uint64
	err := s.db.View(func(txn *badger.Txn) error {
		it, err := txn.Get(append([]byte{kHash}, hash[:]...))
		if err != nil {
			return err
		}
		return it.Value(func(val []byte) error {
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
	err := s.db.View(func(txn *badger.Txn) error {
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
	h, ok := s.HeightOf(hash)
	if !ok {
		return nil, errors.New("badger: unknown block hash")
	}
	return s.BlockAt(h)
}

// HasUTXO returns whether commit is currently unspent.
func (s *BadgerStore) HasUTXO(commit types.Commitment) bool {
	err := s.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(append([]byte{kUTXO}, commit[:]...))
		return err
	})
	return err == nil
}

func (s *BadgerStore) hasSeen(prefix byte, id []byte) bool {
	err := s.db.View(func(txn *badger.Txn) error { _, err := txn.Get(append([]byte{prefix}, id...)); return err })
	return err == nil
}
func (s *BadgerStore) HasOutput(c types.Commitment) bool { return s.hasSeen(kOutputSeen, c[:]) }
func (s *BadgerStore) HasKernel(h types.Hash) bool       { return s.hasSeen(kKernelSeen, h[:]) }

// UTXOByCommit returns the unspent output for a commitment.
func (s *BadgerStore) UTXOByCommit(commit types.Commitment) (*types.Output, bool) {
	var raw []byte
	err := s.db.View(func(txn *badger.Txn) error {
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
	var commit []byte
	err := s.db.View(func(txn *badger.Txn) error {
		it, err := txn.Get(append([]byte{kLegacy}, []byte(addr)...))
		if err != nil {
			return err
		}
		return it.Value(func(val []byte) error {
			commit = append([]byte(nil), val...)
			return nil
		})
	})
	if err != nil || len(commit) != 33 {
		return nil, false
	}
	var c types.Commitment
	copy(c[:], commit)
	return s.UTXOByCommit(c)
}

// WriteBlock appends b at tip+1 and applies its UTXO delta.
func (s *BadgerStore) WriteBlock(b *types.Block) error {
	if b == nil {
		return errors.New("badger: nil block")
	}
	raw, err := encodeBlock(b)
	if err != nil {
		return err
	}
	headerHash := types.HeaderID(&b.Header)
	height := b.Header.Height
	return s.db.Update(func(txn *badger.Txn) error {
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
	tip, ok := s.Tip()
	if !ok || tip.Height == 0 {
		return errors.New("badger: refuse to undo genesis or empty state")
	}
	blocks := make([]*types.Block, 0, tip.Height)
	for h := uint64(0); h < tip.Height; h++ {
		b, err := s.BlockAt(h)
		if err != nil {
			return err
		}
		blocks = append(blocks, b)
	}
	return s.ReplaceChain(blocks)
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
	for _, b := range staged.blocks {
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

// ReplaceChain commits the entire reorg in one Badger transaction. If the
// transaction exceeds Badger's size limit it fails before commit, leaving the
// old chain intact; operators must not split this into multiple transactions.
func (s *BadgerStore) ReplaceChain(blocks []*types.Block) error {
	entries, err := stateEntries(blocks)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		var keys [][]byte
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.KeyCopy(nil)
			want, ok := entries[string(key)]
			if !ok {
				keys = append(keys, key)
				continue
			}
			same := false
			if err := item.Value(func(raw []byte) error { same = bytes.Equal(raw, want); return nil }); err != nil {
				it.Close()
				return err
			}
			if same {
				delete(entries, string(key))
			}
		}
		it.Close()
		for _, key := range keys {
			if err := txn.Delete(key); err != nil {
				return err
			}
		}

		for key, val := range entries {
			if err := txn.Set([]byte(key), val); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *BadgerStore) verifyState(blocks []*types.Block) error {
	entries, err := stateEntries(blocks)
	if err != nil {
		return err
	}
	return s.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		count := 0
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			want, ok := entries[string(item.Key())]
			if !ok {
				return errors.New("badger: unexpected persisted state key")
			}
			if err := item.Value(func(raw []byte) error {
				if !bytes.Equal(raw, want) {
					return errors.New("badger: persisted state differs from verified history")
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
	err := s.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		it.Rewind()
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
