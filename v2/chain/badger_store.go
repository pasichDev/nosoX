package chain

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"

	"github.com/dgraph-io/badger/v4"

	"github.com/noso-project/noso-go/v2/types"
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
	kBlock     = byte('b')
	kHash      = byte('h')
	kUTXO      = byte('u')
	kLegacy    = byte('l')
	kTip       = byte('t')
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
		WithSyncWrites(false). // we explicitly Save() before sensitive exits
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
	raw, err := encodeBlock(b)
	if err != nil {
		return err
	}
	headerHash := types.HeaderID(&b.Header)
	height := b.Header.Height
	return s.db.Update(func(txn *badger.Txn) error {
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
			if out, found := s.UTXOByCommit(c); found && out.Features == types.OutputFeaturesLegacy {
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
		// Bump tip.
		return txn.Set([]byte{kTip}, u64ToBytes(height))
	})
}

// UndoBlock removes the tip block and reverses its UTXO delta. Used for
// reorgs.
func (s *BadgerStore) UndoBlock() error {
	tip, ok := s.Tip()
	if !ok {
		return errors.New("badger: cannot undo, store is empty")
	}
	if tip.Height == 0 {
		return errors.New("badger: refuse to undo genesis")
	}
	b, err := s.BlockAt(tip.Height)
	if err != nil {
		return err
	}
	headerHash := types.HeaderID(&b.Header)
	return s.db.Update(func(txn *badger.Txn) error {
		// Remove the block's outputs from UTXO set.
		for i := range b.Outputs {
			out := b.Outputs[i]
			if err := txn.Delete(append([]byte{kUTXO}, out.Commit[:]...)); err != nil {
				return err
			}
			if out.Features == types.OutputFeaturesLegacy {
				if err := txn.Delete(append([]byte{kLegacy}, []byte(out.LegacyAddress)...)); err != nil {
					return err
				}
			}
		}
		// Restore inputs to UTXO set. Each input copy carries enough data
		// (Features, Commit, LegacyAddr, LegacyAmount) to reconstruct
		// the output that was spent.
		for i := range b.Inputs {
			in := b.Inputs[i]
			restored := types.Output{
				Features:      in.Features,
				Commit:        in.Commit,
				LegacyAddress: in.LegacyAddr,
				LegacyAmount:  in.LegacyAmount,
			}
			val, err := encodeOutput(&restored)
			if err != nil {
				return err
			}
			if err := txn.Set(append([]byte{kUTXO}, in.Commit[:]...), val); err != nil {
				return err
			}
			if restored.Features == types.OutputFeaturesLegacy {
				if err := txn.Set(append([]byte{kLegacy}, []byte(restored.LegacyAddress)...), append([]byte(nil), restored.Commit[:]...)); err != nil {
					return err
				}
			}
		}
		// Drop the block + hash index.
		if err := txn.Delete(heightKey(kBlock, tip.Height)); err != nil {
			return err
		}
		if err := txn.Delete(append([]byte{kHash}, headerHash[:]...)); err != nil {
			return err
		}
		// Bump tip backwards.
		return txn.Set([]byte{kTip}, u64ToBytes(tip.Height-1))
	})
}

// silentBadgerLogger swallows BadgerDB's chatty info-level output.
type silentBadgerLogger struct{}

func (silentBadgerLogger) Errorf(string, ...interface{})   {}
func (silentBadgerLogger) Warningf(string, ...interface{}) {}
func (silentBadgerLogger) Infof(string, ...interface{})    {}
func (silentBadgerLogger) Debugf(string, ...interface{})   {}
