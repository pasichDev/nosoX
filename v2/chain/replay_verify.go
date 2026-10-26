package chain

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dgraph-io/badger/v4"
	"github.com/pasichDev/noso-go/v2/types"
)

// streamingVerifyHistory replays one canonical block at a time into a disposable
// disk store. It never materializes history, the UTXO set, or complete derived
// state in Go maps. Full replay still needs O(history) time and scratch disk.
func (c *Chain) streamingVerifyHistory(source *BadgerStore, genesis *types.Block) (err error) {
	snapshot, release := source.snapshot()
	defer release()
	g, err := replayBlockAt(snapshot, 0)
	if err != nil {
		return err
	}
	if types.HeaderID(&g.Header) != types.HeaderID(&genesis.Header) {
		return errors.New("chain: stored genesis differs from trusted genesis")
	}
	if err := validateGenesis(g); err != nil {
		return err
	}
	tipItem, err := snapshot.Get([]byte{kTip})
	if err != nil {
		return err
	}
	var tipHeight uint64
	err = tipItem.Value(func(raw []byte) error {
		if len(raw) != 8 {
			return errors.New("chain: invalid persisted tip")
		}
		tipHeight = bytesToU64(raw)
		return nil
	})
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(filepath.Dir(source.db.Opts().Dir), ".nosox-replay-")
	if err != nil {
		return fmt.Errorf("chain: create replay scratch: %w", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(dir); err == nil {
			err = removeErr
		}
	}()
	opts := badger.DefaultOptions(dir).WithLogger(silentBadgerLogger{}).
		WithSyncWrites(false).WithDetectConflicts(false).WithNumVersionsToKeep(1).
		WithBlockCacheSize(32 << 20).WithIndexCacheSize(16 << 20).
		WithMemTableSize(8 << 20).WithNumMemtables(2).
		WithCompactL0OnClose(false)
	scratch, err := openBadger(opts)
	if err != nil {
		return fmt.Errorf("chain: open replay scratch: %w", err)
	}
	defer func() {
		if closeErr := scratch.Close(); err == nil {
			err = closeErr
		}
	}()
	if err := scratch.WriteBlock(g); err != nil {
		return err
	}
	check := &Chain{store: scratch, checkpoints: c.checkpoints, now: c.now}
	for h := uint64(1); h <= tipHeight; h++ {
		b, err := replayBlockAt(snapshot, h)
		if err != nil {
			return err
		}
		if err := check.validate(b); err != nil {
			return fmt.Errorf("chain: invalid persisted block %d: %w", h, err)
		}
		if err := scratch.WriteBlock(b); err != nil {
			return err
		}
		if h == tipHeight {
			break
		} // avoid uint64 wrap on a corrupt maximum tip
	}
	return scratch.view(func(expected *badger.Txn) error { return compareReplayState(snapshot, expected) })
}

func replayBlockAt(txn *badger.Txn, height uint64) (*types.Block, error) {
	item, err := txn.Get(heightKey(kBlock, height))
	if err != nil {
		return nil, fmt.Errorf("chain: persisted block %d: %w", height, err)
	}
	maxBody := int64(MaxBlockBodyBytes)
	if height == 0 {
		maxBody = 8 << 20
	}
	// Fixed gob schema overhead and representation lengths fit comfortably
	// within twice the consensus field charge plus a descriptor allowance.
	if item.ValueSize() > 2*maxBody+4096 {
		return nil, fmt.Errorf("%w: encoded persisted block", ErrResourceBudget)
	}
	var b *types.Block
	err = item.Value(func(raw []byte) error { var err error; b, err = decodeBlock(raw); return err })
	return b, err
}

// compareReplayState walks committed logical keys in order with value prefetch
// disabled. Only one source and one expected record are resident at a time.
// Schema fences differ because replay uses fresh timestamps; all other keys,
// including blocks, history indexes, UTXOs and undo, must agree semantically.
func compareReplayState(source, expected *badger.Txn) error {
	opts := badger.DefaultIteratorOptions
	opts.PrefetchValues = false
	a, b := source.NewIterator(opts), expected.NewIterator(opts)
	defer a.Close()
	defer b.Close()
	a.Rewind()
	b.Rewind()
	for {
		for a.Valid() && bytes.Equal(a.Item().Key(), []byte{kActive}) {
			a.Next()
		}
		for b.Valid() && bytes.Equal(b.Item().Key(), []byte{kActive}) {
			b.Next()
		}
		if !a.Valid() || !b.Valid() {
			if a.Valid() != b.Valid() {
				return errors.New("chain: persisted state key set differs from verified history")
			}
			return nil
		}
		x, y := a.Item(), b.Item()
		if !bytes.Equal(x.Key(), y.Key()) {
			return errors.New("chain: persisted state key differs from verified history")
		}
		if x.ValueSize() > 2*y.ValueSize()+4096 {
			return fmt.Errorf("%w: persisted state value", ErrResourceBudget)
		}
		want, err := y.ValueCopy(nil)
		if err != nil {
			return err
		}
		err = x.Value(func(raw []byte) error {
			if !stateValueEqual(x.Key()[0], raw, want) {
				return fmt.Errorf("chain: persisted state differs from verified history at %x", x.Key())
			}
			return nil
		})
		if err != nil {
			return err
		}
		a.Next()
		b.Next()
	}
}
