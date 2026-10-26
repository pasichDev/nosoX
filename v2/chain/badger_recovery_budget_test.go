package chain

import (
	"errors"
	"math"
	"testing"

	"github.com/dgraph-io/badger/v4"
)

func TestBadgerRecoveryDistinctKeyBudgetAndSeek(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleSet(t, s, map[string][]byte{"committed": []byte("retained")})
	active := s.active.Load()
	// Embedded-zero extension keys prove Seek(key||0) skips only the exact
	// user's versions, not keys that merely share the same prefix.
	keys := []string{"k", "k\x00", "k\x00a", "ka"}
	for ts := active + 1; ts <= active+64; ts++ {
		wb := s.db.NewWriteBatchAt(ts)
		for _, key := range keys {
			if ts == active+64 && key == "k" {
				err = wb.Delete([]byte(key))
			} else {
				err = wb.Set([]byte(key), []byte{byte(ts)})
			}
			if err != nil {
				wb.Cancel()
				t.Fatal(err)
			}
		}
		if err := wb.Flush(); err != nil {
			wb.Cancel()
			t.Fatal(err)
		}
		wb.Cancel()
	}
	txn := s.db.NewTransactionAt(math.MaxUint64, false)
	dirty, err := recoverDirtyKeys(txn, active, len(keys))
	if err != nil {
		t.Fatal(err)
	}
	if len(dirty) != len(keys) {
		t.Fatalf("distinct keys: %d", len(dirty))
	}
	for _, key := range keys {
		if _, ok := dirty[key]; !ok {
			t.Fatalf("lost key/tombstone %q", key)
		}
	}
	if _, err := txn.Get([]byte("k")); !errors.Is(err, badger.ErrKeyNotFound) {
		t.Fatalf("latest tombstone: %v", err)
	}
	if _, err := recoverDirtyKeys(txn, active, len(keys)-1); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("budget+1 accepted: %v", err)
	}
	if _, err := recoverDirtyKeys(txn, active, 0); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("zero budget: %v", err)
	}
	// Rejecting a scan must not modify the database or its active state.
	if s.active.Load() != active {
		t.Fatal("recovery budget failure changed active fence")
	}
	dirtyAgain, err := recoverDirtyKeys(txn, active, len(keys))
	if err != nil || len(dirtyAgain) != len(keys) {
		t.Fatalf("budget failure destroyed recoverable data: %v", err)
	}
	txn.Discard()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.dirty) != len(keys) {
		t.Fatalf("reopen lost distinct future keys: %d", len(s.dirty))
	}
	lifecycleSet(t, s, map[string][]byte{"retry": []byte("different")})
	if err := s.view(func(txn *badger.Txn) error {
		for _, key := range keys {
			lifecycleValue(t, txn, key, nil)
		}
		lifecycleValue(t, txn, "committed", []byte("retained"))
		lifecycleValue(t, txn, "retry", []byte("different"))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBadgerRecoveryEmptyZeroBudget(t *testing.T) {
	s, err := OpenBadger(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	txn := s.db.NewTransactionAt(math.MaxUint64, false)
	defer txn.Discard()
	dirty, err := recoverDirtyKeys(txn, s.active.Load(), 0)
	if err != nil || len(dirty) != 0 {
		t.Fatalf("empty recovery exceeded zero budget: %v", err)
	}
}
