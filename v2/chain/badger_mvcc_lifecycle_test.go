package chain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/dgraph-io/badger/v4"
)

func lifecycleSet(t *testing.T, s *BadgerStore, entries map[string][]byte) {
	t.Helper()
	if err := s.mutate(func(txn *stageTxn) error {
		for key, value := range entries {
			if value == nil {
				txn.Delete([]byte(key))
			} else {
				txn.Set([]byte(key), value)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func lifecycleValue(t *testing.T, txn *badger.Txn, key string, want []byte) {
	t.Helper()
	item, err := txn.Get([]byte(key))
	if want == nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			t.Fatalf("%s: wanted missing, got %v", key, err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	got, err := item.ValueCopy(nil)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s: value mismatch: %v", key, err)
	}
}

func TestBadgerLifecyclePinnedReaders(t *testing.T) {
	s, err := OpenBadger(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	lifecycleSet(t, s, map[string][]byte{"x": []byte("first"), "y": []byte("present")})
	old, releaseOld := s.snapshot()
	oldTS := old.ReadTs()
	lifecycleSet(t, s, map[string][]byte{"x": []byte("second"), "y": nil})
	middle, releaseMiddle := s.snapshot()
	lifecycleSet(t, s, map[string][]byte{"x": nil, "y": []byte("again")})
	if err := s.Reclaim(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.discard != oldTS {
		t.Fatalf("discard %d passed pinned timestamp %d", s.discard, oldTS)
	}
	lifecycleValue(t, old, "x", []byte("first"))
	lifecycleValue(t, old, "y", []byte("present"))
	lifecycleValue(t, middle, "x", []byte("second"))
	lifecycleValue(t, middle, "y", nil)
	releaseOld()
	if s.discard != middle.ReadTs() {
		t.Fatal("cutoff did not advance to next oldest reader")
	}
	releaseMiddle()
	if s.discard != s.active.Load() || len(s.readers) != 0 {
		t.Fatal("released readers still pin reclamation")
	}
	if err := s.view(func(txn *badger.Txn) error {
		lifecycleValue(t, txn, "x", nil)
		lifecycleValue(t, txn, "y", []byte("again"))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBadgerLifecycleFailedStageRecovery(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		for _, phase := range []string{"mid-stage", "before-publish"} {
			t.Run(fmt.Sprintf("%s/reopen=%t", phase, reopen), func(t *testing.T) {
				dir := t.TempDir()
				s, err := OpenBadger(dir)
				if err != nil {
					t.Fatal(err)
				}
				lifecycleSet(t, s, map[string][]byte{"x": []byte("committed"), "y": []byte("retained")})
				active := s.active.Load()
				injected := errors.New("failed stage")
				s.fault = func(at string) error {
					if at == phase {
						return injected
					}
					return nil
				}
				err = s.mutate(func(txn *stageTxn) error {
					txn.Delete([]byte("x"))
					txn.Set([]byte("z"), []byte("abandoned"))
					return nil
				})
				if !errors.Is(err, injected) {
					t.Fatalf("failure: %v", err)
				}
				if reopen {
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					s, err = OpenBadger(dir)
					if err != nil {
						t.Fatal(err)
					}
				}
				defer s.Close()
				if s.discard > active || len(s.dirty) == 0 {
					t.Fatal("lost failed-stage recovery versions")
				}
				if err := s.Reclaim(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := s.db.Flatten(1); err != nil {
					t.Fatal(err)
				}
				s.fault = nil
				lifecycleSet(t, s, map[string][]byte{"y": []byte("different retry")})
				if len(s.dirty) != 0 || s.discard != s.active.Load() {
					t.Fatal("successful retry did not retire recovery state")
				}
				if err := s.view(func(txn *badger.Txn) error {
					lifecycleValue(t, txn, "x", []byte("committed"))
					lifecycleValue(t, txn, "y", []byte("different retry"))
					lifecycleValue(t, txn, "z", nil)
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func lifecycleVersions(s *BadgerStore, key string) int {
	txn := s.db.NewTransactionAt(math.MaxUint64, false)
	defer txn.Discard()
	opts := badger.DefaultIteratorOptions
	opts.AllVersions = true
	opts.Prefix = []byte(key)
	it := txn.NewIterator(opts)
	defer it.Close()
	n := 0
	for it.Rewind(); it.Valid(); it.Next() {
		if bytes.Equal(it.Item().Key(), []byte(key)) {
			n++
		}
	}
	return n
}

// Reopen flushes each generation to a distinct L0 table. Explicit Flatten then
// exercises real version removal, without timing assumptions or byte ratios.
func TestBadgerLifecycleCompactionReclaimsVersions(t *testing.T) {
	opts := badger.DefaultOptions(t.TempDir()).WithLogger(silentBadgerLogger{}).
		WithSyncWrites(true).WithDetectConflicts(false).WithNumVersionsToKeep(1).
		WithNumLevelZeroTables(2).WithNumLevelZeroTablesStall(100).
		WithNumCompactors(0).WithCompactL0OnClose(false)
	for i := 0; i < 4; i++ {
		s, err := openBadger(opts)
		if err != nil {
			t.Fatal(err)
		}
		lifecycleSet(t, s, map[string][]byte{"x": []byte{byte(i)}, "y": []byte{byte(i)}})
		if i == 3 {
			lifecycleSet(t, s, map[string][]byte{"y": nil})
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	s, err := openBadger(opts)
	if err != nil {
		t.Fatal(err)
	}
	if n := lifecycleVersions(s, "x"); n != 4 {
		t.Fatalf("fixture versions: %d", n)
	}
	old, release := s.snapshot()
	lifecycleSet(t, s, map[string][]byte{"x": []byte("new")})
	if err := s.db.Flatten(1); err != nil {
		t.Fatal(err)
	}
	lifecycleValue(t, old, "x", []byte{3})
	if n := lifecycleVersions(s, "x"); n != 2 {
		t.Fatalf("expected current and pinned versions after compaction, got %d", n)
	}
	release()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = openBadger(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.db.Flatten(1); err != nil {
		t.Fatal(err)
	}
	if n := lifecycleVersions(s, "x"); n != 1 {
		t.Fatalf("obsolete versions retained after compaction: %d", n)
	}
	if n := lifecycleVersions(s, "y"); n != 0 {
		t.Fatalf("deleted key versions retained after compaction: %d", n)
	}
	if err := s.Reclaim(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestBadgerLifecycleMaintenanceLimits(t *testing.T) {
	s, err := OpenBadger(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Reclaim(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	s.maintenance.Lock()
	if err := s.Reclaim(context.Background()); !errors.Is(err, badger.ErrRejected) {
		t.Fatalf("concurrent GC: %v", err)
	}
	s.maintenance.Unlock()
	// No eligible files: one attempt returns successfully, without retrying.
	if err := s.Reclaim(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Reclaim(context.Background()); !errors.Is(err, badger.ErrRejected) {
		t.Fatalf("closed GC: %v", err)
	}
}

func TestBadgerLifecycleConcurrentViewPublish(t *testing.T) {
	s, err := OpenBadger(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	lifecycleSet(t, s, map[string][]byte{"x": []byte("old")})
	started, finish, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- s.view(func(txn *badger.Txn) error {
			close(started)
			<-finish
			item, err := txn.Get([]byte("x"))
			if err != nil {
				return err
			}
			raw, err := item.ValueCopy(nil)
			if err == nil && !bytes.Equal(raw, []byte("old")) {
				return errors.New("reader lost its committed snapshot")
			}
			return err
		})
	}()
	<-started
	lifecycleSet(t, s, map[string][]byte{"x": []byte("new")})
	if err := s.Reclaim(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(finish)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s.discard != s.active.Load() {
		t.Fatal("released view still pins old state")
	}
}

func TestBadgerLifecycleRepeatedFailuresBoundDirtyKeys(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		t.Run(fmt.Sprintf("reopen=%t", reopen), func(t *testing.T) {
			dir := t.TempDir()
			s, err := OpenBadger(dir)
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("candidate or restoration failure")
			baselineTS := s.active.Load()
			// An interrupted one-key candidate is the only dirty key allowed.
			s.fault = func(at string) error {
				if at == "before-publish" {
					return injected
				}
				return nil
			}
			for i := 0; i < 12; i++ {
				err := s.mutate(func(txn *stageTxn) error { return txn.Set([]byte(fmt.Sprintf("candidate-%d", i)), []byte{byte(i)}) })
				if !errors.Is(err, injected) {
					t.Fatalf("failure %d: %v", i, err)
				}
				if len(s.dirty) != 1 || s.active.Load() != baselineTS {
					t.Fatal("failed restoration accumulated candidate keys or changed state")
				}
				if reopen {
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					s, err = OpenBadger(dir)
					if err != nil {
						t.Fatal(err)
					}
					s.fault = func(at string) error {
						if at == "before-publish" {
							return injected
						}
						return nil
					}
				}
			}
			// Let each restoration finish, then fail its different candidate. The
			// dirty set must remain the size of one stage, rather than their union.
			for i := 12; i < 24; i++ {
				publications := 0
				s.fault = func(at string) error {
					if at == "before-publish" {
						publications++
						if publications == 2 {
							return injected
						}
					}
					return nil
				}
				err := s.mutate(func(txn *stageTxn) error { return txn.Set([]byte(fmt.Sprintf("candidate-%d", i)), []byte{byte(i)}) })
				if !errors.Is(err, injected) || publications != 2 {
					t.Fatalf("restoration/candidate: %v, publications=%d", err, publications)
				}
				if len(s.dirty) != 1 {
					t.Fatalf("dirty union grew: %d", len(s.dirty))
				}
			}
			s.fault = nil
			lifecycleSet(t, s, map[string][]byte{"accepted": []byte("yes")})
			if len(s.dirty) != 0 {
				t.Fatal("recovery did not finish")
			}
			if err := s.view(func(txn *badger.Txn) error {
				for i := 0; i < 24; i++ {
					lifecycleValue(t, txn, fmt.Sprintf("candidate-%d", i), nil)
				}
				lifecycleValue(t, txn, "accepted", []byte("yes"))
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
