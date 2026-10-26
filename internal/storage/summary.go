package storage

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/pasichDev/noso-go/internal/types"
)

// SummaryStore is a thread-safe wrapper around `sumary.psk` providing:
//
//   - hash-indexed O(1) lookups (`Get(hash)`, `GetByAlias(alias)`),
//   - bulk read (`All()`, `Len()`),
//   - bulk and per-record writes (`Save`, `Set`),
//   - balance helpers (`Balance(hash)`, `Total()`),
//   - atomic persist (`Flush()`).
//
// Compared to the Pascal node it adds explicit locking and atomic writes;
// the on-disk format is the same 106-byte packed record sequence.
type SummaryStore struct {
	path  string
	mu    sync.RWMutex
	recs  []types.SummaryRecord
	byHsh map[string]int // hash → index in recs
	byAls map[string]int // custom (alias) → index in recs
}

// NewSummaryStore loads sumary.psk at path. A missing file is treated as
// an empty store (Pascal initializes a fresh sumary.psk on first run).
func NewSummaryStore(path string) (*SummaryStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &SummaryStore{
				path:  path,
				byHsh: map[string]int{},
				byAls: map[string]int{},
			}, nil
		}
		return nil, err
	}
	count, err := recordCount("sumary.psk", data, types.SummaryRecordSize)
	if err != nil {
		return nil, err
	}
	s := &SummaryStore{
		path:  path,
		recs:  make([]types.SummaryRecord, count),
		byHsh: make(map[string]int, count),
		byAls: make(map[string]int, count),
	}
	for i := 0; i < count; i++ {
		if !s.recs[i].Unmarshal(data[i*types.SummaryRecordSize : (i+1)*types.SummaryRecordSize]) {
			return nil, fmt.Errorf("storage: sumary.psk record %d unmarshal failed", i)
		}
		s.byHsh[s.recs[i].Hash] = i
		if s.recs[i].Custom != "" {
			s.byAls[s.recs[i].Custom] = i
		}
	}
	return s, nil
}

// Len returns the number of records.
func (s *SummaryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.recs)
}

// All returns a copy of every record.
func (s *SummaryStore) All() []types.SummaryRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.SummaryRecord, len(s.recs))
	copy(out, s.recs)
	return out
}

// Get returns the record for the given address hash, or false if absent.
func (s *SummaryStore) Get(hash string) (types.SummaryRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.byHsh[hash]
	if !ok {
		return types.SummaryRecord{}, false
	}
	return s.recs[idx], true
}

// GetByAlias returns the record whose Custom field equals alias.
func (s *SummaryStore) GetByAlias(alias string) (types.SummaryRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.byAls[alias]
	if !ok {
		return types.SummaryRecord{}, false
	}
	return s.recs[idx], true
}

// Balance returns the confirmed balance for hash (0 if unknown).
func (s *SummaryStore) Balance(hash string) int64 {
	rec, ok := s.Get(hash)
	if !ok {
		return 0
	}
	return rec.Balance
}

// Total returns the sum of all balances (circulating supply at this height).
func (s *SummaryStore) Total() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var total int64
	for i := range s.recs {
		total += s.recs[i].Balance
	}
	return total
}

// Set inserts or replaces a record in memory. The on-disk file is NOT
// updated until Flush() is called — this matches Pascal's batched
// `UpdateSummaryChanges` semantics.
func (s *SummaryStore) Set(rec types.SummaryRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx, ok := s.byHsh[rec.Hash]; ok {
		// Update existing index entries.
		old := s.recs[idx]
		if old.Custom != "" && old.Custom != rec.Custom {
			delete(s.byAls, old.Custom)
		}
		s.recs[idx] = rec
		if rec.Custom != "" {
			s.byAls[rec.Custom] = idx
		}
		return
	}
	idx := len(s.recs)
	s.recs = append(s.recs, rec)
	s.byHsh[rec.Hash] = idx
	if rec.Custom != "" {
		s.byAls[rec.Custom] = idx
	}
}

// Flush writes the current in-memory state to disk atomically.
func (s *SummaryStore) Flush() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	buf := make([]byte, 0, len(s.recs)*types.SummaryRecordSize)
	for i := range s.recs {
		buf = append(buf, s.recs[i].Marshal()...)
	}
	return atomicWriteFile(s.path, buf)
}
