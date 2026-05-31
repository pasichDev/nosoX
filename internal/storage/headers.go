package storage

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/noso-project/noso-go/internal/types"
)

// HeadersStore wraps `blchhead.nos`, the append-only block-fingerprint log.
type HeadersStore struct {
	path string
	mu   sync.RWMutex
	recs []types.ResumenData
}

// NewHeadersStore loads existing headers from disk.
func NewHeadersStore(path string) (*HeadersStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &HeadersStore{path: path}, nil
		}
		return nil, err
	}
	count, err := recordCount("blchhead.nos", data, types.ResumenDataSize)
	if err != nil {
		return nil, err
	}
	h := &HeadersStore{path: path, recs: make([]types.ResumenData, count)}
	for i := 0; i < count; i++ {
		if !h.recs[i].Unmarshal(data[i*types.ResumenDataSize : (i+1)*types.ResumenDataSize]) {
			return nil, fmt.Errorf("storage: blchhead.nos record %d unmarshal failed", i)
		}
	}
	return h, nil
}

// Len returns how many block headers are stored.
func (h *HeadersStore) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.recs)
}

// All returns a copy of every record.
func (h *HeadersStore) All() []types.ResumenData {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]types.ResumenData, len(h.recs))
	copy(out, h.recs)
	return out
}

// Tip returns the highest-numbered header, or zero-value + false if empty.
func (h *HeadersStore) Tip() (types.ResumenData, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(h.recs) == 0 {
		return types.ResumenData{}, false
	}
	return h.recs[len(h.recs)-1], true
}

// Get returns the header for the given block, or false if absent. Pascal
// stores headers sequentially starting from block 0, but skipped or
// reorganized chains may have gaps — we do a linear scan to be safe.
// For typical archive sizes (< 100k blocks) this is fast enough; an
// optional in-memory index can be added if needed.
func (h *HeadersStore) Get(block int32) (types.ResumenData, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for i := range h.recs {
		if h.recs[i].Block == block {
			return h.recs[i], true
		}
	}
	return types.ResumenData{}, false
}

// Append adds a new header record and persists the change.
func (h *HeadersStore) Append(rec types.ResumenData) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = append(h.recs, rec)
	return h.flushLocked()
}

func (h *HeadersStore) flushLocked() error {
	buf := make([]byte, 0, len(h.recs)*types.ResumenDataSize)
	for i := range h.recs {
		buf = append(buf, h.recs[i].Marshal()...)
	}
	return atomicWriteFile(h.path, buf)
}
