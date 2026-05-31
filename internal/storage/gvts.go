package storage

import (
	"errors"
	"fmt"
	"os"

	"github.com/noso-project/noso-go/internal/types"
)

// LoadGVTs reads all 100 GVT records from `gvts.psk`. Returns an error if
// the file is the wrong size — Pascal always writes exactly 100 records.
func LoadGVTs(path string) ([]types.GVT, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	count, err := recordCount("gvts.psk", data, types.GVTSize)
	if err != nil {
		return nil, err
	}
	out := make([]types.GVT, count)
	for i := 0; i < count; i++ {
		if !out[i].Unmarshal(data[i*types.GVTSize : (i+1)*types.GVTSize]) {
			return nil, fmt.Errorf("storage: gvts.psk record %d unmarshal failed", i)
		}
	}
	return out, nil
}

// SaveGVTs writes GVT records to disk atomically.
func SaveGVTs(path string, recs []types.GVT) error {
	buf := make([]byte, 0, len(recs)*types.GVTSize)
	for i := range recs {
		buf = append(buf, recs[i].Marshal()...)
	}
	return atomicWriteFile(path, buf)
}
