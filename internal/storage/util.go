package storage

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// formatInt64 returns the decimal representation of n, matching Pascal's
// `IntToStr`. Extracted to a helper so we can change format in one place
// if a future revision uses zero-padded names.
func formatInt64(n int64) string { return strconv.FormatInt(n, 10) }

// atomicWriteFile writes data to dst atomically: write to a tmp file in
// the same directory, fsync it, then rename it over dst. This is an
// IMPROVEMENT over the Pascal node, which writes in place and risks
// corruption on crash. The file CONTENTS are identical, so a Pascal node
// reading the result is unaffected.
//
// The function uses 0o644 permissions and overwrites dst if it exists.
func atomicWriteFile(dst string, data []byte) (retErr error) {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".tmp-*.swap")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if retErr != nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return err
	}
	// fsync the directory so the rename is durable.
	d, err := os.Open(dir)
	if err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// readAllFile is os.ReadFile with a clearer error wrap.
func readAllFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("storage: read %s: %w", path, err)
	}
	return data, nil
}

// recordCount returns len(data)/size and an error if data is not an exact
// multiple of size — signaling on-disk corruption.
func recordCount(name string, data []byte, size int) (int, error) {
	if len(data)%size != 0 {
		return 0, fmt.Errorf("storage: %s size %d is not a multiple of record size %d (off by %d)",
			name, len(data), size, len(data)%size)
	}
	return len(data) / size, nil
}

// errAtEOF lets callers tell "no more records" apart from real I/O errors.
var errAtEOF = io.EOF

// safeReadAt reads exactly n bytes from r at the given offset. Returns
// errAtEOF if the file ended mid-record.
func safeReadAt(r io.ReaderAt, off int64, n int) ([]byte, error) {
	buf := make([]byte, n)
	got, err := r.ReadAt(buf, off)
	if err == io.EOF && got == 0 {
		return nil, errAtEOF
	}
	if err != nil && err != io.EOF {
		return nil, err
	}
	if got < n {
		return nil, errors.New("storage: short record read")
	}
	return buf, nil
}
