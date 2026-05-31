package storage

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/noso-project/noso-go/internal/types"
)

// Block is the in-memory representation of one .blk file: its header plus
// the transactions Pascal records after it. PoS and MN sections appended
// after block 8425 / 48010 are exposed as raw bytes for now; full parsing
// is task-future work.
type Block struct {
	Header BlockHeaderOrEmpty
	Orders []types.Order
	Trail  []byte // optional trailing bytes (PoS + MN data, not yet typed)
}

// BlockHeaderOrEmpty is an aliasing shim that lets nilable-style logic
// stay readable: a zero header has Number == 0 AND len(Solution) == 0.
type BlockHeaderOrEmpty = types.BlockHeader

// ReadBlockFile parses a single .blk file. It validates internal sizes and
// returns a structured Block. The Trail field captures bytes that come
// after `TrxTotales` order records — PoS and MN section parsing is TBD
// and will be filled in once the block-file layout for the post-48010
// range is verified against sample data.
func ReadBlockFile(path string) (*Block, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readBlock(f)
}

func readBlock(r io.Reader) (*Block, error) {
	hdrBuf := make([]byte, types.BlockHeaderSize)
	if _, err := io.ReadFull(r, hdrBuf); err != nil {
		return nil, fmt.Errorf("storage: read block header: %w", err)
	}
	b := &Block{}
	if !b.Header.Unmarshal(hdrBuf) {
		return nil, errors.New("storage: block header unmarshal failed")
	}
	n := int(b.Header.TrxTotales)
	if n < 0 || n > 100_000 { // hard sanity cap, Pascal limit is 2000
		return nil, fmt.Errorf("storage: implausible TrxTotales=%d", n)
	}
	b.Orders = make([]types.Order, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, types.OrderSize)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("storage: read order %d/%d: %w", i, n, err)
		}
		if !b.Orders[i].Unmarshal(buf) {
			return nil, fmt.Errorf("storage: order %d unmarshal failed", i)
		}
	}
	// Read any trailing bytes verbatim — PoS / MN sections.
	trail, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("storage: read trailing block data: %w", err)
	}
	b.Trail = trail
	return b, nil
}

// ReadBlock loads block N from layout.BlocksDir.
func (l *Layout) ReadBlock(number int64) (*Block, error) {
	return ReadBlockFile(l.BlockPath(number))
}

// WriteBlockFile serializes b and writes it atomically. The output bytes
// match what `BuildNewBlock` in `mpblock.pas` would produce, including any
// preserved trail section.
func WriteBlockFile(path string, b *Block) error {
	// We don't trust the caller's TrxTotales — fix it to match Orders.
	b.Header.TrxTotales = int32(len(b.Orders))
	buf := make([]byte, 0, types.BlockHeaderSize+len(b.Orders)*types.OrderSize+len(b.Trail))
	buf = append(buf, b.Header.Marshal()...)
	for i := range b.Orders {
		buf = append(buf, b.Orders[i].Marshal()...)
	}
	buf = append(buf, b.Trail...)
	return atomicWriteFile(path, buf)
}

// WriteBlock writes block b under its conventional name in layout.BlocksDir.
func (l *Layout) WriteBlock(b *Block) error {
	return WriteBlockFile(l.BlockPath(b.Header.Number), b)
}
