package types

import (
	"crypto/sha256"
	"encoding/binary"
)

// CompactFilter is a per-block bloom-style filter over output commitments.
// A light wallet downloads only
// the filter; if it matches one of the wallet's "watch" entries the
// wallet fetches the full block to extract its outputs.
//
// This is a simple 256-bit Bloom filter with four salted hash positions,
// not a BIP-158 Golomb-coded set. Saturation is substantial at 100 elements
// (approximately 39% false positives under the usual ideal-hash model).
// It is an experimental hint, not authenticated light-client verification.
type CompactFilter struct {
	Height uint64
	Bits   [32]byte // 256 bits
}

// AddBytes adds a single watch-item (commit bytes) to the filter.
func (f *CompactFilter) AddBytes(elem []byte) {
	for k := 0; k < 4; k++ {
		idx := filterHash(elem, k) % 256
		f.Bits[idx/8] |= 1 << (idx % 8)
	}
}

// MatchBytes reports whether elem might be in the filter. False
// positives are possible; false negatives are not.
func (f *CompactFilter) MatchBytes(elem []byte) bool {
	for k := 0; k < 4; k++ {
		idx := filterHash(elem, k) % 256
		if f.Bits[idx/8]&(1<<(idx%8)) == 0 {
			return false
		}
	}
	return true
}

// BuildFilter constructs a filter from a block, including every output
// commit (33 bytes).
func BuildFilter(b *Block) CompactFilter {
	f := CompactFilter{Height: b.Header.Height}
	for i := range b.Outputs {
		o := &b.Outputs[i]
		f.AddBytes(o.Commit[:])
	}
	return f
}

// filterHash hashes `elem` with the salt index `k` to a 32-bit index.
func filterHash(elem []byte, k int) uint32 {
	h := sha256.New()
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(k))
	h.Write(b[:])
	h.Write(elem)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum[:4])
}
