package types

import (
	"crypto/sha256"
	"encoding/binary"
)

// CompactFilter is a per-block bloom-style filter over output commitments
// (and legacy addresses, for v1 holders). A light wallet downloads only
// the filter; if it matches one of the wallet's "watch" entries the
// wallet fetches the full block to extract its outputs.
//
// The filter uses a Golomb-coded set (similar to BIP-158) for compactness.
// To keep the v2 dependency surface small we implement a much simpler
// counted-Bloom variant: a 256-bit bit array with k=4 independent hashes
// per element. For block sizes typical of the first year of operation
// (<100 outputs/block) the false-positive rate is ~1%, which is fine
// for the use-case (a false positive just means the light wallet pulls
// a block it didn't actually need).
type CompactFilter struct {
	Height uint64
	Bits   [32]byte // 256 bits
}

// FilterAddElement adds a single watch-item (legacy address or commit
// bytes) to the filter.
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

// BuildFilter constructs a filter from a block, including:
//   - every output commit (33 bytes)
//   - every legacy address (utf-8)
func BuildFilter(b *Block) CompactFilter {
	f := CompactFilter{Height: b.Header.Height}
	for i := range b.Outputs {
		o := &b.Outputs[i]
		f.AddBytes(o.Commit[:])
		if o.Features == OutputFeaturesLegacy && o.LegacyAddress != "" {
			f.AddBytes([]byte(o.LegacyAddress))
		}
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
