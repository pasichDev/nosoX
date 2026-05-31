// Package codec implements the binary record format Pascal uses on disk and
// the Noso node writes byte-for-byte. The key building blocks are:
//
//   - Pascal "ShortString[N]": one length byte followed by N capacity bytes
//     of ASCII data, zero-padded after the actual content. Total on-disk
//     size is N+1 bytes regardless of the actual string length.
//   - Little-endian fixed-width integers (int32, int64), matching x86 Pascal.
//   - "Packed Record" semantics: no field alignment, no padding.
//
// This package is the only place that should know about Pascal's encoding
// quirks. Higher layers consume Reader/Writer methods that return Go strings
// and ints.
package codec

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ShortStringSize returns the on-disk size of a Pascal `String[capacity]`
// field: one length byte plus the declared capacity.
func ShortStringSize(capacity int) int { return capacity + 1 }

// EncodeShortString writes a Pascal ShortString into dst[0:capacity+1].
// dst must be at least capacity+1 bytes long. The function panics on a
// short buffer because that's a programming error, not a runtime condition.
//
// Behavior matches Pascal: if len(s) > capacity, the value is truncated
// silently to capacity bytes (same as Pascal's implicit truncation when
// assigning a longer string into a String[N] field). Trailing capacity
// bytes after the content are zero-padded.
func EncodeShortString(dst []byte, s string, capacity int) {
	if len(dst) < capacity+1 {
		panic(fmt.Sprintf("codec.EncodeShortString: dst too small (%d, want %d)", len(dst), capacity+1))
	}
	n := len(s)
	if n > capacity {
		n = capacity
	}
	dst[0] = byte(n)
	copy(dst[1:1+n], s[:n])
	for i := 1 + n; i <= capacity; i++ {
		dst[i] = 0
	}
}

// DecodeShortString reads a Pascal ShortString from src[0:capacity+1].
// Returns the empty string (not an error) if src is shorter than the
// declared length byte — Pascal nodes treat that as a malformed record,
// but for forward-compatible reads we mirror that and let the caller
// validate the surrounding record.
func DecodeShortString(src []byte, capacity int) string {
	if len(src) < 1 {
		return ""
	}
	n := int(src[0])
	if n > capacity {
		n = capacity
	}
	if 1+n > len(src) {
		n = len(src) - 1
	}
	if n < 0 {
		return ""
	}
	return string(src[1 : 1+n])
}

// ReadShortString reads a Pascal ShortString of the given capacity from r.
// Always consumes capacity+1 bytes (or returns the underlying error).
func ReadShortString(r io.Reader, capacity int) (string, error) {
	buf := make([]byte, capacity+1)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return DecodeShortString(buf, capacity), nil
}

// WriteShortString writes a Pascal ShortString of the given capacity to w.
// Always emits capacity+1 bytes.
func WriteShortString(w io.Writer, s string, capacity int) error {
	buf := make([]byte, capacity+1)
	EncodeShortString(buf, s, capacity)
	_, err := w.Write(buf)
	return err
}

// PutInt32 / PutInt64 / GetInt32 / GetInt64 are thin little-endian helpers
// used by record marshalers. They exist so the binary order is documented
// in one place rather than scattered across every struct.

func PutInt32(dst []byte, v int32) { binary.LittleEndian.PutUint32(dst, uint32(v)) }
func PutInt64(dst []byte, v int64) { binary.LittleEndian.PutUint64(dst, uint64(v)) }
func GetInt32(src []byte) int32    { return int32(binary.LittleEndian.Uint32(src)) }
func GetInt64(src []byte) int64    { return int64(binary.LittleEndian.Uint64(src)) }

// ReadInt32 / ReadInt64 / WriteInt32 / WriteInt64 stream variants.

func ReadInt32(r io.Reader) (int32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return GetInt32(buf[:]), nil
}

func ReadInt64(r io.Reader) (int64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return GetInt64(buf[:]), nil
}

func WriteInt32(w io.Writer, v int32) error {
	var buf [4]byte
	PutInt32(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}

func WriteInt64(w io.Writer, v int64) error {
	var buf [8]byte
	PutInt64(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}
