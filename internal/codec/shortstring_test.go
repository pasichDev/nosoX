package codec

import (
	"bytes"
	"testing"
)

func TestShortStringRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		capacity int
		value    string
	}{
		{"empty", 40, ""},
		{"short", 40, "hello"},
		{"exact", 32, "abcdefghijklmnopqrstuvwxyz012345"}, // 32 chars
		{"truncate", 6, "TOOLONG_TRUNCATED"},
		{"address-typical", 40, "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, tc.capacity+1)
			EncodeShortString(buf, tc.value, tc.capacity)
			got := DecodeShortString(buf, tc.capacity)
			want := tc.value
			if len(want) > tc.capacity {
				want = want[:tc.capacity]
			}
			if got != want {
				t.Fatalf("decode mismatch: got %q, want %q", got, want)
			}
			// First byte must be the actual length on disk.
			if int(buf[0]) != len(want) {
				t.Fatalf("length byte = %d, want %d", buf[0], len(want))
			}
			// Capacity must be respected on disk.
			if len(buf) != tc.capacity+1 {
				t.Fatalf("on-disk size = %d, want %d", len(buf), tc.capacity+1)
			}
		})
	}
}

func TestShortStringZeroPadding(t *testing.T) {
	buf := make([]byte, 41)
	for i := range buf {
		buf[i] = 0xAA // pre-fill so we can detect missing zero-pad
	}
	EncodeShortString(buf, "abc", 40)
	if buf[0] != 3 || string(buf[1:4]) != "abc" {
		t.Fatalf("header/content wrong: % x", buf[:4])
	}
	for i := 4; i < 41; i++ {
		if buf[i] != 0 {
			t.Fatalf("byte %d = 0x%02x, want 0x00 (zero-pad)", i, buf[i])
		}
	}
}

func TestReadWriteShortString(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteShortString(&buf, "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd", 40); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 41 {
		t.Fatalf("wrote %d bytes, want 41", buf.Len())
	}
	got, err := ReadShortString(&buf, 40)
	if err != nil {
		t.Fatal(err)
	}
	if got != "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd" {
		t.Fatalf("got %q", got)
	}
}

func TestIntsLittleEndian(t *testing.T) {
	var buf [8]byte
	PutInt64(buf[:], 0x0102030405060708)
	want := [8]byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	if buf != want {
		t.Fatalf("int64 little-endian wrong: % x", buf)
	}
	if got := GetInt64(buf[:]); got != 0x0102030405060708 {
		t.Fatalf("round-trip int64: %x", got)
	}
}
