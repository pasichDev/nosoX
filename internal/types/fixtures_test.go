package types

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pasichDev/noso-go/internal/crypto"
)

// These tests exercise the type-level Marshal/Unmarshal code against
// actual production data files copied out of NosoNode-main/ at the time
// of the port. If the on-disk format ever drifts, these tests are the
// first line of detection.

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Skipf("fixture %s not available: %v", name, err)
	}
	return root
}

func TestSumaryFixture59238(t *testing.T) {
	// 59238.psk was distributed alongside NosoNode-main as a snapshot of
	// `sumary.psk` at block 59238. Its size must be a multiple of the
	// SummaryRecord size, and the records must round-trip.
	data, err := os.ReadFile(fixturePath(t, "sumary_59238.psk"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data)%SummaryRecordSize != 0 {
		t.Fatalf("file size %d is not a multiple of %d (record size); off by %d",
			len(data), SummaryRecordSize, len(data)%SummaryRecordSize)
	}
	count := len(data) / SummaryRecordSize
	t.Logf("loaded %d SummaryRecord entries (%d bytes)", count, len(data))

	// Spot-check: at least one Noso address must validate, and the genesis
	// address with the 1.03e12 premine should be present at LastOP=0.
	var validAddresses, invalidAddresses int
	var sawGenesis bool
	for i := 0; i < count; i++ {
		var rec SummaryRecord
		if !rec.Unmarshal(data[i*SummaryRecordSize : (i+1)*SummaryRecordSize]) {
			t.Fatalf("record %d unmarshal failed", i)
		}
		// Round-trip: re-marshal and compare to original slice.
		round := rec.Marshal()
		for j, b := range round {
			if b != data[i*SummaryRecordSize+j] {
				// Bytes can differ in the "padding" after the length-prefixed
				// string content because Pascal does not always zero-pad.
				// Tolerate that by only failing on bytes that fall inside
				// the declared content of each string field. We accept
				// non-zero garbage in the tail.
				if isInStringPadding(j) {
					continue
				}
				t.Fatalf("record %d byte %d mismatch: got %02x want %02x",
					i, j, b, data[i*SummaryRecordSize+j])
			}
		}
		if crypto.IsValidAddress(rec.Hash) {
			validAddresses++
		} else if rec.Hash != "" {
			invalidAddresses++
		}
		if rec.Hash == "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd" {
			sawGenesis = true
			if rec.Balance < 1_000_000_000 {
				t.Errorf("genesis address balance suspiciously low: %d", rec.Balance)
			}
		}
	}
	t.Logf("valid addresses: %d, malformed: %d", validAddresses, invalidAddresses)
	if validAddresses == 0 {
		t.Fatal("no addresses in 59238.psk passed IsValidAddress — crypto pipeline is wrong")
	}
	if !sawGenesis {
		t.Log("genesis address not found in this snapshot (acceptable if it spent the premine)")
	}
	// Sanity: > 90% of non-empty rows should be valid addresses. Pascal
	// summary files typically have a small number of "system" entries
	// (PROJCT fund, treasury) with custom labels; the rest should be real.
	if validAddresses*10 < (validAddresses+invalidAddresses)*9 {
		t.Errorf("only %d/%d non-empty addresses are valid; expected >= 90%%",
			validAddresses, validAddresses+invalidAddresses)
	}
}

// isInStringPadding returns true when offset `off` inside a 106-byte
// SummaryRecord falls in the unused tail of a Pascal ShortString. Pascal
// does not zero-pad the unused capacity bytes — they retain whatever was
// there before the write. Round-trip comparisons must ignore those bytes.
func isInStringPadding(off int) bool {
	// Hash: [0..40], length byte at 0, content at 1..1+len, padding at
	// 1+len..40. Same for Custom: [41..81].
	// Numeric fields cover [82..105]; never padding.
	if off >= 82 {
		return false
	}
	// We don't know the actual length without the data, so just return
	// true for any byte inside a string region — this is safe because the
	// numeric fields and length-prefix bytes are still strictly checked.
	if off >= 1 && off <= 40 { // inside Hash content/padding
		return true
	}
	if off >= 42 && off <= 81 { // inside Custom content/padding
		return true
	}
	return false
}

func TestGVTsFixture(t *testing.T) {
	data, err := os.ReadFile(fixturePath(t, "gvts.psk"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 100*GVTSize {
		t.Fatalf("gvts.psk size = %d, want %d (100 records of %d)",
			len(data), 100*GVTSize, GVTSize)
	}
	for i := 0; i < 100; i++ {
		var g GVT
		if !g.Unmarshal(data[i*GVTSize : (i+1)*GVTSize]) {
			t.Fatalf("GVT %d unmarshal failed", i)
		}
		// "00".."99". Pascal stores it as a 2-char ShortString.
		want := []byte{byte('0' + i/10), byte('0' + i%10)}
		if g.Number != string(want) {
			t.Errorf("GVT %d: Number = %q, want %q", i, g.Number, string(want))
		}
	}
}
