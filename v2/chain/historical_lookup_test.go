package chain

import (
	"testing"

	"github.com/pasichDev/noso-go/v2/types"
)

// A transient persistent-store read error must not make an already-seen
// output/kernel appear reusable to consensus validation.
func TestBadgerHistoricalIdentityLookupFailsClosed(t *testing.T) {
	store, err := OpenBadger(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	var output types.Commitment
	output[0] = 2
	var kernel types.Hash
	kernel[0] = 3

	if store.HasOutput(output) || store.HasKernel(kernel) {
		t.Fatal("missing history identities must be absent in an open database")
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if !store.HasOutput(output) {
		t.Error("closed database must reject output uniqueness checks")
	}
	if !store.HasKernel(kernel) {
		t.Error("closed database must reject kernel uniqueness checks")
	}
}

func TestBadgerMalformedHeightIndexFailsClosed(t *testing.T) {
	store, err := OpenBadger(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var hash types.Hash
	hash[0] = 5
	key := append([]byte{kHash}, hash[:]...)
	if err := store.mutate(func(txn *stageTxn) error {
		return txn.Set(key, []byte{42}) // invalid: heights must be exactly 8 bytes
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.HeightOf(hash); ok {
		t.Fatal("corrupted hash index must not resolve to a valid height")
	}
}
