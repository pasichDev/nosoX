package wallet

import (
	"os"
	"testing"
)

// testPass satisfies the passphrase policy.
const testPass = "correct horse battery"

// TestMain runs the package with cheap key derivation and a shallow
// confirmation depth. Production defaults are exercised by dedicated tests that
// restore them (see TestProductionDefaultsAreStrong).
// Production values, captured before TestMain lowers them.
var (
	prodDefaultMinConfirmations = defaultMinConfirmations
	prodKDFFloor                = kdfFloor
	prodKDFDefault              = kdfDefault
)

func TestMain(m *testing.M) {
	kdfDefault = KDFParams{T: 1, MemKiB: 64, P: 1}
	kdfFloor = KDFParams{T: 1, MemKiB: 8, P: 1}
	defaultMinConfirmations = 1
	os.Exit(m.Run())
}
