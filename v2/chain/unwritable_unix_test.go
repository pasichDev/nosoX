//go:build !windows

package chain

import (
	"os"
	"testing"
)

// makeUnwritable removes write permission from dir for the test's duration. The
// badger files are already open, so only new files (the marker temp) fail.
func makeUnwritable(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}
