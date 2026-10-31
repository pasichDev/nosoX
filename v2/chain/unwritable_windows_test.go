//go:build windows

package chain

import "testing"

func makeUnwritable(t *testing.T, _ string) {
	t.Helper()
	t.Skip("directory permissions are not Unix mode bits on Windows")
}
