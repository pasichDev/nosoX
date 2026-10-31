//go:build !windows

package wallet

import (
	"os"
	"path/filepath"
)

// replaceFile atomically renames tmp over path.
func replaceFile(tmp, path string) error { return os.Rename(tmp, path) }

// syncDir makes a completed rename durable by syncing the directory.
func syncDir(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
