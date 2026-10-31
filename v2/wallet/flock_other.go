//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !windows

package wallet

import (
	"errors"
	"os"
)

// No file locking exists for this platform, so refuse to open a store rather
// than run without the interlock that keeps one nonce context from being
// used twice.
func lockFile(string) (*os.File, error) {
	return nil, errors.New("wallet: this platform has no file locking; the wallet store is not supported here")
}
func unlockFile(*os.File) {}
