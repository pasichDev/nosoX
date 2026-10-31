//go:build linux || darwin || freebsd || netbsd || openbsd
// +build linux darwin freebsd netbsd openbsd

package wallet

import (
	"errors"
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock so that two wallet processes never
// interleave read-modify-write cycles on the same state file (which could
// otherwise select one output twice or reuse a nonce context).
func lockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("wallet: state is locked by another process")
		}
		return nil, err
	}
	return f, nil
}

func unlockFile(f *os.File) {
	if f != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}
}
