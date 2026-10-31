//go:build windows

package wallet

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// lockFile takes an exclusive LockFileEx lock on the first byte of path, held
// until unlockFile (or process exit). Same contract as the Unix flock version.
var (
	modkernel32      = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = modkernel32.NewProc("LockFileEx")
	procUnlockFileEx = modkernel32.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 0x1
	lockfileExclusive       = 0x2
	errorLockViolation      = syscall.Errno(33)
)

func lockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var ol syscall.Overlapped
	r, _, e := procLockFileEx.Call(f.Fd(), lockfileExclusive|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r == 0 {
		f.Close()
		if errors.Is(e, errorLockViolation) {
			return nil, errors.New("wallet: state is locked by another process")
		}
		return nil, e
	}
	return f, nil
}

func unlockFile(f *os.File) {
	if f != nil {
		var ol syscall.Overlapped
		_, _, _ = procUnlockFileEx.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
		_ = f.Close()
	}
}
