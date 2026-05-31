//go:build linux || darwin || freebsd || netbsd || openbsd
// +build linux darwin freebsd netbsd openbsd

package wallet

import "syscall"

func platformLock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return syscall.Mlock(b)
}

func platformUnlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return syscall.Munlock(b)
}
