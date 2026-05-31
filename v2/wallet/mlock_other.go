//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd
// +build !linux,!darwin,!freebsd,!netbsd,!openbsd

package wallet

// No-op fallback for platforms without an mlock syscall available.
// Zeroize still works; we just can't pin pages out of swap.

func platformLock(_ []byte) error   { return nil }
func platformUnlock(_ []byte) error { return nil }
