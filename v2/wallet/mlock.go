package wallet

// Memory protection for decrypted wallet secrets.
//
// Two responsibilities:
//
//  1. mlock the seed slice so the kernel can't swap it to disk.
//  2. Zeroize it before release.
//
// On Linux/Darwin we call mlock via syscall. On Windows the syscall
// is different (VirtualLock); we expose the same interface and let
// the platform-specific file (mlock_windows.go / mlock_unix.go) wire
// the actual primitive.
//
// Failures from mlock are returned by LockBytes; Load treats them as best effort. A wallet can
// still function even on a host where mlock isn't permitted (e.g. a
// container without IPC_LOCK). Zeroization always works.

// LockBytes attempts to mlock b. Returns the underlying error if the
// syscall fails. Callers should call UnlockBytes to release the lock
// (typically deferred).
func LockBytes(b []byte) error { return platformLock(b) }

// UnlockBytes munlocks b. Safe to call on a slice that was never
// locked (errors are swallowed by the platform layer).
func UnlockBytes(b []byte) { _ = platformUnlock(b) }

// Zeroize overwrites b with zeros. Useful immediately before the
// slice's underlying memory is released back to the allocator.
//
// Note: due to Go's GC behavior there is no absolute guarantee that
// b's backing array is the only copy in memory, but combined with
// the mlock above and the Encrypted-at-rest design this still
// raises the bar significantly against trivial recovery.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Close zeroizes and unlocks the mutable master key. Idempotent.
func (w *Wallet) Close() {
	if w == nil {
		return
	}
	if w.Master != nil {
		Zeroize(w.Master)
		UnlockBytes(w.Master)
		w.Master = nil
	}
	w.Plain = plainView{}
}
