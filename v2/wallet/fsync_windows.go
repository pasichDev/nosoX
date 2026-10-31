//go:build windows

package wallet

import (
	"syscall"
	"unsafe"
)

// Windows cannot fsync a directory: opening one read-only and calling Sync
// ends in FlushFileBuffers without write access, which fails with "access
// denied". Durability of the rename comes from MoveFileEx with
// MOVEFILE_WRITE_THROUGH instead, and syncDir is a no-op.

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

var procMoveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func replaceFile(tmp, path string) error {
	from, err := syscall.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r, _, e := procMoveFileExW.Call(uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), moveFileReplaceExisting|moveFileWriteThrough)
	if r == 0 {
		return &linkError{op: "rename", old: tmp, new: path, err: e}
	}
	return nil
}

func syncDir(string) error { return nil }

type linkError struct {
	op, old, new string
	err          error
}

func (e *linkError) Error() string { return e.op + " " + e.old + " " + e.new + ": " + e.err.Error() }
func (e *linkError) Unwrap() error { return e.err }
