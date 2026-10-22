//go:build unix

package collector

import (
	"fmt"
	"io/fs"
	"syscall"
)

func owner(info fs.FileInfo) (uid, gid *uint32) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil
	}
	u, g := st.Uid, st.Gid
	return &u, &g
}

// Inode returns the inode number, used to recognise a log file that was rotated.
func Inode(info fs.FileInfo) (uint64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Ino), true //nolint:unconvert // Ino is not uint64 on every platform
}

// FileID returns the device and inode identifying the file behind info.
func FileID(info fs.FileInfo) (string, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino), true
}

// Owner returns the user that owns the file.
func Owner(info fs.FileInfo) (uint32, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// Allocated returns the bytes actually allocated on disk for the file, smaller than its size
// when the file is sparse.
func Allocated(info fs.FileInfo) (int64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Blocks * 512, true
}
