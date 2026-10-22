//go:build unix

package collector

import (
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
