//go:build linux

package collector

import (
	"io/fs"
	"syscall"
)

// ChangeTime returns the inode change time. Unlike the modification time, an unprivileged user
// cannot set it back.
func ChangeTime(info fs.FileInfo) (int64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Ctim.Nano(), true
}
