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
