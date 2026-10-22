//go:build unix

package pki

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// checkPrivate refuses a file other users can read or write, or that belongs to someone else.
func checkPrivate(info fs.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("readable or writable by other users (mode %s): chmod 600 it", perm)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("owned by uid %d, not by the user running the sensor (%d)", st.Uid, os.Geteuid())
	}
	return nil
}
