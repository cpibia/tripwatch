//go:build !linux

package collector

import (
	"os"
	"path/filepath"
	"syscall"
)

// openInRoot opens name relative to dir without blocking. Symlinks are not confined to dir
// here: confinement relies on openat2, and the sensor only ships for Linux.
func openInRoot(dir, name string) (*os.File, error) {
	full := filepath.Join(dir, filepath.FromSlash(name))
	fd, err := syscall.Open(full, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: full, Err: err}
	}
	return os.NewFile(uintptr(fd), full), nil
}
