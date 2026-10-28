//go:build !linux

package collector

import (
	"os"
	"path/filepath"
	"syscall"
)

// Outside Linux, where the sensor is not deployed, symlinks are not confined to the observed
// root; files are still checked before and after opening so that FIFOs and devices are never
// read.

func releaseRoot(string) {}

// Warnings has nothing to report outside Linux.
func Warnings() []string { return nil }

func statIn(dir, name string) (os.FileInfo, error) {
	return os.Stat(filepath.Join(dir, filepath.FromSlash(name)))
}

func openIn(dir, name string) (*os.File, os.FileInfo, error) {
	full := filepath.Join(dir, filepath.FromSlash(name))
	info, err := os.Stat(full)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return nil, info, ErrNotRegular
	}
	fd, err := syscall.Open(full, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, &os.PathError{Op: "open", Path: full, Err: err}
	}
	f := os.NewFile(uintptr(fd), full)
	if info, err = f.Stat(); err != nil || (!info.Mode().IsRegular() && !info.IsDir()) {
		_ = f.Close()
		return nil, info, ErrNotRegular
	}
	return f, info, nil
}

func lstatIn(dir, name string) (os.FileInfo, error) {
	return os.Lstat(filepath.Join(dir, filepath.FromSlash(name)))
}

func readlinkIn(dir, name string) (string, error) {
	return os.Readlink(filepath.Join(dir, filepath.FromSlash(name)))
}

func attrsIn(dir, name string) (Attrs, error) {
	return ReadAttrs(filepath.Join(dir, filepath.FromSlash(name)))
}
