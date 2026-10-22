//go:build linux

package collector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// openat2 and its resolve flags from linux/openat2.h; the syscall number is the same on
// amd64 and arm64.
const (
	sysOpenat2    = 437
	resolveInRoot = 0x10
)

type openHow struct {
	flags   uint64
	mode    uint64
	resolve uint64
}

const openFlags = syscall.O_RDONLY | syscall.O_NONBLOCK | syscall.O_CLOEXEC | syscall.O_NOCTTY

var (
	rootFDs   sync.Map // dir -> int
	noOpenat2 bool
)

// openInRoot opens name relative to dir. When dir is not "/", symlinks are resolved with
// RESOLVE_IN_ROOT, so an absolute link on the observed host points inside dir, as it does for
// the host itself, instead of into the sensor's own container. /proc is opened normally: its
// magic links (/proc/<pid>/exe) are what the process collector needs, and RESOLVE_IN_ROOT
// refuses them.
func openInRoot(dir, name string) (*os.File, error) {
	full := filepath.Join(dir, filepath.FromSlash(name))
	if dir == "/" || name == "proc" || strings.HasPrefix(name, "proc/") || noOpenat2 {
		return openPlain(full)
	}

	rootFD, err := rootDescriptor(dir)
	if err != nil {
		return nil, err
	}
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	how := openHow{flags: openFlags, resolve: resolveInRoot}
	fd, _, errno := syscall.Syscall6(sysOpenat2, uintptr(rootFD), uintptr(unsafe.Pointer(p)), //nolint:gosec // openat2 takes pointers to the path and the how struct
		uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0) //nolint:gosec // see above
	switch {
	case errors.Is(errno, syscall.ENOSYS):
		noOpenat2 = true
		return openPlain(full)
	case errno != 0:
		return nil, &os.PathError{Op: "openat2", Path: full, Err: errno}
	}
	return os.NewFile(fd, full), nil
}

func rootDescriptor(dir string) (int, error) {
	if fd, ok := rootFDs.Load(dir); ok {
		return fd.(int), nil
	}
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	if prev, loaded := rootFDs.LoadOrStore(dir, fd); loaded {
		_ = syscall.Close(fd)
		return prev.(int), nil
	}
	return fd, nil
}

func openPlain(full string) (*os.File, error) {
	fd, err := syscall.Open(full, openFlags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: full, Err: err}
	}
	return os.NewFile(uintptr(fd), full), nil
}
