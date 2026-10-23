//go:build linux

package collector

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// openat2, its resolve flags and O_PATH from the kernel headers; the syscall number is the
// same on amd64 and arm64.
const (
	sysOpenat2        = 437
	resolveFlagInRoot = 0x10
	oPath             = 0x200000
	maxSymlinks       = 40
)

type openHow struct {
	flags   uint64
	mode    uint64
	resolve uint64
}

const (
	pathFlags = oPath | syscall.O_CLOEXEC
	readFlags = syscall.O_RDONLY | syscall.O_NONBLOCK | syscall.O_CLOEXEC | syscall.O_NOCTTY
)

var (
	rootFDs sync.Map // dir -> int

	degradedMu     sync.Mutex
	degradedReason string
)

// Warnings reports conditions that weaken the sensor's guarantees, to be shown in the
// snapshot rather than silently tolerated.
func Warnings() []string {
	degradedMu.Lock()
	defer degradedMu.Unlock()
	if degradedReason == "" {
		return nil
	}
	return []string{"symlink confinement uses userspace resolution, open to races: " + degradedReason}
}

func degrade(reason string) {
	degradedMu.Lock()
	defer degradedMu.Unlock()
	if degradedReason == "" {
		degradedReason = reason
	}
}

func isDegraded() bool {
	degradedMu.Lock()
	defer degradedMu.Unlock()
	return degradedReason != ""
}

// openPath returns an O_PATH descriptor for name inside dir. O_PATH resolves the path without
// opening the file, so a device or FIFO is never touched before its type is known.
//
// When dir is not "/", symlinks are resolved inside dir, as they are for the observed host,
// and not in the sensor's own filesystem: with openat2 RESOLVE_IN_ROOT where the kernel offers
// it, otherwise with a userspace resolver (reported through Warnings). /proc is resolved
// normally: its magic links (/proc/<pid>/exe) are what the process collector needs.
func openPath(dir, name string) (*os.File, error) {
	full := filepath.Join(dir, filepath.FromSlash(name))
	if dir == "/" || name == "proc" || strings.HasPrefix(name, "proc/") {
		return openFlags(full, pathFlags)
	}
	if !isDegraded() {
		f, err := openat2InRoot(dir, name)
		switch {
		case err == nil:
			return f, nil
		case errors.Is(err, syscall.ENOSYS), errors.Is(err, syscall.EPERM):
			degrade(fmt.Sprintf("openat2 unavailable (%v)", err))
		default:
			return nil, err
		}
	}
	return openPathByDescriptors(dir, name)
}

func openat2InRoot(dir, name string) (*os.File, error) {
	rootFD, err := rootDescriptor(dir)
	if err != nil {
		return nil, err
	}
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	how := openHow{flags: pathFlags, resolve: resolveFlagInRoot}
	fd, _, errno := syscall.Syscall6(sysOpenat2, uintptr(rootFD), uintptr(unsafe.Pointer(p)), //nolint:gosec // openat2 takes pointers to the path and the how struct
		uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0) //nolint:gosec // see above
	if errno != 0 {
		return nil, &os.PathError{Op: "openat2", Path: filepath.Join(dir, name), Err: errno}
	}
	return os.NewFile(fd, filepath.Join(dir, name)), nil
}

// openPathByDescriptors resolves name inside dir the way openat2 RESOLVE_IN_ROOT does, for
// kernels without it: every component is opened with openat relative to the descriptor of the
// directory before it, with O_NOFOLLOW, and symlinks are read from their own descriptor. No
// step goes back through a path string, so swapping a directory for a link between two steps
// cannot lead outside dir. Absolute link targets restart from dir and ".." stops at it.
func openPathByDescriptors(dir, name string) (*os.File, error) {
	rootFD, err := rootDescriptor(dir)
	if err != nil {
		return nil, err
	}
	start, err := syscall.Openat(rootFD, ".", pathFlags|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: dir, Err: err}
	}
	stack := []int{start}
	closeAll := func() {
		for _, fd := range stack {
			_ = syscall.Close(fd)
		}
	}

	full := filepath.Join(dir, filepath.FromSlash(name))
	pending := strings.Split(name, "/")
	links := 0
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if len(stack) > 1 {
				_ = syscall.Close(stack[len(stack)-1])
				stack = stack[:len(stack)-1]
			}
			continue
		}

		fd, err := syscall.Openat(stack[len(stack)-1], part, pathFlags|syscall.O_NOFOLLOW, 0)
		if err != nil {
			closeAll()
			return nil, &os.PathError{Op: "openat", Path: full, Err: err}
		}
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			_ = syscall.Close(fd)
			closeAll()
			return nil, &os.PathError{Op: "fstat", Path: full, Err: err}
		}

		if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			target, err := readlinkFD(fd)
			_ = syscall.Close(fd)
			if err != nil {
				closeAll()
				return nil, &os.PathError{Op: "readlinkat", Path: full, Err: err}
			}
			if links++; links > maxSymlinks {
				closeAll()
				return nil, &os.PathError{Op: "resolve", Path: full, Err: syscall.ELOOP}
			}
			if path.IsAbs(target) {
				for _, d := range stack[1:] {
					_ = syscall.Close(d)
				}
				stack = stack[:1]
			}
			pending = append(strings.Split(strings.TrimPrefix(target, "/"), "/"), pending...)
			continue
		}
		if len(pending) > 0 && st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			_ = syscall.Close(fd)
			closeAll()
			return nil, &os.PathError{Op: "openat", Path: full, Err: syscall.ENOTDIR}
		}
		stack = append(stack, fd)
	}

	result := stack[len(stack)-1]
	for _, fd := range stack[:len(stack)-1] {
		_ = syscall.Close(fd)
	}
	return os.NewFile(uintptr(result), full), nil
}

// readlinkFD reads the target of the symlink open as fd (O_PATH|O_NOFOLLOW), with an empty
// path as readlinkat allows since Linux 2.6.39.
func readlinkFD(fd int) (string, error) {
	empty, err := syscall.BytePtrFromString("")
	if err != nil {
		return "", err
	}
	buf := make([]byte, syscall.PathMax)
	n, _, errno := syscall.Syscall6(syscall.SYS_READLINKAT, uintptr(fd), uintptr(unsafe.Pointer(empty)), //nolint:gosec // readlinkat takes pointers to the path and the buffer
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0) //nolint:gosec // see above
	if errno != 0 {
		return "", errno
	}
	return string(buf[:n]), nil
}

// statIn describes name, following symlinks inside dir, without opening the file itself.
func statIn(dir, name string) (os.FileInfo, error) {
	f, err := openPath(dir, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return f.Stat()
}

// openIn opens name for reading only when it is a regular file or a directory: the type is
// read from the O_PATH descriptor, and only then is the same inode reopened through
// /proc/self/fd, so no other kind of file is ever opened.
func openIn(dir, name string) (*os.File, os.FileInfo, error) {
	pf, err := openPath(dir, name)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = pf.Close() }()
	info, err := pf.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return nil, info, ErrNotRegular
	}
	fd, err := syscall.Open("/proc/self/fd/"+strconv.Itoa(int(pf.Fd())), readFlags, 0)
	if err != nil {
		return nil, nil, &os.PathError{Op: "reopen", Path: pf.Name(), Err: err}
	}
	// Named after the real path: the /proc/self/fd path dies with the O_PATH descriptor.
	return os.NewFile(uintptr(fd), pf.Name()), info, nil
}

// lstatIn and readlinkIn resolve the parent directory inside dir and address the last
// component through the parent's descriptor, so a link in an intermediate component cannot
// lead outside dir.
func lstatIn(dir, name string) (os.FileInfo, error) {
	p, done, err := parentPath(dir, name)
	if err != nil {
		return nil, err
	}
	defer done()
	return os.Lstat(p)
}

func readlinkIn(dir, name string) (string, error) {
	p, done, err := parentPath(dir, name)
	if err != nil {
		return "", err
	}
	defer done()
	return os.Readlink(p)
}

func parentPath(dir, name string) (string, func(), error) {
	if dir == "/" {
		return filepath.Join(dir, filepath.FromSlash(name)), func() {}, nil
	}
	parent, err := openPath(dir, path.Dir(name))
	if err != nil {
		return "", nil, err
	}
	return "/proc/self/fd/" + strconv.Itoa(int(parent.Fd())) + "/" + path.Base(name), func() { _ = parent.Close() }, nil
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

func openFlags(full string, flags int) (*os.File, error) {
	fd, err := syscall.Open(full, flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: full, Err: err}
	}
	return os.NewFile(uintptr(fd), full), nil
}

// attrsIn reads the attributes of name resolved inside dir: by its raw path the kernel would
// follow a link in the sensor's own filesystem instead of the observed one.
func attrsIn(dir, name string) (Attrs, error) {
	f, err := openPath(dir, name)
	if err != nil {
		return Attrs{}, err
	}
	defer func() { _ = f.Close() }()
	return ReadAttrs("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
}
