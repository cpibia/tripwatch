//go:build linux && (amd64 || arm64)

package collector

import (
	"errors"
	"syscall"
	"unsafe"
)

// FS_IOC_GETFLAGS and the flag bits from linux/fs.h, for 64-bit architectures.
const (
	fsIocGetflags = 0x80086601
	fsImmutableFl = 0x00000010
	fsAppendFl    = 0x00000020
)

// ReadAttrs reads the immutable and append-only flags (as shown by lsattr) and whether the
// file carries Linux capabilities (as shown by getcap).
func ReadAttrs(path string) (Attrs, error) {
	var attrs Attrs

	if n, err := syscall.Getxattr(path, "security.capability", nil); err == nil && n > 0 {
		attrs.Capabilities = true
	}

	// O_NONBLOCK keeps a FIFO or device from blocking the open.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return attrs, err
	}
	defer func() { _ = syscall.Close(fd) }()

	// The kernel reads and writes an int here, despite the ioctl being declared with long.
	var flags int32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), fsIocGetflags, uintptr(unsafe.Pointer(&flags))) //nolint:gosec // ioctl requires a pointer to the flags word
	if errno != 0 {
		if errors.Is(errno, syscall.ENOTTY) || errors.Is(errno, syscall.EOPNOTSUPP) {
			return attrs, nil
		}
		return attrs, errno
	}

	attrs.Immutable = flags&fsImmutableFl != 0
	attrs.AppendOnly = flags&fsAppendFl != 0
	return attrs, nil
}
