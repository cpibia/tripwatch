//go:build linux && (amd64 || arm64)

package collector

import (
	"crypto/sha256"
	"encoding/hex"
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

	attrs.ACL = aclDigest(path)

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

// aclDigest hashes the access and default ACLs of path. The kernel stores an ACL as an extended
// attribute only when it has entries beyond the mode bits.
func aclDigest(path string) string {
	h := sha256.New()
	found := false
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		buf := make([]byte, 4096)
		n, err := syscall.Getxattr(path, name, buf)
		if errors.Is(err, syscall.ERANGE) {
			n, buf = 0, nil
		} else if err != nil || n <= 0 {
			continue
		}
		found = true
		h.Write([]byte(name))
		h.Write(buf[:n])
	}
	if !found {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
