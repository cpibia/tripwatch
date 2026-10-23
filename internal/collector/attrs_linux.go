//go:build linux && (amd64 || arm64)

package collector

import (
	"crypto/sha256"
	"encoding/binary"
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

	attrs.ACL, attrs.ACLWrite = readACL(path)

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

// POSIX ACL extended attribute layout, from linux/posix_acl_xattr.h: a 4-byte version, then
// 8-byte entries of tag, permissions and id, little endian.
const (
	aclUser  = 0x02
	aclGroup = 0x08
	aclMask  = 0x10
	aclWrite = 0x02
)

// readACL fingerprints the access and default ACLs of path and reports whether a named user or
// group may write. The kernel stores an ACL as an extended attribute only when it has entries
// beyond the mode bits.
func readACL(path string) (string, bool) {
	h := sha256.New()
	found, write := false, false
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		data := getxattr(path, name)
		if len(data) == 0 {
			continue
		}
		found = true
		h.Write([]byte(name))
		h.Write(data)
		write = write || aclWrites(data)
	}
	if !found {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil))[:16], write
}

// aclWrites reports whether an ACL lets a named user or group write, through its mask.
func aclWrites(data []byte) bool {
	named, mask := false, true
	for e := data[min(4, len(data)):]; len(e) >= 8; e = e[8:] {
		tag, perm := binary.LittleEndian.Uint16(e), binary.LittleEndian.Uint16(e[2:])
		switch tag {
		case aclUser, aclGroup:
			named = named || perm&aclWrite != 0
		case aclMask:
			mask = perm&aclWrite != 0
		}
	}
	return named && mask
}

// getxattr reads an extended attribute whatever its size; nil when it is absent.
func getxattr(path, name string) []byte {
	for range 3 {
		n, err := syscall.Getxattr(path, name, nil)
		if err != nil || n <= 0 {
			return nil
		}
		buf := make([]byte, n)
		n, err = syscall.Getxattr(path, name, buf)
		if errors.Is(err, syscall.ERANGE) {
			continue
		}
		if err != nil {
			return nil
		}
		return buf[:n]
	}
	return nil
}
