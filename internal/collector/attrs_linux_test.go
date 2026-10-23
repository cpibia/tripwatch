//go:build linux && (amd64 || arm64)

package collector

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type aclEntry struct {
	tag, perm uint16
	id        uint32
}

func acl(entries ...aclEntry) []byte {
	out := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range entries {
		out = binary.LittleEndian.AppendUint16(out, e.tag)
		out = binary.LittleEndian.AppendUint16(out, e.perm)
		out = binary.LittleEndian.AppendUint32(out, e.id)
	}
	return out
}

// Only a named user or group allowed to write through the mask makes an ACL a writer: a
// read-only ACL for a backup agent does not.
func TestACLWrites(t *testing.T) {
	const r, rw = 4, 6
	for _, c := range []struct {
		data []byte
		want bool
	}{
		{acl(aclEntry{1, rw, 0}, aclEntry{aclUser, rw, 33}, aclEntry{4, r, 0}, aclEntry{aclMask, rw, 0}, aclEntry{0x20, r, 0}), true},
		{acl(aclEntry{aclGroup, rw, 1001}, aclEntry{aclMask, r, 0}), false},
		{acl(aclEntry{aclUser, r, 34}, aclEntry{aclMask, rw, 0}), false},
		{acl(aclEntry{aclGroup, rw, 1001}), true},
		{[]byte{2, 0}, false},
	} {
		if got := aclWrites(c.data); got != c.want {
			t.Errorf("aclWrites(%v) = %v, want %v", c.data, got, c.want)
		}
	}
}

// An ACL is read on the file a link leads to inside the observed root, not in the sensor's own
// filesystem.
func TestACLThroughLinkInRoot(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"opt/p", "etc"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(root, "opt/p/b.rules")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/opt/p/b.rules", filepath.Join(root, "etc/link.rules")); err != nil {
		t.Fatal(err)
	}
	const all = 0xffffffff
	data := acl(aclEntry{1, 6, all}, aclEntry{aclUser, 6, 33}, aclEntry{4, 4, all}, aclEntry{aclMask, 6, all}, aclEntry{0x20, 4, all})
	if err := syscall.Setxattr(target, "system.posix_acl_access", data, 0); err != nil {
		t.Skipf("ACLs not supported here: %v", err)
	}
	a, err := NewSource(root).Attrs("etc/link.rules")
	if err != nil || !a.ACLWrite || a.ACL == "" {
		t.Fatalf("attrs = %+v, %v", a, err)
	}
}
