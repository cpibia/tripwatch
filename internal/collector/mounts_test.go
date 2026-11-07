package collector

import (
	"os"
	"path/filepath"
	"testing"
)

// Of mounts stacked on one point the last one is in sight; escaped names are decoded.
func TestMountType(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "proc/1"), 0o750); err != nil {
		t.Fatal(err)
	}
	table := "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
		"30 22 0:40 / /tmp/a rw - tmpfs tmpfs rw\n" +
		"31 30 0:41 / /tmp/a rw - overlay overlay rw,lowerdir=/x\n" +
		"32 22 0:42 / /tmp/my\\040dir rw,nosuid - fuse.sshfs host:/ rw\n"
	if err := os.WriteFile(filepath.Join(root, "proc/1/mountinfo"), []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	src := NewSource(root)
	for point, want := range map[string]string{"tmp/a": "overlay", "tmp/my dir": "fuse.sshfs", "": "ext4"} {
		if got, ok := MountType(src, point); !ok || got != want {
			t.Errorf("%q: %q %v, want %q", point, got, ok, want)
		}
	}
	if got, ok := MountType(src, "tmp/b"); ok {
		t.Errorf("tmp/b is no mount point, got %q", got)
	}
}
