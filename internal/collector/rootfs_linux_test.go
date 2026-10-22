//go:build linux

package collector

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// When the sensor observes a host mounted at /host, an absolute symlink on that host must
// resolve inside /host, as it does for the host itself, not in the sensor's own filesystem.
func TestAbsoluteSymlinkStaysInRoot(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "etc"))
	mustMkdir(t, filepath.Join(root, "usr/lib"))
	if err := os.WriteFile(filepath.Join(root, "usr/lib/.cfg"), []byte("/usr/lib/libhide.so\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/lib/.cfg", filepath.Join(root, "etc/ld.so.preload")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(root, "etc/escape")); err != nil {
		t.Fatal(err)
	}

	src := NewSource(root)
	data, err := fs.ReadFile(src.FS, "etc/ld.so.preload")
	if err != nil || string(data) != "/usr/lib/libhide.so\n" {
		t.Fatalf("preload = %q, %v; want the file inside the root", data, err)
	}
	if _, err := fs.ReadFile(src.FS, "etc/escape"); err == nil {
		t.Error("a link to a path missing inside the root must not reach the sensor's own /etc")
	}
	if _, err := fs.ReadFile(src.FS, "../../etc/hostname"); err == nil {
		t.Error("an invalid path must be refused")
	}
}
