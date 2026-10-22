//go:build linux

package collector

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
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

func confinementTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "etc"))
	mustMkdir(t, filepath.Join(root, "usr/lib"))
	if err := os.WriteFile(filepath.Join(root, "usr/lib/.cfg"), []byte("/usr/lib/libhide.so\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"etc/ld.so.preload": "/usr/lib/.cfg",
		"etc/escape":        "/etc/hostname",
		"hostetc":           "/etc",
		"up":                "../../../../../../..",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func checkConfinement(t *testing.T, src Source) {
	t.Helper()
	data, err := fs.ReadFile(src.FS, "etc/ld.so.preload")
	if err != nil || string(data) != "/usr/lib/libhide.so\n" {
		t.Errorf("preload = %q, %v; want the file inside the root", data, err)
	}
	for _, name := range []string{"etc/escape", "hostetc/hostname", "up/etc/hostname"} {
		if _, err := fs.ReadFile(src.FS, name); err == nil {
			t.Errorf("ReadFile(%s) reached a file outside the root", name)
		}
	}
	// Lstat does not follow the last component (etc/escape is a link inside the root), but
	// must not follow an intermediate one out of it.
	for _, name := range []string{"hostetc/hostname", "up/etc/hostname"} {
		if _, err := fs.Lstat(src.FS, name); err == nil {
			t.Errorf("Lstat(%s) reached a file outside the root", name)
		}
	}
	if _, err := fs.ReadLink(src.FS, "hostetc/os-release"); err == nil {
		t.Error("ReadLink followed an intermediate link outside the root")
	}
	if target, err := fs.ReadLink(src.FS, "etc/ld.so.preload"); err != nil || target != "/usr/lib/.cfg" {
		t.Errorf("ReadLink = %q, %v", target, err)
	}
}

// The userspace resolver used when openat2 is missing or forbidden must confine links in the
// same way, and the degradation must be visible in the snapshot.
func TestConfinementWithoutOpenat2(t *testing.T) {
	degradedMu.Lock()
	prev := degradedReason
	degradedReason = "forced by test"
	degradedMu.Unlock()
	t.Cleanup(func() {
		degradedMu.Lock()
		degradedReason = prev
		degradedMu.Unlock()
	})

	checkConfinement(t, NewSource(confinementTree(t)))
	snap := Run(context.Background(), NewSource(t.TempDir()), nil, time.Now())
	if len(snap.Warnings) != 1 {
		t.Errorf("warnings = %v, want the degraded confinement reported", snap.Warnings)
	}
}

func TestConfinementWithOpenat2(t *testing.T) {
	checkConfinement(t, NewSource(confinementTree(t)))
	if w := Warnings(); len(w) != 0 {
		t.Skipf("kernel without openat2: %v", w)
	}
}

// A device is described but never opened.
func TestDevicesAreNotOpened(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "dev"))
	if err := syscall.Mknod(filepath.Join(root, "dev/null"), syscall.S_IFCHR|0o666, 1<<8|3); err != nil {
		t.Skipf("mknod not permitted: %v", err)
	}
	src := NewSource(root)
	if _, err := fs.ReadFile(src.FS, "dev/null"); !errors.Is(err, ErrNotRegular) {
		t.Errorf("ReadFile(device) err = %v", err)
	}
	if info, err := fs.Stat(src.FS, "dev/null"); err != nil || info.Mode()&fs.ModeCharDevice == 0 {
		t.Errorf("Stat(device) = %v, %v", info, err)
	}
}

// Swapping a directory for a link to the outside while files are being opened must never
// let a read escape: the descriptor walk has no step that goes back through a path string.
func TestUserspaceResolutionRace(t *testing.T) {
	degradedMu.Lock()
	prev := degradedReason
	degradedReason = "forced by test"
	degradedMu.Unlock()
	t.Cleanup(func() {
		degradedMu.Lock()
		degradedReason = prev
		degradedMu.Unlock()
	})

	root, outside := t.TempDir(), t.TempDir()
	mustMkdir(t, filepath.Join(root, "d"))
	mustMkdir(t, filepath.Join(outside, "d"))
	if err := os.WriteFile(filepath.Join(root, "d/f"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "d/f"), []byte("OUTSIDE"), 0o600); err != nil {
		t.Fatal(err)
	}
	escape, err := filepath.Rel(root, outside)
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		d, saved, tmp := filepath.Join(root, "d"), filepath.Join(root, "d.real"), filepath.Join(root, "d.tmp")
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Rename(d, saved)
			_ = os.Symlink(filepath.Join(escape, "d"), tmp)
			_ = os.Rename(tmp, d)
			_ = os.Remove(d)
			_ = os.Rename(saved, d)
		}
	}()

	src := NewSource(root)
	for range 200_000 {
		if data, err := fs.ReadFile(src.FS, "d/f"); err == nil && string(data) != "inside" {
			close(stop)
			<-done
			t.Fatalf("read %q from outside the root", data)
		}
	}
	close(stop)
	<-done
}
