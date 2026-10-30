package system

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/cpibia/tripwatch/internal/collector"
)

// A cache written by "ldconfig /opt/x" in Debian lists /opt/x, which no configuration file
// names; the configuration's directories are read through its includes.
func TestLoaderPaths(t *testing.T) {
	cache, err := os.ReadFile("testdata/ld.so.cache")
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{
		"etc/ld.so.cache":                         {Data: cache},
		"etc/ld.so.conf":                          text("include /etc/ld.so.conf.d/*.conf\n"),
		"etc/ld.so.conf.d/libc.conf":              text("# libc default configuration\n/usr/local/lib\n"),
		"etc/ld.so.conf.d/aarch64-linux-gnu.conf": text("/usr/local/lib/aarch64-linux-gnu\n/lib/aarch64-linux-gnu, /usr/lib/aarch64-linux-gnu\n"),
		"etc/ld.so.conf.d/nested.conf":            text("include more/*.conf\n"),
		"etc/ld.so.conf.d/more/x.conf":            text("/opt/vendor/lib=libc6\n"),
	}
	var issues collector.Issues
	lp := readLoaderPaths(fsys, &issues)
	if lp == nil {
		t.Fatalf("no loader paths: %v", issues)
	}
	if !slices.Contains(lp.CacheDirs, "/opt/x") || !slices.Contains(lp.CacheDirs, "/lib/aarch64-linux-gnu") {
		t.Errorf("cache dirs %v", lp.CacheDirs)
	}
	if want := []LibcCopy{{Dir: "/lib/aarch64-linux-gnu", Flags: 0x0a03}}; !slices.Equal(lp.Libc, want) {
		t.Errorf("libc %v, want %v", lp.Libc, want)
	}
	want := []string{"/lib/aarch64-linux-gnu", "/opt/vendor/lib", "/usr/lib/aarch64-linux-gnu", "/usr/local/lib", "/usr/local/lib/aarch64-linux-gnu"}
	if !slices.Equal(lp.ConfigDirs, want) {
		t.Errorf("config dirs %v, want %v", lp.ConfigDirs, want)
	}
}

// A cache too large to read at once, which the loader still uses, is reported as truncated
// with the configuration, not left out.
func TestLoaderCacheTooLarge(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/ld.so.conf"), []byte("/usr/local/lib\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(root, "etc/ld.so.cache")) //nolint:gosec // a file of the test's own temporary directory
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(collector.MaxReadSize + 1<<20); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	var issues collector.Issues
	lp := readLoaderPaths(collector.NewSource(root).FS, &issues)
	if lp == nil || !lp.Truncated || lp.Libc == nil || lp.Native != nativeLibcFlags || !slices.Equal(lp.ConfigDirs, []string{"/usr/local/lib"}) || len(issues) != 1 {
		t.Errorf("loader paths %+v, issues %q", lp, issues)
	}
}

// A cache padded with more directories than are read is truncated, and libc is still found
// after the last directory kept.
func TestLoaderCachePadded(t *testing.T) {
	var files []string
	for i := range maxLoaderDirs + 8 {
		files = append(files, fmt.Sprintf("/opt/pad%04d/libz.so.1", i))
	}
	dirs, libc, truncated, err := cacheDirs(newCache(append(files, "/usr/lib64/libc.so.6")))
	if err != nil || !truncated || len(dirs) != maxLoaderDirs {
		t.Fatalf("dirs %d, truncated %v, err %v", len(dirs), truncated, err)
	}
	if want := []LibcCopy{{Dir: "/usr/lib64", Flags: 0x0303}}; !slices.Equal(libc, want) {
		t.Errorf("libc %v, want %v", libc, want)
	}
}

// newCache writes a cache in glibc's new format listing files, as x86-64 libc6 libraries.
func newCache(files []string) []byte {
	head := make([]byte, newHeaderSize)
	copy(head, newCacheMagic)
	binary.LittleEndian.PutUint32(head[20:], uint32(len(files))) //nolint:gosec // a few hundred test entries
	strs := newHeaderSize + len(files)*newEntrySize
	var entries, text []byte
	for _, f := range files {
		e := make([]byte, newEntrySize)
		binary.LittleEndian.PutUint32(e, 0x0303)
		at := uint32(strs + len(text)) //nolint:gosec // a few kilobytes of test strings
		binary.LittleEndian.PutUint32(e[4:], at)
		binary.LittleEndian.PutUint32(e[8:], at)
		entries = append(entries, e...)
		text = append(append(text, f...), 0)
	}
	return append(append(head, entries...), text...)
}

// The cache comes from a host that may be compromised: cut or damaged, it is an error, never a
// panic or a read out of bounds.
func TestLoaderCacheDamaged(t *testing.T) {
	cache, err := os.ReadFile("testdata/ld.so.cache")
	if err != nil {
		t.Fatal(err)
	}
	for n := range len(cache) {
		_, _, _, _ = cacheDirs(cache[:n])
	}
	for i := 20; i < 200; i++ {
		bad := slices.Clone(cache)
		bad[i] ^= 0xff
		_, _, _, _ = cacheDirs(bad)
	}
	old := append(append([]byte("ld.so-1.7.0\x00"), 0, 0, 0, 0), make([]byte, 0)...)
	if _, _, _, err := cacheDirs(append(old, cache...)); err != nil {
		t.Errorf("old header before the new format: %v", err)
	}
}
