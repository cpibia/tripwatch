package system

import (
	"os"
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
	want := []string{"/lib/aarch64-linux-gnu", "/opt/vendor/lib", "/usr/lib/aarch64-linux-gnu", "/usr/local/lib", "/usr/local/lib/aarch64-linux-gnu"}
	if !slices.Equal(lp.ConfigDirs, want) {
		t.Errorf("config dirs %v, want %v", lp.ConfigDirs, want)
	}
}

// The cache comes from a host that may be compromised: cut or damaged, it is an error, never a
// panic or a read out of bounds.
func TestLoaderCacheDamaged(t *testing.T) {
	cache, err := os.ReadFile("testdata/ld.so.cache")
	if err != nil {
		t.Fatal(err)
	}
	for n := range len(cache) {
		_, _, _ = cacheDirs(cache[:n])
	}
	for i := 20; i < 200; i++ {
		bad := slices.Clone(cache)
		bad[i] ^= 0xff
		_, _, _ = cacheDirs(bad)
	}
	old := append(append([]byte("ld.so-1.7.0\x00"), 0, 0, 0, 0), make([]byte, 0)...)
	if _, _, err := cacheDirs(append(old, cache...)); err != nil {
		t.Errorf("old header before the new format: %v", err)
	}
}
