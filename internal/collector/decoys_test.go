package collector

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// A decoy is never opened, through its path or a link to it, and a file put in its place later is
// the decoy once the decoys are refreshed.
func TestDecoysNeverOpened(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"bait.bak", "other.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("bait.bak", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	src := NewSource(dir)
	SetDecoys(src, []string{"bait.bak"})
	t.Cleanup(func() { SetDecoys(src, nil) })
	for _, name := range []string{"bait.bak", "link"} {
		if _, err := fs.ReadFile(src.FS, name); !errors.Is(err, ErrDecoy) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := fs.ReadFile(src.FS, "other.txt"); err != nil {
		t.Errorf("another file: %v", err)
	}
	if err := os.Rename(filepath.Join(dir, "other.txt"), filepath.Join(dir, "bait.bak")); err != nil {
		t.Fatal(err)
	}
	SetDecoys(src, []string{"bait.bak"})
	if _, err := fs.ReadFile(src.FS, "bait.bak"); !errors.Is(err, ErrDecoy) {
		t.Errorf("the decoy put in place: %v", err)
	}
}
