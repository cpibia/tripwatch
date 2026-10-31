package system

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cpibia/tripwatch/internal/collector"
)

// The decoys are reported by their metadata alone, a missing one as missing, and no reader of the
// sensor opens them once collected.
func TestDecoysCollected(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/www"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "var/www/wp-config.php.bak"), []byte("<?php define('DB_PASSWORD','x');"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := collector.NewSource(root)
	r, err := Decoys{Paths: []string{"/var/www/wp-config.php.bak", "/root/.aws/credentials"}}.Collect(context.Background(), src)
	t.Cleanup(func() { collector.SetDecoys(src, nil) })
	if err != nil {
		t.Fatal(err)
	}
	got := r.(DecoysResult).Decoys
	if len(got) != 2 || got[0].Path != "/var/www/wp-config.php.bak" || got[0].Missing || got[0].Size != 32 || got[0].Inode == 0 || !got[1].Missing {
		t.Errorf("decoys = %+v", got)
	}
	if _, err := fs.ReadFile(src.FS, "var/www/wp-config.php.bak"); !errors.Is(err, collector.ErrDecoy) {
		t.Errorf("the decoy was opened: %v", err)
	}
}

// The decoys' list comes from a file only its owner can read, one absolute path a line; a missing
// file is no decoys, and one others can read, or with a relative path, is refused.
func TestLoadDecoys(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "decoys")
	if paths, err := LoadDecoys(name); err != nil || paths != nil {
		t.Errorf("missing file: %v %v", paths, err)
	}
	if err := os.WriteFile(name, []byte("# fake backups\n/var/www/backup.sql\n\n  /root/.aws/credentials.old  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, err := LoadDecoys(name)
	if err != nil || !slices.Equal(paths, []string{"/var/www/backup.sql", "/root/.aws/credentials.old"}) {
		t.Errorf("got %q %v", paths, err)
	}
	if err := os.Chmod(name, 0o644); err != nil { //nolint:gosec // the mode the loader must refuse
		t.Fatal(err)
	}
	if _, err := LoadDecoys(name); err == nil {
		t.Error("a list others can read is accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "relative"), []byte("var/www/backup.sql\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDecoys(filepath.Join(dir, "relative")); err == nil {
		t.Error("a relative path is accepted")
	}
}

// A hard link to a decoy is refused like the decoy, and reported as a path leading to one, with the
// decoy's links counted.
func TestDecoyHardLinkReported(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/www"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "var/www/backup.sql"), []byte("bait"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "var/www/backup.sql"), filepath.Join(root, "var/www/x.php")); err != nil {
		t.Fatal(err)
	}
	src := collector.NewSource(root)
	d := Decoys{Paths: []string{"/var/www/backup.sql"}}
	d.Refresh(src)
	t.Cleanup(func() { collector.SetDecoys(src, nil) })
	if _, err := fs.ReadFile(src.FS, "var/www/x.php"); !errors.Is(err, collector.ErrDecoy) {
		t.Fatalf("the link is read: %v", err)
	}
	out, err := d.Collect(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	res := out.(DecoysResult)
	if !slices.Contains(res.Aliases, "/var/www/x.php") || res.Decoys[0].Links != 2 {
		t.Errorf("got %+v", res)
	}
}
