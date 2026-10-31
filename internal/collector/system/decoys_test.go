package system

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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
