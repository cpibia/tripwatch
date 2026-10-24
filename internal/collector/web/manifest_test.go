package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cpibia/tripwatch/internal/collector"
)

// The second run names the code files that changed since the first one was delivered; data
// directories stay out, and a run whose snapshot was not delivered is compared again.
func TestManifestNamesChangedFiles(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/shop/bin/magento", "#!/usr/bin/env php")
	tr.file("var/www/shop/app/etc/di.xml", "<config/>")
	tr.file("var/www/shop/pub/index.php", "<?php require 'app/bootstrap.php';")
	tr.file("var/www/shop/vendor/acme/framework/App/View.php", "<?php class View {}")
	tr.file("var/www/shop/vendor/acme/framework/App/Old.php", "<?php class Old {}")
	tr.file("var/www/shop/var/log/system.log", "one")
	c := &Collector{StateDir: t.TempDir()}
	collect := func() AppReport {
		t.Helper()
		out, err := c.Collect(context.Background(), collector.NewSource(tr.root))
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range out.(Result).Apps {
			if a.Path == "/var/www/shop" {
				return a
			}
		}
		t.Fatal("application not found")
		return AppReport{}
	}
	if first := collect(); first.ChangeCount != 0 || first.Changes != nil {
		t.Fatalf("a first run names changes: %+v", first.Changes)
	}
	if err := c.Commit(); err != nil {
		t.Fatal(err)
	}

	tr.file("var/www/shop/vendor/acme/framework/App/View.php", "<?php class View { function render() { include($_COOKIE['t']); } }")
	tr.file("var/www/shop/pub/sysapi.php", `<?php $f = "sy"."stem"; $f($_GET["c"]);`)
	tr.file("var/www/shop/pub/odd\nname.php", "<?php")
	tr.file("var/www/shop/var/log/system.log", "two")
	if err := os.Remove(filepath.Join(tr.root, "var/www/shop/vendor/acme/framework/App/Old.php")); err != nil {
		t.Fatal(err)
	}
	want := "[{/var/www/shop/pub/odd\nname.php added} {/var/www/shop/pub/sysapi.php added} " +
		"{/var/www/shop/vendor/acme/framework/App/Old.php removed} {/var/www/shop/vendor/acme/framework/App/View.php modified}]"
	got := func(r AppReport) string {
		var out []string
		for _, ch := range r.Changes {
			out = append(out, fmt.Sprintf("{%s %s}", ch.Path, ch.Change))
		}
		return fmt.Sprint(out)
	}
	second := collect()
	if got(second) != want || second.ChangeCount != 4 {
		t.Fatalf("changes %s (%d), want %s", got(second), second.ChangeCount, want)
	}
	if second.Changes[1].SHA256 == "" || second.Changes[2].SHA256 != "" {
		t.Errorf("hashes: %+v", second.Changes)
	}
	// Not committed: the next run still compares with the first.
	if third := collect(); got(third) != want {
		t.Fatalf("after an undelivered run: %s", got(third))
	}
	if err := c.Commit(); err != nil {
		t.Fatal(err)
	}
	if fourth := collect(); fourth.ChangeCount != 0 {
		t.Fatalf("after commit: %s", got(fourth))
	}
}

func TestComparePaths(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"a/b", "a/b", 0},
		{"a/b", "a/c", -1},
		{"a/b/z", "a/c", -1},
		// Directory a is listed before the file a-b, so its content comes first too.
		{"a-b", "a/b", 1},
		{"a/b", "a-b", -1},
		{"a", "a/b", -1},
	} {
		if got := comparePaths(c.a, c.b); got != c.want {
			t.Errorf("comparePaths(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
