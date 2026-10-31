package web

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/discovery"
)

// A changed file names the release of its plugin, read from the plugin's header as WordPress
// finds it; a header with a version of another shape names none.
func TestPluginReleases(t *testing.T) {
	root := t.TempDir()
	write := func(p, content string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("var/www/blog/wp-content/plugins/shop/shop.php", "<?php\n/**\n * Plugin Name: Shop\n * Version: 1.2.3\n */\n")
	write("var/www/blog/wp-content/plugins/shop/assets/app.js", "x")
	write("var/www/blog/wp-content/plugins/forms/a-helper.php", "<?php // helpers\n")
	write("var/www/blog/wp-content/plugins/forms/main.php", "<?php\n/*\nPlugin Name: Forms\nVersion: 5.9\n*/\n")
	write("var/www/blog/wp-content/plugins/odd/odd.php", "<?php\n/* Plugin Name: Odd\n Version: 1.0/../../x */\n")
	write("var/www/blog/wp-content/themes/t/style.css", "/* Theme Name: T\nVersion: 2 */")
	s := &scanner{src: collector.NewSource(root), budget: newHashBudget(), findings: map[string]int{}}
	got := s.pluginReleases([]FileChange{
		{Path: "/var/www/blog/wp-content/plugins/shop/assets/app.js", Change: ChangeModified},
		{Path: "/var/www/blog/wp-content/plugins/shop/shop.php", Change: ChangeModified},
		{Path: "/var/www/blog/wp-content/plugins/forms/main.php", Change: ChangeModified},
		{Path: "/var/www/blog/wp-content/plugins/odd/odd.php", Change: ChangeModified},
		{Path: "/var/www/blog/wp-content/themes/t/style.css", Change: ChangeModified},
	})
	want := []PackageRelease{
		{Root: "/var/www/blog/wp-content/plugins/shop", Ecosystem: EcosystemWordPressPlugin, Slug: "shop", Version: "1.2.3"},
		{Root: "/var/www/blog/wp-content/plugins/forms", Ecosystem: EcosystemWordPressPlugin, Slug: "forms", Version: "5.9"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("releases = %+v", got)
	}
}

// An install whose files outside wp-content changed names its WordPress release with the locale
// of wp-includes/version.php; one whose changes are all in wp-content names none.
func TestCoreRelease(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/www/blog/wp-includes"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "var/www/blog/wp-includes/version.php"), []byte("<?php\n$wp_version = '6.6.2';\n$wp_local_package = 'it_IT';\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &scanner{src: collector.NewSource(root), budget: newHashBudget(), findings: map[string]int{}}
	s.report.Application = discovery.Application{Path: "/var/www/blog", Framework: "wordpress", Version: "6.6.2"}
	got, ok := s.coreRelease([]FileChange{{Path: "/var/www/blog/wp-includes/load.php", Change: ChangeModified}})
	if !ok || got != (PackageRelease{Root: "/var/www/blog", Ecosystem: EcosystemWordPressCore, Slug: "it_IT", Version: "6.6.2"}) {
		t.Errorf("core release = %+v, %v", got, ok)
	}
	if _, ok := s.coreRelease([]FileChange{{Path: "/var/www/blog/wp-content/plugins/x/x.php", Change: ChangeModified}}); ok {
		t.Error("changes in wp-content alone named the core")
	}
	if err := os.WriteFile(filepath.Join(root, "var/www/blog/wp-includes/version.php"), []byte("<?php $wp_version = '6.6.2';"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.coreRelease([]FileChange{{Path: "/var/www/blog/index.php"}}); got.Slug != "en_US" {
		t.Errorf("locale without one: %q", got.Slug)
	}
}
