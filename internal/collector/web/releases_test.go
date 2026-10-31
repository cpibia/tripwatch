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
	write("var/www/blog/wp-content/themes/calm/style.css", "/*\nTheme Name: Calm\nVersion: 1.4\n*/\nbody{}")
	s := &scanner{src: collector.NewSource(root), budget: newHashBudget(), findings: map[string]int{}}
	got := s.packageReleases([]FileChange{
		{Path: "/var/www/blog/wp-content/plugins/shop/assets/app.js", Change: ChangeModified},
		{Path: "/var/www/blog/wp-content/plugins/shop/shop.php", Change: ChangeModified},
		{Path: "/var/www/blog/wp-content/plugins/forms/main.php", Change: ChangeModified},
		{Path: "/var/www/blog/wp-content/plugins/odd/odd.php", Change: ChangeModified},
		{Path: "/var/www/blog/wp-content/themes/t/style.css", Change: ChangeModified},
		{Path: "/var/www/blog/wp-content/themes/calm/functions.php", Change: ChangeModified},
	})
	want := []PackageRelease{
		{Root: "/var/www/blog/wp-content/plugins/shop", Ecosystem: EcosystemWordPressPlugin, Slug: "shop", Version: "1.2.3"},
		{Root: "/var/www/blog/wp-content/plugins/forms", Ecosystem: EcosystemWordPressPlugin, Slug: "forms", Version: "5.9"},
		{Root: "/var/www/blog/wp-content/themes/calm", Ecosystem: EcosystemWordPressTheme, Slug: "calm", Version: "1.4"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("releases = %+v", got)
	}
}

// An install names its WordPress release with the locale of wp-includes/version.php, en_US
// without one, and every plugin installed, changed or not, the changed ones first.
func TestCoreAndInstalledReleases(t *testing.T) {
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
	write("var/www/blog/wp-includes/version.php", "<?php\n$wp_version = '6.6.2';\n$wp_local_package = 'it_IT';\n")
	write("var/www/blog/wp-content/plugins/shop/shop.php", "<?php\n/*\nPlugin Name: Shop\nVersion: 1.2.3\n*/\n")
	write("var/www/blog/wp-content/plugins/forms/forms.php", "<?php\n/*\nPlugin Name: Forms\nVersion: 5.9\n*/\n")
	s := &scanner{src: collector.NewSource(root), budget: newHashBudget(), findings: map[string]int{}}
	s.report.Application = discovery.Application{Path: "/var/www/blog", Framework: "wordpress", Version: "6.6.2"}
	got := s.releases([]FileChange{{Path: "/var/www/blog/wp-content/plugins/shop/shop.php", Change: ChangeModified}})
	want := []PackageRelease{
		{Root: "/var/www/blog", Ecosystem: EcosystemWordPressCore, Slug: "it_IT", Version: "6.6.2"},
		{Root: "/var/www/blog/wp-content/plugins/shop", Ecosystem: EcosystemWordPressPlugin, Slug: "shop", Version: "1.2.3"},
		{Root: "/var/www/blog/wp-content/plugins/forms", Ecosystem: EcosystemWordPressPlugin, Slug: "forms", Version: "5.9"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("releases = %+v", got)
	}
	write("var/www/blog/wp-includes/version.php", "<?php $wp_version = '6.6.2';")
	if core, _ := s.coreRelease(); core.Slug != "en_US" {
		t.Errorf("locale without one: %q", core.Slug)
	}
}

// A changed file of a drupal.org module names the project and version its packaged .info.yml
// gives; a module without them, or outside a Drupal site, names none.
func TestDrupalReleases(t *testing.T) {
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
	write("var/www/site/web/modules/contrib/token/token.info.yml", "name: Token\ntype: module\n\n# Information added by Drupal.org packaging script on 2026-10-30\nversion: '8.x-1.18'\nproject: 'token'\n")
	write("var/www/site/web/modules/contrib/devel/devel.info.yml", "name: Devel\ntype: module\n")
	s := &scanner{src: collector.NewSource(root), budget: newHashBudget(), findings: map[string]int{}}
	changes := []FileChange{
		{Path: "/var/www/site/web/modules/contrib/token/token.module", Change: ChangeModified},
		{Path: "/var/www/site/web/modules/contrib/devel/devel.module", Change: ChangeModified},
	}
	if got := s.packageReleases(changes); len(got) != 0 {
		t.Errorf("outside a Drupal site: %+v", got)
	}
	s.report.Application = discovery.Application{Path: "/var/www/site", Framework: "drupal"}
	want := []PackageRelease{{Root: "/var/www/site/web/modules/contrib/token", Ecosystem: EcosystemDrupalProject, Slug: "token", Version: "8.x-1.18"}}
	if got := s.packageReleases(changes); !slices.Equal(got, want) {
		t.Errorf("releases = %+v", got)
	}
}
