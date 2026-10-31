package web

import (
	"io"
	"io/fs"
	"path"
	"regexp"
	"strings"
)

// PackageRelease is the public release a package of an application says it is: the verifier
// compares the package's changed files with that release as published. Root is the package's
// directory, Ecosystem where its releases are published, Slug and Version as the package's own
// header gives them, which whoever writes there may forge: the verifier only ever lowers what
// matches the release byte for byte.
type PackageRelease struct {
	Root      string `json:"root"`
	Ecosystem string `json:"ecosystem"`
	Slug      string `json:"slug"`
	Version   string `json:"version"`
}

// Ecosystems of the releases: a plugin in a WordPress install's wp-content/plugins, and WordPress
// itself, whose Slug is the locale of the release.
const (
	EcosystemWordPressPlugin = "wordpress-plugin"
	EcosystemWordPressCore   = "wordpress-core"
	EcosystemWordPressTheme  = "wordpress-theme"
)

// Bounds of the releases read in one application: packages, files looked at for a plugin's header
// in its directory, and the start of each file read for it.
const (
	maxPackageReleases = 200
	maxHeaderFiles     = 50
	headerBytes        = 8 << 10
)

var (
	wpLocale      = regexp.MustCompile(`\$wp_local_package\s*=\s*['"]([a-z]{2,3}(?:_[A-Z]{2})?(?:_[a-z]{2,10})?)['"]`)
	pluginName    = regexp.MustCompile(`(?mi)^[ \t/*#@]*Plugin Name:`)
	themeName     = regexp.MustCompile(`(?mi)^[ \t/*#@]*Theme Name:`)
	pluginVersion = regexp.MustCompile(`(?mi)^[ \t/*#@]*Version:[ \t]*([0-9][0-9A-Za-z.+-]{0,31})[ \t]*\r?$`)
)

// packageReleases names the release of each WordPress plugin or theme a changed file belongs to,
// from its header: a plugin's main file is the one named after its directory, or the first PHP
// file of the directory with a "Plugin Name:" header, as WordPress finds it; a theme's is its
// style.css.
func (s *scanner) packageReleases(changes []FileChange) []PackageRelease {
	var out []PackageRelease
	seen := map[string]bool{}
	for _, c := range changes {
		root, slug, kind, ok := packageRoot(c.Path)
		if !ok || seen[root] {
			continue
		}
		seen[root] = true
		if len(out) == maxPackageReleases {
			break
		}
		var version string
		if kind == EcosystemWordPressTheme {
			version = s.themeVersion(root)
		} else {
			version = s.pluginVersion(root, slug)
		}
		if version != "" {
			out = append(out, PackageRelease{Root: root, Ecosystem: kind, Slug: slug, Version: version})
		}
	}
	return out
}

// themeVersion reads a theme's version from the header of its style.css.
func (s *scanner) themeVersion(root string) string {
	head, ok := s.head(path.Join(strings.TrimPrefix(root, "/"), "style.css"))
	if !ok || !themeName.Match(head) {
		return ""
	}
	if m := pluginVersion.FindSubmatch(head); m != nil {
		return string(m[1])
	}
	return ""
}

// coreRelease names the WordPress release of an install whose files outside wp-content changed:
// the version discovery read, the locale from wp-includes/version.php (en_US without one).
func (s *scanner) coreRelease(changes []FileChange) (PackageRelease, bool) {
	app := s.report.Application
	if app.Framework != "wordpress" || app.Version == "" {
		return PackageRelease{}, false
	}
	core := false
	for _, c := range changes {
		if rest, ok := strings.CutPrefix(c.Path, app.Path+"/"); ok && !strings.HasPrefix(rest, "wp-content/") {
			core = true
			break
		}
	}
	if !core {
		return PackageRelease{}, false
	}
	locale := "en_US"
	if head, ok := s.head(path.Join(strings.TrimPrefix(app.Path, "/"), "wp-includes/version.php")); ok {
		if m := wpLocale.FindSubmatch(head); m != nil {
			locale = string(m[1])
		}
	}
	return PackageRelease{Root: app.Path, Ecosystem: EcosystemWordPressCore, Slug: locale, Version: app.Version}, true
}

// packageRoot returns the directory of the plugin or theme p is in, its slug and its ecosystem.
func packageRoot(p string) (root, slug, kind string, ok bool) {
	for _, d := range []struct{ dir, kind string }{{"/wp-content/plugins/", EcosystemWordPressPlugin}, {"/wp-content/themes/", EcosystemWordPressTheme}} {
		i := strings.Index(p, d.dir)
		if i < 0 {
			continue
		}
		slug, _, found := strings.Cut(p[i+len(d.dir):], "/")
		if !found || slug == "" {
			return "", "", "", false
		}
		return p[:i] + d.dir + slug, slug, d.kind, true
	}
	return "", "", "", false
}

func (s *scanner) pluginVersion(root, slug string) string {
	dir := strings.TrimPrefix(root, "/")
	if v, ok := s.headerVersion(path.Join(dir, slug+".php")); ok {
		return v
	}
	entries, err := fs.ReadDir(s.src.FS, dir)
	if err != nil {
		return ""
	}
	looked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".php") || e.Name() == slug+".php" {
			continue
		}
		if looked++; looked > maxHeaderFiles {
			break
		}
		if v, ok := s.headerVersion(path.Join(dir, e.Name())); ok {
			return v
		}
	}
	return ""
}

// headerVersion reads the version of a plugin's header at the start of a file, and whether the
// file has one.
func (s *scanner) headerVersion(name string) (string, bool) {
	head, ok := s.head(name)
	if !ok || !pluginName.Match(head) {
		return "", false
	}
	if m := pluginVersion.FindSubmatch(head); m != nil {
		return string(m[1]), true
	}
	return "", false
}

// head reads the first headerBytes of a file.
func (s *scanner) head(name string) ([]byte, bool) {
	f, err := s.src.FS.Open(name)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	head, err := io.ReadAll(io.LimitReader(f, headerBytes))
	return head, err == nil
}
