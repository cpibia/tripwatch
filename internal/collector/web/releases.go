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
	EcosystemDrupalProject   = "drupal-project"
)

// Bounds of the releases read in one application: packages, files looked at for a plugin's header
// in its directory, and the start of each file read for it.
const (
	maxPackageReleases = 200
	maxHeaderFiles     = 50
	maxHeaderReads     = 1000
	headerBytes        = 8 << 10
)

var (
	wpLocale   = regexp.MustCompile(`\$wp_local_package\s*=\s*['"]([a-z]{2,3}(?:_[A-Z]{2})?(?:_[a-z]{2,10})?)['"]`)
	pluginName = regexp.MustCompile(`(?mi)^[ \t/*#@]*Plugin Name:`)
	themeName  = regexp.MustCompile(`(?mi)^[ \t/*#@]*Theme Name:`)
	// drupal.org's packaging writes the project and its version into each .info.yml.
	drupalInfoProject = regexp.MustCompile(`(?m)^project:[ \t]*['"]?([a-z][a-z0-9_]{0,99})['"]?[ \t]*\r?$`)
	drupalInfoVersion = regexp.MustCompile(`(?m)^version:[ \t]*['"]?([0-9][0-9A-Za-z.+-]{0,31})['"]?[ \t]*\r?$`)
	pluginVersion     = regexp.MustCompile(`(?mi)^[ \t/*#@]*Version:[ \t]*([0-9][0-9A-Za-z.+-]{0,31})[ \t]*\r?$`)
)

// releases names the release of WordPress itself and of every plugin, theme or drupal.org project
// installed in the application, those with changed files first so that the bound keeps them: the
// verifier remembers them, to tell a package installed or downgraded since.
func (s *scanner) releases(changes []FileChange) []PackageRelease {
	var out []PackageRelease
	if core, ok := s.coreRelease(); ok {
		out = append(out, core)
	}
	paths := make([]FileChange, 0, len(changes))
	paths = append(paths, changes...)
	for _, dir := range s.packageParents() {
		entries, err := fs.ReadDir(s.src.FS, strings.TrimPrefix(dir, "/"))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				// A path inside the package is all packageRoot needs.
				paths = append(paths, FileChange{Path: dir + "/" + e.Name() + "/."})
			}
		}
	}
	return append(out, s.packageReleases(paths)...)
}

// packageParents are the directories whose children are packages with public releases.
func (s *scanner) packageParents() []string {
	app := s.report.Application
	switch app.Framework {
	case "wordpress":
		return []string{app.Path + "/wp-content/plugins", app.Path + "/wp-content/themes"}
	case "drupal":
		var out []string
		for _, docroot := range []string{"", "/web", "/docroot"} {
			for _, kind := range []string{"modules", "themes", "profiles"} {
				out = append(out, app.Path+docroot+"/"+kind+"/contrib")
			}
		}
		return out
	}
	return nil
}

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
		switch kind {
		case EcosystemWordPressTheme:
			version = s.themeVersion(root)
		case EcosystemDrupalProject:
			if s.report.Framework != "drupal" {
				continue
			}
			slug, version = s.drupalRelease(root, slug)
		default:
			version = s.pluginVersion(root, slug)
		}
		if version != "" {
			out = append(out, PackageRelease{Root: root, Ecosystem: kind, Slug: slug, Version: version})
		}
	}
	return out
}

// drupalRelease reads a drupal.org project's short name and version from the .info.yml named
// after its directory, as drupal.org's packaging writes them; none for a checkout without them.
func (s *scanner) drupalRelease(root, dir string) (project, version string) {
	head, ok := s.head(path.Join(strings.TrimPrefix(root, "/"), dir+".info.yml"))
	if !ok {
		return "", ""
	}
	p, v := drupalInfoProject.FindSubmatch(head), drupalInfoVersion.FindSubmatch(head)
	if p == nil || v == nil {
		return "", ""
	}
	return string(p[1]), string(v[1])
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

// coreRelease names the WordPress release of an install: the version discovery read, the locale
// from wp-includes/version.php (en_US without one).
func (s *scanner) coreRelease() (PackageRelease, bool) {
	app := s.report.Application
	if app.Framework != "wordpress" || app.Version == "" {
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
	for _, d := range []struct{ dir, kind string }{
		{"/wp-content/plugins/", EcosystemWordPressPlugin}, {"/wp-content/themes/", EcosystemWordPressTheme},
		{"/modules/contrib/", EcosystemDrupalProject}, {"/themes/contrib/", EcosystemDrupalProject}, {"/profiles/contrib/", EcosystemDrupalProject},
	} {
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

// head reads the first headerBytes of a file, within maxHeaderReads files an application.
func (s *scanner) head(name string) ([]byte, bool) {
	if s.headerReads++; s.headerReads > maxHeaderReads {
		return nil, false
	}
	f, err := s.src.FS.Open(name)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	head, err := io.ReadAll(io.LimitReader(f, headerBytes))
	return head, err == nil
}
