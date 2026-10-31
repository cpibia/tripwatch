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

// EcosystemWordPressPlugin is a plugin in a WordPress install's wp-content/plugins.
const EcosystemWordPressPlugin = "wordpress-plugin"

// Bounds of the releases read in one application: packages, files looked at for a plugin's header
// in its directory, and the start of each file read for it.
const (
	maxPackageReleases = 200
	maxHeaderFiles     = 50
	headerBytes        = 8 << 10
)

var (
	pluginName    = regexp.MustCompile(`(?mi)^[ \t/*#@]*Plugin Name:`)
	pluginVersion = regexp.MustCompile(`(?mi)^[ \t/*#@]*Version:[ \t]*([0-9][0-9A-Za-z.+-]{0,31})[ \t]*\r?$`)
)

// pluginReleases names the release of each WordPress plugin a changed file belongs to, from the
// plugin's header: the main file is the one named after the plugin's directory, or the first PHP
// file of the directory with a "Plugin Name:" header, as WordPress finds it.
func (s *scanner) pluginReleases(changes []FileChange) []PackageRelease {
	var out []PackageRelease
	seen := map[string]bool{}
	for _, c := range changes {
		root, slug, ok := pluginRoot(c.Path)
		if !ok || seen[root] {
			continue
		}
		seen[root] = true
		if len(out) == maxPackageReleases {
			break
		}
		if version := s.pluginVersion(root, slug); version != "" {
			out = append(out, PackageRelease{Root: root, Ecosystem: EcosystemWordPressPlugin, Slug: slug, Version: version})
		}
	}
	return out
}

// pluginRoot returns the directory of the plugin p is in, and the plugin's slug.
func pluginRoot(p string) (root, slug string, ok bool) {
	i := strings.Index(p, "/wp-content/plugins/")
	if i < 0 {
		return "", "", false
	}
	rest := p[i+len("/wp-content/plugins/"):]
	slug, _, found := strings.Cut(rest, "/")
	if !found || slug == "" {
		return "", "", false
	}
	return p[:i] + "/wp-content/plugins/" + slug, slug, true
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
	f, err := s.src.FS.Open(name)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	head, err := io.ReadAll(io.LimitReader(f, headerBytes))
	if err != nil || !pluginName.Match(head) {
		return "", false
	}
	if m := pluginVersion.FindSubmatch(head); m != nil {
		return string(m[1]), true
	}
	return "", false
}
