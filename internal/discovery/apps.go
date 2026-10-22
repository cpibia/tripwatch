package discovery

import (
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
)

// Profile describes how to recognise an application stack and where its parts live. Paths
// are relative to the application root and may be globs.
type Profile struct {
	Name    string
	Markers []string
	// WebRoot is the directory a correctly configured server exposes.
	WebRoot string
	// UploadDirs hold user-supplied files: nothing in them should ever be executable.
	UploadDirs []string
	// DataDirs change at runtime (uploads, caches, logs, sessions) and are left out of the
	// code tree hash; they are still scanned.
	DataDirs       []string
	VersionFile    string
	VersionPattern *regexp.Regexp
}

// Profiles are tried in order; specific stacks come before the generic ones they also match.
var Profiles = []Profile{
	{
		Name:           "magento",
		Markers:        []string{"bin/magento", "app/etc/di.xml"},
		WebRoot:        "pub",
		UploadDirs:     []string{"pub/media"},
		DataDirs:       []string{"pub/media", "var"},
		VersionFile:    "vendor/magento/magento2-base/composer.json",
		VersionPattern: regexp.MustCompile(`"version":\s*"([^"]+)"`),
	},
	{
		Name:           "wordpress",
		Markers:        []string{"wp-includes/version.php"},
		WebRoot:        ".",
		UploadDirs:     []string{"wp-content/uploads"},
		DataDirs:       []string{"wp-content/uploads", "wp-content/cache", "wp-content/upgrade"},
		VersionFile:    "wp-includes/version.php",
		VersionPattern: regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`),
	},
	{
		Name:           "drupal",
		Markers:        []string{"core/lib/Drupal.php"},
		WebRoot:        ".",
		UploadDirs:     []string{"sites/*/files"},
		DataDirs:       []string{"sites/*/files"},
		VersionFile:    "core/lib/Drupal.php",
		VersionPattern: regexp.MustCompile(`const VERSION = '([^']+)'`),
	},
	{
		Name:           "drupal7",
		Markers:        []string{"includes/bootstrap.inc", "misc/drupal.js"},
		WebRoot:        ".",
		UploadDirs:     []string{"sites/*/files"},
		DataDirs:       []string{"sites/*/files"},
		VersionFile:    "includes/bootstrap.inc",
		VersionPattern: regexp.MustCompile(`define\('VERSION', '([^']+)'\)`),
	},
	{
		Name:           "laravel",
		Markers:        []string{"artisan", "bootstrap/app.php"},
		WebRoot:        "public",
		UploadDirs:     []string{"storage/app/public"},
		DataDirs:       []string{"storage", "bootstrap/cache"},
		VersionFile:    "vendor/laravel/framework/src/Illuminate/Foundation/Application.php",
		VersionPattern: regexp.MustCompile(`const VERSION = '([^']+)'`),
	},
	{
		Name:           "symfony",
		Markers:        []string{"bin/console", "config/bundles.php"},
		WebRoot:        "public",
		DataDirs:       []string{"var"},
		VersionFile:    "vendor/symfony/http-kernel/Kernel.php",
		VersionPattern: regexp.MustCompile(`const VERSION = '([^']+)'`),
	},
	{
		Name:       "django",
		Markers:    []string{"manage.py"},
		UploadDirs: []string{"media"},
		DataDirs:   []string{"media", "staticfiles"},
	},
	{
		Name:       "rails",
		Markers:    []string{"config/application.rb", "Gemfile"},
		WebRoot:    "public",
		UploadDirs: []string{"public/uploads", "storage"},
		DataDirs:   []string{"public/uploads", "storage", "tmp", "log"},
	},
	{Name: "java-webapp", Markers: []string{"WEB-INF/web.xml"}, WebRoot: "."},
	{Name: "java", Markers: []string{"pom.xml"}},
	{Name: "java", Markers: []string{"build.gradle"}},
	{Name: "java", Markers: []string{"build.gradle.kts"}},
	{Name: "rust", Markers: []string{"Cargo.toml"}},
	{Name: "go", Markers: []string{"go.mod"}},
	{Name: "node", Markers: []string{"package.json"}},
	{Name: "python", Markers: []string{"pyproject.toml"}},
	{Name: "python", Markers: []string{"requirements.txt"}},
	{Name: "php", Markers: []string{"composer.json"}, WebRoot: "."},
	{Name: "php", Markers: []string{"index.php"}, WebRoot: "."},
	{Name: "static", Markers: []string{"index.html"}, WebRoot: "."},
}

// GenericUploadDirs are directory names treated as upload or data directories in any stack.
var GenericUploadDirs = []string{"uploads", "upload", "media", "files", "images", "img", "attachments", "tmp", "temp", "cache"}

// Application is a deployed application found on disk.
type Application struct {
	Path      string   `json:"path"`
	Framework string   `json:"framework"`
	Version   string   `json:"version,omitempty"`
	Sites     []string `json:"sites,omitempty"`
	Profile   *Profile `json:"-"`
}

// candidateRoots are where applications usually live.
var candidateRoots = []string{"var/www", "srv", "opt", "home", "usr/share/nginx/html", "var/lib/docker/volumes"}

// skipDirs are never descended into while looking for applications.
var skipDirs = []string{"vendor", "node_modules", "bower_components", "proc", "sys", "dev"}

const maxAppDepth = 5

// FindApplications looks for applications under the usual roots and under the document roots
// of the given sites (and their parents, since frameworks serve a subdirectory such as pub or
// public). A document root no profile recognises becomes an application of kind "unknown".
func FindApplications(fsys fs.FS, sites []Site) []Application {
	found := map[string]Application{}
	for _, root := range candidateRoots {
		walkApps(fsys, root, 0, found)
	}

	// Outermost first: the Magento root must be found before its pub directory, which on its
	// own looks like a plain PHP application.
	for _, s := range sites {
		r := siteRoot(s)
		if r == "" {
			continue
		}
		for _, dir := range []string{path.Dir(path.Dir(r)), path.Dir(r), r} {
			if dir == "." || covering(found, dir) != "" {
				continue
			}
			if p := matchProfile(fsys, dir); p != nil {
				found[dir] = Application{Path: "/" + dir, Framework: p.Name, Version: readVersion(fsys, dir, p), Profile: p}
				break
			}
		}
	}

	for _, s := range sites {
		r := siteRoot(s)
		if r == "" || !exists(fsys, r) || covering(found, r) != "" {
			continue
		}
		found[r] = Application{Path: "/" + r, Framework: "unknown", Profile: &Profile{Name: "unknown", WebRoot: "."}}
	}

	apps := make([]Application, 0, len(found))
	for _, key := range sortedKeys(found) {
		app := found[key]
		for _, s := range sites {
			r := siteRoot(s)
			if r != "" && covering(map[string]Application{key: app}, r) != "" && len(s.Names) > 0 {
				app.Sites = append(app.Sites, s.Names[0])
			}
		}
		apps = append(apps, app)
	}
	return apps
}

// siteRoot returns the document root as a Source path, or "" when it is unset or still holds
// a variable that could not be resolved.
func siteRoot(s Site) string {
	if s.Root == "" || strings.Contains(s.Root, "$") {
		return ""
	}
	return strings.TrimPrefix(path.Clean(s.Root), "/")
}

func walkApps(fsys fs.FS, dir string, depth int, found map[string]Application) {
	if _, seen := found[dir]; seen || depth > maxAppDepth {
		return
	}
	if covering(found, dir) != "" {
		return
	}
	if p := matchProfile(fsys, dir); p != nil {
		found[dir] = Application{Path: "/" + dir, Framework: p.Name, Version: readVersion(fsys, dir, p), Profile: p}
		return
	}
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || slices.Contains(skipDirs, e.Name()) {
			continue
		}
		walkApps(fsys, path.Join(dir, e.Name()), depth+1, found)
	}
}

func matchProfile(fsys fs.FS, dir string) *Profile {
	for i := range Profiles {
		p := &Profiles[i]
		if !slices.ContainsFunc(p.Markers, func(m string) bool { return !exists(fsys, path.Join(dir, m)) }) {
			return p
		}
	}
	return nil
}

func readVersion(fsys fs.FS, dir string, p *Profile) string {
	if p.VersionFile == "" {
		return ""
	}
	data, err := fs.ReadFile(fsys, path.Join(dir, p.VersionFile))
	if err != nil {
		return ""
	}
	if m := p.VersionPattern.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// covering returns the application that contains dir, if any.
func covering(apps map[string]Application, dir string) string {
	for root := range apps {
		if dir == root || strings.HasPrefix(dir, root+"/") {
			return root
		}
	}
	return ""
}

func sortedKeys(m map[string]Application) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
