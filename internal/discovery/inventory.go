package discovery

import (
	"io/fs"
	"slices"
	"strconv"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

// runtimeNames maps process names to the web servers and application runtimes they belong to.
var runtimeNames = map[string]string{
	"nginx": "nginx", "apache2": "apache", "httpd": "apache", "caddy": "caddy", "traefik": "traefik",
	"haproxy": "haproxy", "lighttpd": "lighttpd", "envoy": "envoy",
	"php-fpm": "php-fpm", "php": "php", "gunicorn": "gunicorn", "uwsgi": "uwsgi", "uvicorn": "uvicorn",
	"node": "node", "java": "java", "ruby": "ruby", "puma": "puma", "dotnet": "dotnet",
	"python": "python", "mysqld": "mysql", "mariadbd": "mariadb", "postgres": "postgres",
	"redis-server": "redis", "memcached": "memcached", "elasticsearch": "elasticsearch",
}

// Inventory is what runs on the observed machine, as far as the web is concerned.
type Inventory struct {
	Sites        []Site           `json:"sites"`
	Applications []Application    `json:"applications"`
	Runtimes     []string         `json:"runtimes"`
	Issues       collector.Issues `json:"issues,omitempty"`
}

// Inspect builds the web inventory: sites from every web server configuration present,
// applications on disk and the runtimes currently running.
func Inspect(fsys fs.FS) Inventory {
	var inv Inventory
	for _, parse := range []func(fs.FS) ([]Site, collector.Issues){NginxSites, ApacheSites, CaddySites} {
		sites, issues := parse(fsys)
		inv.Sites = append(inv.Sites, sites...)
		inv.Issues = append(inv.Issues, issues...)
	}
	inv.Applications = FindApplications(fsys, inv.Sites)
	inv.Runtimes = runningRuntimes(fsys)
	return inv
}

func runningRuntimes(fsys fs.FS) []string {
	entries, err := fs.ReadDir(fsys, "proc")
	if err != nil {
		return nil
	}
	found := []string{}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		comm, err := fs.ReadFile(fsys, "proc/"+e.Name()+"/comm")
		if err != nil {
			continue
		}
		if name, ok := runtimeName(strings.TrimSpace(string(comm))); ok && !slices.Contains(found, name) {
			found = append(found, name)
		}
	}
	slices.Sort(found)
	return found
}

// runtimeName normalises versioned process names such as php-fpm8.1 or python3.11.
func runtimeName(comm string) (string, bool) {
	if name, ok := runtimeNames[comm]; ok {
		return name, true
	}
	base := strings.TrimRight(comm, "0123456789.")
	if strings.HasPrefix(comm, "php-fpm") {
		base = "php-fpm"
	}
	name, ok := runtimeNames[base]
	return name, ok
}
