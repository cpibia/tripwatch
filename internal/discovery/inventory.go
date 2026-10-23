package discovery

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

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
	Sites []Site `json:"sites"`
	// ConfigFiles are the web server configuration files read, with owner and mode: one an
	// unprivileged user can write lets that user change what the server executes.
	ConfigFiles []collector.File `json:"config_files"`
	// StaleConfig lists configuration files changed after the web server process started: the
	// running configuration may differ from the one on disk, so reachability read from disk is
	// not to be trusted for them.
	StaleConfig  []string         `json:"stale_config,omitempty"`
	Applications []Application    `json:"applications"`
	Runtimes     []string         `json:"runtimes"`
	Issues       collector.Issues `json:"issues,omitempty"`
}

// Inspect builds the web inventory: sites from every web server configuration present,
// applications on disk and the runtimes currently running.
func Inspect(fsys fs.FS) Inventory {
	var inv Inventory
	servers := []struct {
		parse     func(fs.FS) ([]Site, []string, collector.Issues)
		processes []string
		// reloadsWorkers: a reload starts new workers and nothing else does, so the newest
		// process tells when the configuration was read. Apache's children come and go all the
		// time and Caddy reloads in place: for them only the oldest process counts.
		reloadsWorkers bool
	}{
		{NginxSites, []string{"nginx"}, true},
		{ApacheSites, []string{"apache2", "httpd"}, false},
		{CaddySites, []string{"caddy"}, false},
	}
	for _, srv := range servers {
		sites, files, issues := srv.parse(fsys)
		inv.Sites = append(inv.Sites, sites...)
		inv.Issues = append(inv.Issues, issues...)
		started, running := configLoaded(fsys, srv.processes, srv.reloadsWorkers)
		for _, name := range files {
			f, err := collector.Describe(collector.Source{FS: fsys}, name)
			inv.Issues.Add(err)
			if f.Path == "" {
				continue
			}
			inv.ConfigFiles = append(inv.ConfigFiles, f)
			if running && changedAfter(fsys, name, started) {
				inv.StaleConfig = append(inv.StaleConfig, f.Path)
				inv.Issues = append(inv.Issues, fmt.Sprintf("%s changed after the web server started: the running configuration may differ", f.Path))
			}
		}
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

// userHZ is the unit of process start times in /proc/<pid>/stat on every mainstream Linux.
const userHZ = 100

// serverProcess is a process of a web server, as /proc shows it.
type serverProcess struct {
	pid, ppid, uid int
	start          time.Time
}

// configLoaded returns when the web server last read its configuration. Only processes running
// the server's executable from the system's directories count: a process can give itself any
// name. Where a reload starts new workers (workers), it is the oldest child of a master running
// as root, the workers of the previous configuration having exited; otherwise, and when the
// master has no child, the oldest process. Start times come from /proc/<pid>/stat (ticks since
// boot) and the boot time in /proc/stat: the timestamps of /proc entries themselves are not
// usable, procfs sets them at first lookup.
func configLoaded(fsys fs.FS, names []string, workers bool) (time.Time, bool) {
	boot, ok := bootTime(fsys)
	if !ok {
		return time.Time{}, false
	}
	entries, err := fs.ReadDir(fsys, "proc")
	if err != nil {
		return time.Time{}, false
	}
	var procs []serverProcess
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := "proc/" + e.Name() + "/"
		exe, err := fs.ReadLink(fsys, dir+"exe")
		if err != nil || !slices.Contains(names, path.Base(exe)) || !systemExecutable(exe) {
			continue
		}
		stat, err := fs.ReadFile(fsys, dir+"stat")
		if err != nil {
			continue
		}
		i := bytes.LastIndexByte(stat, ')')
		if i < 0 {
			continue
		}
		fields := strings.Fields(string(stat[i+1:]))
		if len(fields) < 20 {
			continue
		}
		ticks, err := strconv.ParseInt(fields[19], 10, 64)
		if err != nil {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1])
		procs = append(procs, serverProcess{pid: pid, ppid: ppid, uid: processUID(fsys, dir), start: boot.Add(time.Duration(ticks) * time.Second / userHZ)})
	}
	if len(procs) == 0 {
		return time.Time{}, false
	}
	oldest := func(ps []serverProcess) time.Time {
		var t time.Time
		for _, p := range ps {
			if t.IsZero() || p.start.Before(t) {
				t = p.start
			}
		}
		return t
	}
	if workers {
		pids := map[int]bool{}
		for _, p := range procs {
			pids[p.pid] = true
		}
		var loaded time.Time
		for _, m := range procs {
			if m.uid != 0 || pids[m.ppid] {
				continue
			}
			var children []serverProcess
			for _, c := range procs {
				if c.ppid == m.pid {
					children = append(children, c)
				}
			}
			t := m.start
			if len(children) > 0 {
				t = oldest(children)
			}
			if t.After(loaded) {
				loaded = t
			}
		}
		if !loaded.IsZero() {
			return loaded, true
		}
	}
	return oldest(procs), true
}

// systemExecutable reports whether a path lies in the system's binary directories.
func systemExecutable(p string) bool {
	return slices.ContainsFunc([]string{"/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/", "/usr/local/sbin/", "/usr/local/bin/", "/usr/lib/", "/opt/"}, func(d string) bool { return strings.HasPrefix(p, d) })
}

func processUID(fsys fs.FS, dir string) int {
	status, err := fs.ReadFile(fsys, dir+"status")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				if n, err := strconv.Atoi(f[0]); err == nil {
					return n
				}
			}
		}
	}
	return -1
}

func bootTime(fsys fs.FS) (time.Time, bool) {
	lines, err := collector.ReadLines(fsys, "proc/stat")
	if err != nil {
		return time.Time{}, false
	}
	for _, line := range lines {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			if sec, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return time.Unix(sec, 0), true
			}
		}
	}
	return time.Time{}, false
}

// changedAfter compares with the change time where available: a file's owner can set its
// modification time back, not its change time.
func changedAfter(fsys fs.FS, name string, t time.Time) bool {
	info, err := fs.Stat(fsys, name)
	if err != nil {
		return false
	}
	if ctime, ok := collector.ChangeTime(info); ok {
		return time.Unix(0, ctime).After(t)
	}
	return info.ModTime().After(t)
}
