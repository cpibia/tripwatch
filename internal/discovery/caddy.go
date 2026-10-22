package discovery

import (
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

const caddyfile = "etc/caddy/Caddyfile"

// CaddySites reads the site blocks of the Caddyfile. Only the directives that matter here are
// interpreted: root, php_fastcgi, reverse_proxy and log output files.
func CaddySites(fsys fs.FS) ([]Site, []string, collector.Issues) {
	var issues collector.Issues
	if !exists(fsys, caddyfile) {
		return nil, nil, issues
	}
	budget := newConfigBudget("caddy")
	lines := caddyLines(fsys, caddyfile, budget, &issues)

	var sites []Site
	var site *Site
	depth := 0
	inLog := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		opens := strings.HasSuffix(line, "{")
		fields := strings.Fields(strings.TrimSuffix(line, "{"))

		if line == "}" {
			depth--
			switch {
			case depth == 0 && site != nil:
				sites = append(sites, *site)
				site = nil
			case depth == 1:
				inLog = false
			}
			continue
		}

		if depth == 0 {
			// A label-less block is the global options; (name) is a snippet.
			if opens && len(fields) > 0 && !strings.HasPrefix(fields[0], "(") {
				site = &Site{Server: ServerCaddy, Config: "/" + caddyfile}
				for _, f := range fields {
					site.Names = append(site.Names, strings.TrimSuffix(f, ","))
				}
			}
		} else if site != nil && len(fields) > 0 {
			switch {
			case fields[0] == "root" && depth == 1:
				site.Root = fields[len(fields)-1]
			case fields[0] == "php_fastcgi":
				site.ScriptExtensions = []string{".php"}
				if len(fields) > 1 && !slices.Contains(site.Upstreams, fields[1]) {
					site.Upstreams = append(site.Upstreams, fields[1])
				}
			case fields[0] == "reverse_proxy" && len(fields) > 1:
				site.Upstreams = append(site.Upstreams, fields[len(fields)-1])
			case fields[0] == "log":
				inLog = opens
			case inLog && fields[0] == "output" && len(fields) > 2 && fields[1] == "file":
				site.AccessLogs = append(site.AccessLogs, fields[2])
			}
		}
		if opens {
			depth++
		}
	}
	return sites, budget.files, issues
}

// caddyLines returns the lines of a Caddyfile with import directives naming files replaced by
// the content of those files. Imports of snippets, which name no file, stay as they are.
func caddyLines(fsys fs.FS, name string, budget *configBudget, issues *collector.Issues) []string {
	if !budget.enter(name, issues) {
		return nil
	}
	defer budget.leave(name)
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		issues.Add(err)
		return nil
	}
	if !budget.consume(len(data), issues) {
		return nil
	}

	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "import" {
			pattern := fields[1]
			if !path.IsAbs(pattern) {
				pattern = path.Join("/"+path.Dir(caddyfile), pattern)
			}
			if matches := collector.Glob(fsys, collector.Rel(pattern)); len(matches) > 0 {
				for _, m := range matches {
					out = append(out, caddyLines(fsys, m, budget, issues)...)
				}
				continue
			}
		}
		out = append(out, line)
	}
	return out
}
