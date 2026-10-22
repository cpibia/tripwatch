package discovery

import (
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

// apacheConfigs pairs each main configuration file with its ServerRoot.
var apacheConfigs = []struct{ conf, root string }{
	{"etc/apache2/apache2.conf", "etc/apache2"},
	{"etc/httpd/conf/httpd.conf", "etc/httpd"},
	{"usr/local/apache2/conf/httpd.conf", "usr/local/apache2"},
}

// Extensions the stock PHP handlers match (".+\.ph(ar|p|tml)$").
var phpHandlerExtensions = []string{".php", ".phar", ".phtml"}

var (
	apacheVarRef   = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}`)
	apacheExportRe = regexp.MustCompile(`^\s*export\s+([A-Za-z0-9_]+)=(.*)$`)
	// Newer Debian envvars set defaults with the shell idiom ": ${NAME:=value}".
	apacheDefaultRe = regexp.MustCompile(`^\s*:\s*\$\{([A-Za-z0-9_]+):=([^}]*)\}`)
)

type apacheParser struct {
	fsys   fs.FS
	root   string
	vars   map[string]string
	issues *collector.Issues
	php    bool
	sites  []Site
	main   Site
	vhost  *Site
}

// ApacheSites parses the first Apache httpd configuration found. The main server counts as
// a site when it has a DocumentRoot outside any VirtualHost.
func ApacheSites(fsys fs.FS) ([]Site, collector.Issues) {
	var issues collector.Issues
	for _, c := range apacheConfigs {
		if !exists(fsys, c.conf) {
			continue
		}
		p := &apacheParser{fsys: fsys, root: c.root, vars: apacheEnv(fsys, c.root), issues: &issues}
		p.main = Site{Server: ServerApache, Config: "/" + c.conf}
		p.parseFile(c.conf, 0)

		sites := p.sites
		if p.main.Root != "" {
			sites = append([]Site{p.main}, sites...)
		}
		if p.php {
			for i := range sites {
				sites[i].ScriptExtensions = phpHandlerExtensions
			}
		}
		return sites, issues
	}
	return nil, issues
}

// apacheEnv reads the variables Debian's apache2ctl exports before starting httpd.
func apacheEnv(fsys fs.FS, root string) map[string]string {
	vars := map[string]string{}
	lines, _ := collector.ReadLines(fsys, path.Join(root, "envvars"))
	for _, line := range lines {
		m := apacheExportRe.FindStringSubmatch(line)
		if m == nil {
			m = apacheDefaultRe.FindStringSubmatch(line)
		}
		if m != nil {
			value := strings.Trim(strings.TrimSpace(m[2]), `"'`)
			vars[m[1]] = strings.ReplaceAll(value, "$SUFFIX", "")
		}
	}
	return vars
}

func (p *apacheParser) parseFile(name string, depth int) {
	lines, err := collector.ReadLines(p.fsys, name)
	if err != nil {
		p.issues.Add(err)
		return
	}

	var logical string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if cont, ok := strings.CutSuffix(line, "\\"); ok {
			logical += cont + " "
			continue
		}
		logical += line
		p.directive(logical, name, depth)
		logical = ""
	}
}

func (p *apacheParser) directive(line, file string, depth int) {
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	line = apacheVarRef.ReplaceAllStringFunc(line, func(ref string) string {
		if v, ok := p.vars[ref[2:len(ref)-1]]; ok {
			return v
		}
		return ref
	})

	if strings.HasPrefix(line, "</") {
		if strings.EqualFold(strings.TrimSuffix(line[2:], ">"), "VirtualHost") && p.vhost != nil {
			p.sites = append(p.sites, *p.vhost)
			p.vhost = nil
		}
		return
	}
	if strings.HasPrefix(line, "<") {
		fields := splitApacheArgs(strings.TrimSuffix(line[1:], ">"))
		if len(fields) > 0 && strings.EqualFold(fields[0], "VirtualHost") {
			p.vhost = &Site{Server: ServerApache, Config: "/" + file, Listen: fields[1:]}
		}
		p.detectPHP(line)
		return
	}

	fields := splitApacheArgs(line)
	if len(fields) == 0 {
		return
	}
	name, args := strings.ToLower(fields[0]), fields[1:]
	site := &p.main
	if p.vhost != nil {
		site = p.vhost
	}

	switch name {
	case "include", "includeoptional":
		if len(args) > 0 {
			p.include(args[0], depth)
		}
	case "define":
		if len(args) > 1 {
			p.vars[args[0]] = args[1]
		}
	case "servername":
		site.Names = append(site.Names, first(args))
	case "serveralias":
		site.Names = append(site.Names, args...)
	case "documentroot":
		site.Root = absolute(first(args), p.root)
	case "customlog", "transferlog":
		if target := first(args); target != "" && !strings.HasPrefix(target, "|") {
			site.AccessLogs = append(site.AccessLogs, absolute(target, p.root))
		}
	case "errorlog":
		if target := first(args); target != "" && !strings.HasPrefix(target, "|") && !strings.HasPrefix(target, "syslog") {
			site.ErrorLogs = append(site.ErrorLogs, absolute(target, p.root))
		}
	case "proxypass":
		if len(args) > 1 && !slices.Contains(site.Upstreams, args[1]) {
			site.Upstreams = append(site.Upstreams, args[1])
		}
	}
	p.detectPHP(line)
}

// detectPHP recognises mod_php and the PHP-FPM handler (SetHandler "proxy:...fcgi").
func (p *apacheParser) detectPHP(line string) {
	l := strings.ToLower(line)
	switch {
	case strings.HasPrefix(l, "loadmodule php"):
		p.php = true
	case strings.HasPrefix(l, "sethandler") && strings.Contains(l, "proxy:") && (strings.Contains(l, "fcgi") || strings.Contains(l, "php")):
		p.php = true
	case (strings.HasPrefix(l, "addhandler") || strings.HasPrefix(l, "addtype")) && strings.Contains(l, "php"):
		p.php = true
	}
}

// include follows Include and IncludeOptional: a glob, or a directory whose files are all
// read, relative to ServerRoot.
func (p *apacheParser) include(pattern string, depth int) {
	if depth >= maxIncludeDepth {
		*p.issues = append(*p.issues, "apache: include depth exceeded at "+pattern)
		return
	}
	rel := collector.Rel(absolute(pattern, p.root))
	if info, err := fs.Stat(p.fsys, rel); err == nil && info.IsDir() {
		rel = path.Join(rel, "*")
	}
	for _, name := range collector.Glob(p.fsys, rel) {
		p.parseFile(name, depth+1)
	}
}

func splitApacheArgs(s string) []string {
	var out []string
	var cur strings.Builder
	quoted, inWord := false, false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			inWord = true
		case (r == ' ' || r == '\t') && !quoted:
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}
