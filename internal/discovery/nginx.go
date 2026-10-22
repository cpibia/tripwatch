package discovery

import (
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

var nginxConfigs = []string{
	"etc/nginx/nginx.conf",
	"usr/local/nginx/conf/nginx.conf",
	"usr/local/etc/nginx/nginx.conf",
	"opt/nginx/conf/nginx.conf",
}

const (
	maxIncludeDepth  = 10
	defaultNginxLog  = "/var/log/nginx/access.log"
	defaultNginxErr  = "/var/log/nginx/error.log"
	nginxDefaultRoot = "html"
)

// directive is a parsed nginx statement; Block is set for block directives.
type directive struct {
	Name  string
	Args  []string
	Block []directive
	File  string
}

// NginxSites parses the first nginx configuration found and returns its server blocks.
func NginxSites(fsys fs.FS) ([]Site, collector.Issues) {
	var issues collector.Issues
	for _, conf := range nginxConfigs {
		if !exists(fsys, conf) {
			continue
		}
		p := nginxParser{fsys: fsys, prefix: path.Dir(conf), issues: &issues}
		tree := p.parseFile(conf, 0)
		return nginxServers(tree, path.Dir(conf)), issues
	}
	return nil, issues
}

type nginxParser struct {
	fsys   fs.FS
	prefix string
	issues *collector.Issues
}

func (p *nginxParser) parseFile(name string, depth int) []directive {
	data, err := fs.ReadFile(p.fsys, name)
	if err != nil {
		p.issues.Add(err)
		return nil
	}
	tokens := tokenizeNginx(string(data))
	tree, _ := p.parseBlock(tokens, name, depth)
	return tree
}

// parseBlock consumes tokens up to the closing brace of the current block and expands
// include directives in place.
func (p *nginxParser) parseBlock(tokens []string, file string, depth int) ([]directive, []string) {
	var out []directive
	var stmt []string
	for len(tokens) > 0 {
		tok := tokens[0]
		tokens = tokens[1:]
		switch tok {
		case ";":
			if len(stmt) == 0 {
				continue
			}
			d := directive{Name: stmt[0], Args: stmt[1:], File: "/" + file}
			stmt = nil
			if d.Name == "include" && len(d.Args) > 0 {
				out = append(out, p.include(d.Args[0], depth)...)
				continue
			}
			out = append(out, d)
		case "{":
			if len(stmt) == 0 {
				stmt = []string{""}
			}
			d := directive{Name: stmt[0], Args: stmt[1:], File: "/" + file}
			stmt = nil
			d.Block, tokens = p.parseBlock(tokens, file, depth)
			out = append(out, d)
		case "}":
			return out, tokens
		default:
			stmt = append(stmt, tok)
		}
	}
	return out, tokens
}

func (p *nginxParser) include(pattern string, depth int) []directive {
	if depth >= maxIncludeDepth {
		*p.issues = append(*p.issues, "nginx: include depth exceeded at "+pattern)
		return nil
	}
	if !path.IsAbs(pattern) {
		pattern = path.Join("/"+p.prefix, pattern)
	}
	var out []directive
	for _, name := range collector.Glob(p.fsys, collector.Rel(pattern)) {
		out = append(out, p.parseFile(name, depth+1)...)
	}
	return out
}

// tokenizeNginx splits a configuration into words and the punctuation ; { }, handling
// quotes, escapes and comments.
func tokenizeNginx(s string) []string {
	var tokens []string
	var cur strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			tokens = append(tokens, cur.String())
			cur.Reset()
			inWord = false
		}
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '#' && !inWord:
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '"' || c == '\'':
			quote := c
			inWord = true
			for i++; i < len(s) && s[i] != quote; i++ {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				cur.WriteByte(s[i])
			}
		case c == ';' || c == '{' || c == '}':
			flush()
			tokens = append(tokens, string(c))
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			inWord = true
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	flush()
	return tokens
}

func nginxServers(tree []directive, prefix string) []Site {
	var sites []Site
	for _, http := range blocks(tree, "http") {
		httpRoot := last(http.Block, "root")
		httpLogs := logPaths(http.Block, "access_log", prefix)
		httpErrs := logPaths(http.Block, "error_log", prefix)
		for _, server := range blocks(http.Block, "server") {
			vars := map[string]string{}
			for _, d := range server.Block {
				if d.Name == "set" && len(d.Args) == 2 {
					vars[d.Args[0]] = d.Args[1]
				}
			}
			expand := func(s string) string { return expandVars(s, vars) }

			site := Site{Server: ServerNginx, Config: server.File}
			for _, d := range server.Block {
				switch d.Name {
				case "server_name":
					site.Names = append(site.Names, d.Args...)
				case "listen":
					if len(d.Args) > 0 {
						site.Listen = append(site.Listen, d.Args[0])
					}
				}
			}

			root := last(server.Block, "root")
			if root == "" {
				root = httpRoot
			}
			if root == "" {
				root = nginxDefaultRoot
			}
			site.Root = absolute(expand(root), prefix)

			site.AccessLogs = logPaths(server.Block, "access_log", prefix)
			if len(site.AccessLogs) == 0 {
				site.AccessLogs = httpLogs
			}
			if len(site.AccessLogs) == 0 {
				site.AccessLogs = []string{defaultNginxLog}
			}
			site.ErrorLogs = logPaths(server.Block, "error_log", prefix)
			if len(site.ErrorLogs) == 0 {
				site.ErrorLogs = httpErrs
			}
			if len(site.ErrorLogs) == 0 {
				site.ErrorLogs = []string{defaultNginxErr}
			}

			site.Locations = nginxLocations(server.Block, expand, &site.Upstreams)
			sites = append(sites, site)
		}
	}
	return sites
}

func nginxLocations(block []directive, expand func(string) string, upstreams *[]string) []Location {
	var out []Location
	for _, d := range blocks(block, "location") {
		if len(d.Args) == 0 {
			continue
		}
		l := Location{Pattern: d.Args[len(d.Args)-1]}
		if len(d.Args) > 1 {
			l.Modifier = d.Args[0]
		}
		if l.isRegex() {
			l.re = compileLocation(l.Modifier, l.Pattern)
		}
		for _, inner := range d.Block {
			switch inner.Name {
			case "fastcgi_pass", "uwsgi_pass", "scgi_pass":
				l.Executes = true
				l.Upstream = first(inner.Args)
			case "proxy_pass", "grpc_pass":
				l.Upstream = first(inner.Args)
			case "deny":
				l.Denied = first(inner.Args) == "all"
			case "return":
				l.Denied = l.Denied || strings.HasPrefix(first(inner.Args), "4")
			case "internal":
				l.Denied = true
			case "root", "alias":
				l.Root = expand(first(inner.Args))
			}
		}
		if l.Upstream != "" && !slices.Contains(*upstreams, l.Upstream) {
			*upstreams = append(*upstreams, l.Upstream)
		}
		l.Locations = nginxLocations(d.Block, expand, upstreams)
		out = append(out, l)
	}
	return out
}

func blocks(tree []directive, name string) []directive {
	var out []directive
	for _, d := range tree {
		if d.Name == name && d.Block != nil {
			out = append(out, d)
		}
	}
	return out
}

func last(tree []directive, name string) string {
	value := ""
	for _, d := range tree {
		if d.Name == name && len(d.Args) > 0 {
			value = d.Args[0]
		}
	}
	return value
}

func logPaths(tree []directive, name, prefix string) []string {
	var out []string
	for _, d := range tree {
		if d.Name != name || len(d.Args) == 0 || d.Args[0] == "off" || strings.HasPrefix(d.Args[0], "syslog:") {
			continue
		}
		out = append(out, absolute(d.Args[0], prefix))
	}
	return out
}

func expandVars(s string, vars map[string]string) string {
	for name, value := range vars {
		s = strings.ReplaceAll(s, "${"+strings.TrimPrefix(name, "$")+"}", value)
		s = strings.ReplaceAll(s, name, value)
	}
	return s
}

func absolute(p, prefix string) string {
	if p == "" || path.IsAbs(p) || strings.HasPrefix(p, "$") {
		return p
	}
	return path.Join("/"+prefix, p)
}

func first(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}
