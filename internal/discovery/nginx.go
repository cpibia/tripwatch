package discovery

import (
	"fmt"
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

// Budgets for parsing one web server configuration. Include globs can point into directories
// an attacker writes to (some applications ship a server config inside their own tree), and
// without a budget a few files that include each other fan out exponentially.
const (
	maxConfigFiles      = 500
	maxConfigBytes      = 4 << 20
	maxConfigDirectives = 50_000
	maxDirectiveArgs    = 64
	maxTokenLength      = 4096
	maxBlockNesting     = 64
)

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

// NginxSites parses the first nginx configuration found and returns its server blocks and
// the configuration files it read.
func NginxSites(fsys fs.FS) ([]Site, []string, collector.Issues) {
	var issues collector.Issues
	for _, conf := range nginxConfigs {
		if !exists(fsys, conf) {
			continue
		}
		p := nginxParser{fsys: fsys, prefix: path.Dir(conf), issues: &issues, budget: newConfigBudget("nginx")}
		tree := p.parseFile(conf, 0)
		return nginxServers(tree, path.Dir(conf)), p.budget.files, issues
	}
	return nil, nil, issues
}

type nginxParser struct {
	fsys    fs.FS
	prefix  string
	issues  *collector.Issues
	budget  *configBudget
	nesting int
}

func (p *nginxParser) parseFile(name string, depth int) []directive {
	if !p.budget.enter(name, p.issues) {
		return nil
	}
	defer p.budget.leave(name)

	data, err := fs.ReadFile(p.fsys, name)
	if err != nil {
		p.issues.Add(err)
		return nil
	}
	if !p.budget.consume(len(data), p.issues) {
		return nil
	}
	tree := p.parseBlock(&nginxLexer{src: string(data)}, name, depth)
	return tree
}

// parseBlock consumes tokens up to the closing brace of the current block and expands
// include directives in place. Tokens are pulled one at a time and every directive counts
// against the budget, so memory follows the budget and not the size of a hostile file.
func (p *nginxParser) parseBlock(lx *nginxLexer, file string, depth int) []directive {
	var out []directive
	var stmt []string
	for {
		tok, ok := lx.next()
		if !ok {
			return out
		}
		switch tok {
		case ";":
			if len(stmt) == 0 {
				continue
			}
			if !p.budget.directive(p.issues) {
				lx.stop()
				return out
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
			if !p.budget.directive(p.issues) {
				lx.stop()
				return out
			}
			d := directive{Name: stmt[0], Args: stmt[1:], File: "/" + file}
			stmt = nil
			if p.nesting >= maxBlockNesting {
				*p.issues = append(*p.issues, fmt.Sprintf("nginx: blocks nested deeper than %d in /%s, rest of the file ignored", maxBlockNesting, file))
				lx.stop()
				return out
			}
			p.nesting++
			d.Block = p.parseBlock(lx, file, depth)
			p.nesting--
			out = append(out, d)
		case "}":
			return out
		default:
			if len(stmt) < maxDirectiveArgs {
				stmt = append(stmt, tok)
			}
		}
	}
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

// nginxLexer splits a configuration into words and the punctuation ; { }, handling quotes,
// escapes and comments, one token at a time.
type nginxLexer struct {
	src  string
	pos  int
	done bool
}

func (lx *nginxLexer) stop() { lx.done = true }

func (lx *nginxLexer) next() (string, bool) {
	if lx.done {
		return "", false
	}
	var cur strings.Builder
	inWord, inVar := false, false
	s := lx.src
	for ; lx.pos < len(s); lx.pos++ {
		c := s[lx.pos]
		switch {
		case c == '{' && inWord && lx.pos > 0 && s[lx.pos-1] == '$':
			// ${name}: the braces belong to the variable, not to a block.
			inVar = true
			cur.WriteByte(c)
		case c == '}' && inVar:
			inVar = false
			cur.WriteByte(c)
		case c == '#' && !inWord:
			for lx.pos < len(s) && s[lx.pos] != '\n' {
				lx.pos++
			}
		case c == '"' || c == '\'':
			quote := c
			inWord = true
			for lx.pos++; lx.pos < len(s) && s[lx.pos] != quote; lx.pos++ {
				if s[lx.pos] == '\\' && lx.pos+1 < len(s) {
					lx.pos++
				}
				cur.WriteByte(s[lx.pos])
			}
		case c == ';' || c == '{' || c == '}':
			if inWord {
				return cur.String(), true
			}
			lx.pos++
			return string(c), true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inWord {
				lx.pos++
				return cur.String(), true
			}
		case c == '\\' && lx.pos+1 < len(s):
			lx.pos++
			cur.WriteByte(s[lx.pos])
			inWord = true
		default:
			if cur.Len() < maxTokenLength {
				cur.WriteByte(c)
			}
			inWord = true
		}
	}
	if inWord {
		return cur.String(), true
	}
	return "", false
}

// tokenizeNginx returns all the tokens of s.
func tokenizeNginx(s string) []string {
	lx := &nginxLexer{src: s}
	var out []string
	for tok, ok := lx.next(); ok; tok, ok = lx.next() {
		out = append(out, tok)
	}
	return out
}

func nginxServers(tree []directive, prefix string) []Site {
	var sites []Site
	for _, http := range blocks(tree, "http") {
		httpRoot := last(http.Block, "root")
		httpLogs := logPaths(http.Block, "access_log", prefix)
		httpErrs := logPaths(http.Block, "error_log", prefix)
		for _, server := range blocks(http.Block, "server") {
			var vars []nginxVar
			for _, d := range server.Block {
				if d.Name == "set" && len(d.Args) == 2 {
					vars = append(vars, nginxVar{d.Args[0], d.Args[1]})
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

			site.AccessLogs = expandAll(logPaths(server.Block, "access_log", prefix), expand)
			if len(site.AccessLogs) == 0 {
				site.AccessLogs = httpLogs
			}
			if len(site.AccessLogs) == 0 {
				site.AccessLogs = []string{defaultNginxLog}
			}
			site.ErrorLogs = expandAll(logPaths(server.Block, "error_log", prefix), expand)
			if len(site.ErrorLogs) == 0 {
				site.ErrorLogs = httpErrs
			}
			if len(site.ErrorLogs) == 0 {
				site.ErrorLogs = []string{defaultNginxErr}
			}

			site.Locations = nginxLocations(server.Block, expand, &site.Upstreams)
			site.answers = last(server.Block, "return") != ""
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

type nginxVar struct{ name, value string }

func expandAll(list []string, expand func(string) string) []string {
	for i, v := range list {
		list[i] = expand(v)
	}
	return list
}

// expandVars substitutes server-level set variables. Longer names go first so that $ROOT does
// not eat the start of $ROOT_DIR, and the order is fixed so the result is the same on every
// run.
func expandVars(s string, vars []nginxVar) string {
	sorted := slices.Clone(vars)
	slices.SortStableFunc(sorted, func(a, b nginxVar) int { return len(b.name) - len(a.name) })
	for _, v := range sorted {
		s = strings.ReplaceAll(s, "${"+strings.TrimPrefix(v.name, "$")+"}", v.value)
		s = strings.ReplaceAll(s, v.name, v.value)
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
