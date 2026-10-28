package discovery

import (
	"path"
	"regexp"
	"slices"
	"strings"
)

// Web servers.
const (
	ServerNginx  = "nginx"
	ServerApache = "apache"
	ServerCaddy  = "caddy"
)

// Site is a virtual host found in a web server configuration.
type Site struct {
	Server     string   `json:"server"`
	Config     string   `json:"config"`
	Names      []string `json:"names,omitempty"`
	Listen     []string `json:"listen,omitempty"`
	Root       string   `json:"root,omitempty"`
	AccessLogs []string `json:"access_logs,omitempty"`
	ErrorLogs  []string `json:"error_logs,omitempty"`
	Upstreams  []string `json:"upstreams,omitempty"`

	// Locations model nginx request routing. Servers without one (Apache, Caddy) hand every
	// file with one of ScriptExtensions to the interpreter.
	Locations        []Location `json:"locations,omitempty"`
	ScriptExtensions []string   `json:"script_extensions,omitempty"`

	// aliases map URL prefixes to other directories (Apache's Alias); opaque says the
	// configuration maps URLs in ways not modelled (AliasMatch, a rewrite to a proxy), so the
	// files a request reaches cannot be told. Both only serve ScriptFiles, in the sensor.
	aliases []alias
	opaque  bool
}

type alias struct{ url, dir string }

// Location is an nginx location block.
type Location struct {
	Modifier  string     `json:"modifier,omitempty"`
	Pattern   string     `json:"pattern"`
	Executes  bool       `json:"executes,omitempty"`
	Denied    bool       `json:"denied,omitempty"`
	Upstream  string     `json:"upstream,omitempty"`
	Root      string     `json:"root,omitempty"`
	Locations []Location `json:"locations,omitempty"`

	re *regexp.Regexp
}

func (l *Location) isRegex() bool {
	return l.Modifier == "~" || l.Modifier == "~*"
}

// matches reports whether a regex location matches uri. A pattern Go cannot compile (nginx
// uses PCRE) is treated as matching, so reachability errs on the side of reporting.
func (l *Location) matches(uri string) bool {
	if l.re == nil {
		return true
	}
	return l.re.MatchString(uri)
}

func compileLocation(modifier, pattern string) *regexp.Regexp {
	expr := pattern
	if modifier == "~*" {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil
	}
	return re
}

// Executes reports whether a request for uri reaches an interpreter rather than being served
// as a static file or refused.
func (s *Site) Executes(uri string) bool {
	if s.Server == ServerNginx {
		l := findLocation(s.Locations, uri)
		return l != nil && l.Executes && !l.Denied
	}
	return slices.Contains(s.ScriptExtensions, strings.ToLower(path.Ext(uri)))
}

// findLocation follows nginx's selection order: an exact match wins; otherwise the longest
// prefix is remembered, and unless it is ^~ the regexes are tried in configuration order,
// those nested in the remembered prefix first; the first regex that matches wins, else the
// prefix does.
func findLocation(locs []Location, uri string) *Location {
	var prefix *Location
	for i := range locs {
		l := &locs[i]
		switch l.Modifier {
		case "=":
			if l.Pattern == uri {
				return l
			}
		case "", "^~":
			if strings.HasPrefix(uri, l.Pattern) && (prefix == nil || len(l.Pattern) > len(prefix.Pattern)) {
				prefix = l
			}
		}
	}

	if prefix != nil && prefix.Modifier == "^~" {
		return deepest(prefix, uri)
	}
	if prefix != nil {
		if nested := findLocation(prefix.Locations, uri); nested != nil && nested.isRegex() {
			return nested
		}
	}
	for i := range locs {
		if l := &locs[i]; l.isRegex() && l.matches(uri) {
			return deepest(l, uri)
		}
	}
	if prefix != nil {
		return deepest(prefix, uri)
	}
	return nil
}

func deepest(l *Location, uri string) *Location {
	if nested := findLocation(l.Locations, uri); nested != nil {
		return nested
	}
	return l
}

// maxScriptFiles bounds the places ScriptFiles names for one request.
const maxScriptFiles = 64

// ScriptFiles names the files a request for uri could have reached on this host, and false when
// they cannot be told: a server other than nginx (Apache aliases and proxies are not modelled),
// a request nginx may hand to a proxy (its location, or a named location try_files or
// error_page can fall back to), a root that holds a variable or is relative, or more places
// than the bound. Every root of the site is tried, both as root and as alias of its location, so a file
// served from any of them is found: naming too many places only makes a file look present.
func (s *Site) ScriptFiles(uri string) ([]string, bool) {
	if s.Server == ServerApache {
		return s.apacheScriptFiles(uri)
	}
	if s.Server != ServerNginx || s.Root == "" {
		return nil, false
	}
	if l := findLocation(s.Locations, uri); l != nil && l.Upstream != "" && !l.Executes {
		return nil, false
	}
	files := []string{path.Join(s.Root, uri)}
	ok := !strings.Contains(s.Root, "$")
	var walk func(locs []Location)
	walk = func(locs []Location) {
		for _, l := range locs {
			if strings.HasPrefix(l.Pattern, "@") && l.Upstream != "" && !l.Executes {
				ok = false
			}
			if l.Root != "" {
				ok = ok && !strings.Contains(l.Root, "$") && path.IsAbs(l.Root)
				files = append(files, path.Join(l.Root, uri))
				if !l.isRegex() && l.Modifier != "=" && strings.HasPrefix(uri, l.Pattern) {
					files = append(files, path.Join(l.Root, strings.TrimPrefix(uri, l.Pattern)))
				}
			}
			walk(l.Locations)
		}
	}
	walk(s.Locations)
	if !ok || len(files) > maxScriptFiles {
		return nil, false
	}
	slices.Sort(files)
	return slices.Compact(files), true
}

// apacheScriptFiles names the files a request could reach on an Apache site: under its
// DocumentRoot, and under the directory of each Alias whose prefix the request starts with.
// Any proxy in the site, or a mapping not modelled, leaves the question open.
func (s *Site) apacheScriptFiles(uri string) ([]string, bool) {
	if s.Root == "" || s.opaque || len(s.Upstreams) > 0 || strings.Contains(s.Root, "$") {
		return nil, false
	}
	files := []string{path.Join(s.Root, uri)}
	for _, a := range s.aliases {
		if !path.IsAbs(a.dir) || strings.Contains(a.dir, "$") {
			return nil, false
		}
		if rest, ok := strings.CutPrefix(uri, strings.TrimSuffix(a.url, "/")); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
			files = append(files, path.Join(a.dir, rest))
		}
	}
	if len(files) > maxScriptFiles {
		return nil, false
	}
	slices.Sort(files)
	return slices.Compact(files), true
}
