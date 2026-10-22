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
}

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
