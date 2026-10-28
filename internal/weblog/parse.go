// Package weblog parses web server access logs into a common shape and applies attack
// detection rules to them. It does no I/O, so the sensor and the verifier share it.
package weblog

import (
	"encoding/json"
	"math"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Log formats.
const (
	FormatCombined = "combined"
	FormatCaddy    = "caddy_json"
)

// Request is one access log entry, whatever the server that wrote it.
type Request struct {
	Time      time.Time `json:"time"`
	IP        string    `json:"ip"`
	Method    string    `json:"method"`
	URI       string    `json:"uri"`
	Status    int       `json:"status"`
	Size      int64     `json:"size,omitempty"`
	Referer   string    `json:"referer,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`

	path  string
	norm  string
	query string
}

// Path returns the URI path, percent-decoded and normalised the way nginx resolves it before
// routing: slashes merged, "." and ".." resolved. /v1/../index.php and //index.php are the
// same request as /index.php and are grouped with it.
func (r *Request) Path() string { return r.norm }

// RawPath returns the decoded path before normalisation, which still shows traversal attempts.
func (r *Request) RawPath() string { return r.path }

func normalisePath(p string) string {
	if p == "" {
		return "/"
	}
	return path.Clean("/" + p)
}

// combinedRe matches the NCSA combined format used by default by nginx and Apache. Anything
// after the user agent (request time, upstream, host) is ignored.
var combinedRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)(?: [^"]*)?" (\d{3}) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?`)

const combinedTime = "02/Jan/2006:15:04:05 -0700"

// DetectFormat guesses the format of a log from one of its lines.
func DetectFormat(line string) string {
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		return FormatCaddy
	}
	return FormatCombined
}

// Parse decodes one line in the given format.
func Parse(format, line string) (Request, bool) {
	var r Request
	var ok bool
	switch format {
	case FormatCaddy:
		r, ok = parseCaddy(line)
	default:
		r, ok = parseCombined(line)
	}
	if !ok {
		return Request{}, false
	}
	r.path, r.query = splitURI(r.URI)
	r.norm = normalisePath(r.path)
	return r, true
}

// requestPrefixRe matches the start of a combined line whose request was cut: what is left is
// enough to apply the rules on method and path.
var requestPrefixRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)`)

func parseCombined(line string) (Request, bool) {
	m := combinedRe.FindStringSubmatch(line)
	if m == nil {
		p := requestPrefixRe.FindStringSubmatch(line)
		if p == nil {
			return Request{}, false
		}
		t, err := time.Parse(combinedTime, p[2])
		if err != nil {
			return Request{}, false
		}
		return Request{Time: t.UTC(), IP: p[1], Method: p[3], URI: p[4]}, true
	}
	t, err := time.Parse(combinedTime, m[2])
	if err != nil {
		return Request{}, false
	}
	status, _ := strconv.Atoi(m[5])
	size, _ := strconv.ParseInt(m[6], 10, 64)
	return Request{
		Time: t.UTC(), IP: m[1], Method: m[3], URI: m[4], Status: status, Size: size,
		Referer: dash(m[7]), UserAgent: dash(m[8]),
	}, true
}

type caddyEntry struct {
	TS      float64 `json:"ts"`
	Status  int     `json:"status"`
	Size    int64   `json:"size"`
	Request struct {
		RemoteIP string              `json:"remote_ip"`
		ClientIP string              `json:"client_ip"`
		Method   string              `json:"method"`
		URI      string              `json:"uri"`
		Headers  map[string][]string `json:"headers"`
	} `json:"request"`
}

func parseCaddy(line string) (Request, bool) {
	var e caddyEntry
	if err := json.Unmarshal([]byte(line), &e); err != nil || e.Request.Method == "" {
		return Request{}, false
	}
	sec, frac := math.Modf(e.TS)
	ip := e.Request.ClientIP
	if ip == "" {
		ip = e.Request.RemoteIP
	}
	r := Request{
		Time:   time.Unix(int64(sec), int64(frac*1e9)).UTC(),
		IP:     ip,
		Method: e.Request.Method,
		URI:    e.Request.URI,
		Status: e.Status,
		Size:   e.Size,
	}
	if ua := e.Request.Headers["User-Agent"]; len(ua) > 0 {
		r.UserAgent = ua[0]
	}
	if ref := e.Request.Headers["Referer"]; len(ref) > 0 {
		r.Referer = ref[0]
	}
	return r, true
}

// splitURI returns the decoded path and query. Decoding is applied twice so that double
// encoding (%252e%252e) does not hide a pattern.
func splitURI(uri string) (string, string) {
	p, q, _ := strings.Cut(uri, "?")
	return decodeTwice(p, url.PathUnescape), decodeTwice(q, url.QueryUnescape)
}

func decodeTwice(s string, unescape func(string) (string, error)) string {
	for range 2 {
		d, err := unescape(s)
		if err != nil || d == s {
			break
		}
		s = d
	}
	return s
}

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// ScriptPath reduces a normalised path to the script that serves it, as the server's
// SCRIPT_NAME: the part up to the first segment naming a script, without the PATH_INFO after
// it and without ";" parameters. Paths without a script are returned whole.
func ScriptPath(p string) string {
	segments := strings.Split(p, "/")
	for i, seg := range segments {
		if j := strings.IndexByte(seg, ';'); j >= 0 {
			seg = seg[:j]
			segments[i] = seg
		}
		if slices.Contains(scriptExtensions, strings.ToLower(path.Ext(seg))) {
			return strings.Join(segments[:i+1], "/")
		}
	}
	return strings.Join(segments, "/")
}

// IsScript reports whether the last segment of a path names a script.
func IsScript(p string) bool {
	return slices.Contains(scriptExtensions, strings.ToLower(path.Ext(p)))
}
