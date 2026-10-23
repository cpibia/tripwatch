package weblog

import (
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Severities, from most to least urgent.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Hit is a rule that matched a request.
type Hit struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
}

const (
	chainWindow      = 24 * time.Hour
	bruteForceWindow = 10 * time.Minute
	bruteForceLimit  = 20
)

var (
	scriptExtensions = []string{".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".phar", ".pht", ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".pl"}
	staticExtensions = []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ico", ".webp"}

	uploadSegments = []string{
		"/media/", "/uploads/", "/upload/", "/files/", "/images/", "/storage/", "/tmp/",
		"/wp-content/uploads/", "/sites/default/files/", "/custom_options/", "/customer_address/",
	}

	// Names of widespread web shells and file managers.
	webshellNames = []string{
		"c99.php", "r57.php", "wso.php", "wso2.php", "alfa.php", "alfashell.php", "b374k.php", "shell.php",
		"cmd.php", "webshell.php", "up.php", "upl.php", "uploader.php", "filemanager.php", "leaf.php",
		"mini.php", "bypass.php", "priv8.php", "indoxploit.php", "marijuana.php", "symlink.php",
	}

	// Magento entry points that serve files and never receive forms; a POST to them is how
	// skimmers relay stolen data through the shop's own domain.
	getOnlyEntryPoints = []string{"/get.php", "/static.php"}

	// Public login forms only: admin panels receive many legitimate POSTs from busy staff.
	loginEndpoints = []string{
		"/wp-login.php", "/xmlrpc.php", "/user/login", "/administrator/index.php",
		"/customer/account/loginpost",
	}

	sensitiveRe     = regexp.MustCompile(`(?i)(/\.env(\.|$)|/\.git/|/\.svn/|/\.hg/|/\.aws/|/\.ssh/|/id_[rd]sa|/\.htpasswd|/\.ds_store$|/app/etc/(env\.php|local\.xml)|/wp-config\.php[.~_-]|/config\.php[.~_-]|\.(sql|bak|old|orig|swp)$|/(backup|dump|database|db)\.(zip|tar|tar\.gz|tgz|sql\.gz)$|/(phpinfo|info|test)\.php$|/server-status$|/actuator/(env|heapdump)|/web\.config$)`)
	traversalRe     = regexp.MustCompile(`(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self/|(php|file|expect|data|phar|zip)://)`)
	sqlInjectionRe  = regexp.MustCompile(`(?i)(union(\s|/\*.*?\*/)+(all\s+)?select\b|\bsleep\s*\(\s*\d|benchmark\s*\(|information_schema|'\s*or\s*'?\d'?\s*=\s*'?\d|extractvalue\s*\(|updatexml\s*\(|waitfor\s+delay)`)
	commandParamRe  = regexp.MustCompile(`(?i)(^|&)(cmd|exec|command|c|e|run|shell|do|code)=[^&]*(whoami|\bid\b|uname|cat\s+/|wget\s|curl\s|/bin/(ba)?sh|\bnc\s|python\s|perl\s|base64|chmod\s|powershell)`)
	injectionProbes = regexp.MustCompile(`(?i)(\$\{jndi:|\$\{\$\{|\(\)\s*\{\s*:\s*;\s*\}|<script\b|\{\{\s*7\s*\*\s*7\s*\}\})`)
	scannerAgentRe  = regexp.MustCompile(`(?i)(sqlmap|nikto|nuclei|wpscan|masscan|zgrab|gobuster|dirbuster|ffuf|feroxbuster|nmap|acunetix|nessus|openvas|whatweb|jaeles|xray|commix|joomscan|droopescan|cmsmap)`)
	sessionReaperRe = regexp.MustCompile(`^(/[a-z0-9_]+)?/customer/address_file/upload/?$`)
	guestCartRe     = regexp.MustCompile(`^/rest(/[a-z0-9_]+)?/v1/guest-carts/`)
)

// maxTrackedIPs bounds the per-IP state: a remote attacker controls how many distinct
// addresses appear (a single IPv6 /64 is enough), and memory must not follow.
const maxTrackedIPs = 50_000

// Analyzer applies the rules to requests in log order. It keeps per-IP state to correlate
// requests into chains, so one Analyzer must see all the requests of a site.
type Analyzer struct {
	uploads map[string]time.Time
	logins  map[string][]time.Time
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{uploads: map[string]time.Time{}, logins: map[string][]time.Time{}}
}

// Analyze returns the rules r matches.
func (a *Analyzer) Analyze(r *Request) []Hit {
	var hits []Hit
	hit := func(rule, severity string) { hits = append(hits, Hit{Rule: rule, Severity: severity}) }

	p := strings.ToLower(r.norm)
	raw := strings.ToLower(r.path)
	q := r.query
	ok := r.Status >= 200 && r.Status < 300
	ext := path.Ext(p)
	// Any segment counts: with PATH_INFO routing /media/x.php/a.jpg executes x.php.
	script := hasScriptSegment(p)
	post := r.Method == "POST" || r.Method == "PUT"

	// SessionReaper (CVE-2025-54236): a session file uploaded through the customer address
	// attribute endpoint, then loaded by a guest cart REST call that fails with 500.
	if r.Method == "POST" && sessionReaperRe.MatchString(p) {
		evictOne(a.uploads, r.IP)
		a.uploads[r.IP] = r.Time
		hit("sessionreaper_upload", SeverityHigh)
	}
	if guestCartRe.MatchString(p) && r.Status >= 500 {
		if at, seen := a.uploads[r.IP]; seen && r.Time.Sub(at) <= chainWindow && !r.Time.Before(at) {
			hit("sessionreaper_chain", SeverityCritical)
		}
	}

	// The status is chosen by the script itself, and many web shells answer 404 to blend in:
	// a script requested in an upload directory stays high on any status but a redirect. A
	// redirect is almost always the server's own (to https, to a canonical host) before the
	// script is reached; the request that follows it is logged with its own status. A POST answered
	// with a redirect stays high: the script may have chosen that status, and nothing reposts it.
	if script && hasUploadSegment(p) {
		switch {
		case ok:
			hit("script_in_upload_path", SeverityCritical)
		case r.Status >= 300 && r.Status < 400 && !post:
			hit("script_in_upload_path", SeverityLow)
		default:
			hit("script_in_upload_path", SeverityHigh)
		}
	}
	if slices.ContainsFunc(strings.Split(p, "/"), func(seg string) bool { return slices.Contains(webshellNames, seg) }) {
		switch {
		case ok:
			hit("known_webshell_name", SeverityCritical)
		case post:
			hit("known_webshell_name", SeverityHigh)
		default:
			hit("known_webshell_name", SeverityLow)
		}
	}
	if commandParamRe.MatchString(q) {
		hit("command_in_parameters", bySuccess(ok && script, SeverityCritical, SeverityHigh))
	}
	if post && slices.Contains(getOnlyEntryPoints, p) {
		hit("post_to_get_only_endpoint", SeverityHigh)
	}
	if post && ok && slices.Contains(staticExtensions, ext) {
		hit("post_to_static_file", SeverityMedium)
	}
	if sensitiveRe.MatchString(p) {
		hit("sensitive_file", bySuccess(ok, SeverityHigh, SeverityLow))
	}
	if traversalRe.MatchString(raw) || traversalRe.MatchString(q) {
		hit("path_traversal", bySuccess(ok, SeverityHigh, SeverityMedium))
	}
	if sqlInjectionRe.MatchString(q) || sqlInjectionRe.MatchString(p) {
		hit("sql_injection", SeverityMedium)
	}
	if injectionProbes.MatchString(r.URI+" "+q) || injectionProbes.MatchString(r.UserAgent) {
		hit("injection_probe", SeverityMedium)
	}
	if scannerAgentRe.MatchString(r.UserAgent) {
		hit("scanner_user_agent", SeverityLow)
	}
	if r.Method == "POST" && isLogin(p) && a.countLogin(r.IP, r.Time) == bruteForceLimit {
		hit("login_bruteforce", SeverityMedium)
	}
	return hits
}

// countLogin records a login attempt and returns how many the IP made in the window, so the
// rule fires once when the limit is reached rather than on every attempt after it.
// At most bruteForceLimit+1 attempts are kept per IP: that is all the rule needs.
func (a *Analyzer) countLogin(ip string, t time.Time) int {
	attempts := a.logins[ip]
	evictOne(a.logins, ip)
	recent := attempts[:0]
	for _, at := range attempts {
		if t.Sub(at) <= bruteForceWindow {
			recent = append(recent, at)
		}
	}
	if len(recent) <= bruteForceLimit {
		recent = append(recent, t)
	}
	a.logins[ip] = recent
	if len(recent) > bruteForceLimit {
		return bruteForceLimit + 1
	}
	return len(recent)
}

// evictOne makes room for key when the table is full by dropping an arbitrary other entry:
// refusing new addresses instead would let an attacker blind the rules by sending from many
// addresses first.
func evictOne[V any](m map[string]V, key string) {
	if _, tracked := m[key]; tracked || len(m) < maxTrackedIPs {
		return
	}
	for k := range m {
		delete(m, k)
		return
	}
}

func isLogin(p string) bool {
	return slices.ContainsFunc(loginEndpoints, func(e string) bool { return p == e || strings.HasPrefix(p, e+"/") })
}

// hasScriptSegment matches a script extension on any segment, and double extensions such as
// x.php.jpg that some server configurations still hand to the interpreter.
func hasScriptSegment(p string) bool {
	return slices.ContainsFunc(strings.Split(p, "/"), func(seg string) bool {
		return slices.Contains(scriptExtensions, path.Ext(seg)) ||
			slices.ContainsFunc(scriptExtensions, func(ext string) bool { return strings.Contains(seg, ext+".") })
	})
}

func hasUploadSegment(p string) bool {
	return slices.ContainsFunc(uploadSegments, func(s string) bool { return strings.Contains(p, s) })
}

func bySuccess(ok bool, success, otherwise string) string {
	if ok {
		return success
	}
	return otherwise
}

// SeverityRank orders severities for sorting and thresholds: higher is more urgent.
func SeverityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}
