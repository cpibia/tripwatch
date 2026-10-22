// Package apps reads what web applications keep in their configuration and database:
// administrators, scripts injected through settings and content, active extensions, and
// settings that do not belong in production.
package apps

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing/fstest"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/discovery"
)

const (
	connectTimeout = 3 * time.Second
	queryTimeout   = 10 * time.Second
	maxRows        = 200
)

type Admin struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email,omitempty"`
	Created   string `json:"created,omitempty"`
	LastLogin string `json:"last_login,omitempty"`
	Active    string `json:"active,omitempty"`
}

// Injected is stored content that loads or carries a script: where it is and which domains
// its scripts come from. Store settings and CMS blocks are where skimmers are usually put.
type Injected struct {
	Where   string   `json:"where"`
	Domains []string `json:"domains,omitempty"`
	Inline  bool     `json:"inline,omitempty"`
}

type Profile struct {
	Path       string            `json:"path"`
	Framework  string            `json:"framework"`
	Database   string            `json:"database,omitempty"`
	Reachable  bool              `json:"database_reachable"`
	Admins     []Admin           `json:"admins"`
	Extensions []string          `json:"extensions,omitempty"`
	Injected   []Injected        `json:"injected_scripts"`
	Settings   map[string]string `json:"settings,omitempty"`
	Warnings   []string          `json:"warnings,omitempty"`
	Issues     collector.Issues  `json:"issues,omitempty"`
}

type Result struct {
	Apps []Profile `json:"apps"`
}

// querier runs a read-only query and returns the rows as strings.
type querier interface {
	query(ctx context.Context, q string, args ...any) ([]map[string]string, error)
}

// Collector profiles the applications found by discovery whose stack it knows. Connect opens
// the database; it is replaceable for tests.
type Collector struct {
	Connect func(ctx context.Context, src collector.Source, cfg dbConfig) (querier, func(), error)
	// AllowedHosts are database hosts the operator trusts beyond the local server.
	AllowedHosts []string
}

func (Collector) Name() string { return "apps" }

func (c Collector) Collect(ctx context.Context, src collector.Source) (any, error) {
	connect := c.Connect
	if connect == nil {
		allowed := c.AllowedHosts
		connect = func(ctx context.Context, src collector.Source, cfg dbConfig) (querier, func(), error) {
			return connectMySQL(ctx, src, cfg, allowed)
		}
	}
	res := Result{Apps: []Profile{}}
	env := runtimeEnv(src.FS)
	for _, app := range discovery.Inspect(src.FS).Applications {
		if !slices.Contains([]string{"wordpress", "magento", "drupal", "drupal7", "laravel"}, app.Framework) {
			continue
		}
		res.Apps = append(res.Apps, profile(ctx, src, app, env, connect))
	}
	return res, nil
}

// runtimeProcesses run application code: their environment holds the settings applications
// read with getenv().
var runtimeProcesses = []string{"php-fpm", "php", "apache2", "httpd", "frankenphp"}

// runtimeEnv merges the environment of the running PHP processes and of their ancestors: in
// containers the variables usually sit in the init process and reach PHP through the FPM pool
// configuration, not through the PHP process's own environment. Only processes running as root
// count (the FPM master, the container's init): a PHP process started by the web server user
// could otherwise feed the sensor the credentials of a database of its own. It is only used to
// resolve configuration values and never leaves the sensor.
func runtimeEnv(fsys fs.FS) map[string]string {
	env := map[string]string{}
	entries, err := fs.ReadDir(fsys, "proc")
	if err != nil {
		return env
	}
	visited := map[string]bool{}
	for _, e := range entries {
		comm, err := fs.ReadFile(fsys, "proc/"+e.Name()+"/comm")
		if err != nil {
			continue
		}
		name := strings.TrimRight(strings.TrimSpace(string(comm)), "0123456789.")
		if !slices.ContainsFunc(runtimeProcesses, func(p string) bool { return name == p || strings.HasPrefix(name, p+"-") }) {
			continue
		}
		for pid, hops := e.Name(), 0; pid != "" && pid != "0" && !visited[pid] && hops < 32; hops++ {
			visited[pid] = true
			if data, err := fs.ReadFile(fsys, "proc/"+pid+"/environ"); err == nil && processUID(fsys, pid) == "0" {
				for _, kv := range strings.Split(string(data), "\x00") {
					if k, v, ok := strings.Cut(kv, "="); ok {
						if _, seen := env[k]; !seen {
							env[k] = v
						}
					}
				}
			}
			pid = parentPID(fsys, pid)
		}
	}
	return env
}

func processUID(fsys fs.FS, pid string) string {
	lines, _ := collector.ReadLines(fsys, "proc/"+pid+"/status")
	for _, line := range lines {
		if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				return f[0]
			}
		}
	}
	return ""
}

func parentPID(fsys fs.FS, pid string) string {
	lines, err := collector.ReadLines(fsys, "proc/"+pid+"/status")
	if err != nil {
		return ""
	}
	for _, line := range lines {
		if v, ok := strings.CutPrefix(line, "PPid:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func profile(ctx context.Context, src collector.Source, app discovery.Application, env map[string]string, connect func(context.Context, collector.Source, dbConfig) (querier, func(), error)) Profile {
	p := Profile{Path: app.Path, Framework: app.Framework, Admins: []Admin{}, Injected: []Injected{}}
	root := strings.TrimPrefix(app.Path, "/")
	// A configuration someone other than root can write may not borrow root's environment:
	// it could name any variable as its password. Only the values written in it count then,
	// which its author knows anyway.
	// Each file is opened once: ownership is checked on the open file and the parser reads the
	// same bytes, so the file cannot be swapped between the check and the read.
	files, untrusted := loadConfigFiles(src.FS, root, app.Framework)
	for _, u := range untrusted {
		p.Warnings = append(p.Warnings, fmt.Sprintf("%s is writable by a user other than root (uid %d): the database it names, and so the administrators and scripts reported, can be forged by that user; environment variables are not used for it", u.name, u.uid))
	}
	cfgEnv := env
	if len(untrusted) > 0 {
		cfgEnv = map[string]string{}
	}
	cfg := readConfig(files, root, app.Framework, cfgEnv, &p.Issues)
	p.Settings, p.Warnings, p.Extensions = cfg.Settings, append(p.Warnings, cfg.Warnings...), cfg.Modules
	if cfg.DB == nil {
		return p
	}
	p.Database = cfg.DB.String()
	if !validPrefix.MatchString(cfg.DB.Prefix) {
		p.Issues = append(p.Issues, fmt.Sprintf("table prefix %q refused: not a plain identifier", cfg.DB.Prefix))
		return p
	}

	db, closeDB, err := connect(ctx, src, *cfg.DB)
	if err != nil {
		p.Issues = append(p.Issues, fmt.Sprintf("database %s not reachable: %v", cfg.DB, err))
		return p
	}
	defer closeDB()
	p.Reachable = true

	switch app.Framework {
	case "wordpress":
		wordpressChecks(ctx, db, cfg.DB.Prefix, &p)
	case "magento":
		magentoChecks(ctx, db, cfg.DB.Prefix, &p)
	case "drupal":
		drupalChecks(ctx, db, cfg.DB.Prefix, &p)
	case "drupal7":
		drupal7Checks(ctx, db, cfg.DB.Prefix, &p)
	}
	return p
}

// configFiles are where each framework keeps its database settings, relative to the
// application; "../" names the directory above it, where WordPress also looks.
var configFiles = map[string][]string{
	"wordpress": {"wp-config.php", "../wp-config.php"},
	"magento":   {"app/etc/env.php"},
	"drupal":    {"sites/default/settings.php", "sites/default/settings.local.php"},
	"drupal7":   {"sites/default/settings.php", "sites/default/settings.local.php"},
	"laravel":   {".env"},
}

// otherConfigFiles are read for settings that do not decide the database.
var otherConfigFiles = map[string][]string{
	"magento": {"app/etc/config.php"},
}

const maxConfigSize = 1 << 20

type untrustedFile struct {
	name string
	uid  uint32
}

// loadConfigFiles reads a framework's configuration files into memory, each from one open
// descriptor, and reports those that decide the database but are not root's alone.
func loadConfigFiles(fsys fs.FS, root, framework string) (fstest.MapFS, []untrustedFile) {
	files := fstest.MapFS{}
	var untrusted []untrustedFile
	load := func(rel string, decides bool) {
		name := path.Join(root, rel)
		f, err := fsys.Open(name)
		if err != nil {
			return
		}
		defer func() { _ = f.Close() }()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return
		}
		data, err := io.ReadAll(io.LimitReader(f, maxConfigSize))
		if err != nil {
			return
		}
		files[name] = &fstest.MapFile{Data: data, Mode: info.Mode(), ModTime: info.ModTime()}
		if uid, ok := collector.Owner(info); decides && ok && (uid != 0 || info.Mode().Perm()&0o022 != 0) {
			untrusted = append(untrusted, untrustedFile{rel, uid})
		}
	}
	for _, rel := range configFiles[framework] {
		load(rel, true)
	}
	for _, rel := range otherConfigFiles[framework] {
		load(rel, false)
	}
	return files, untrusted
}

func run(ctx context.Context, db querier, p *Profile, q string, args ...any) []map[string]string {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := db.query(ctx, q, args...)
	if err != nil {
		p.Issues = append(p.Issues, fmt.Sprintf("query failed: %v", err))
	}
	return rows
}

// Capabilities that amount to administration: whoever holds one can take over the site.
var wpAdminCaps = []string{"manage_options", "install_plugins", "edit_plugins", "activate_plugins", "edit_users", "promote_users", "create_users", "unfiltered_upload", "edit_themes", "update_core"}

// wordpressChecks finds administrators by what they can do, not by the role's name: an attacker
// with the database can grant manage_options to the editor role, or a capability directly to a
// user, or make a user super admin of a multisite network.
func wordpressChecks(ctx context.Context, db querier, t string, p *Profile) {
	adminRoles := []string{"administrator"}
	for _, r := range run(ctx, db, p, `SELECT LEFT(option_value, 1048576) AS option_value FROM `+t+`options WHERE option_name = ?`, t+"user_roles") {
		adminRoles = append(adminRoles, rolesWithCaps(r["option_value"], wpAdminCaps)...)
	}
	superAdmins := []string{}
	for _, r := range run(ctx, db, p, `SELECT LEFT(meta_value, 65535) AS meta_value FROM `+t+`sitemeta WHERE meta_key = 'site_admins'`) {
		superAdmins = serializedStrings(r["meta_value"])
	}
	rows := run(ctx, db, p, `SELECT u.ID, u.user_login, u.user_email, u.user_registered, LEFT(m.meta_value, 65535) AS caps FROM `+t+`users u
		JOIN `+t+`usermeta m ON m.user_id = u.ID AND m.meta_key = ? ORDER BY u.ID LIMIT `+fmt.Sprint(maxRows), t+"capabilities")
	truncated(p, rows, "users")
	for _, r := range rows {
		granted := grantedKeys(r["caps"])
		if slices.ContainsFunc(granted, func(k string) bool { return slices.Contains(adminRoles, k) || slices.Contains(wpAdminCaps, k) }) || slices.Contains(superAdmins, r["user_login"]) {
			p.Admins = append(p.Admins, Admin{ID: r["ID"], Name: r["user_login"], Email: r["user_email"], Created: r["user_registered"]})
		}
	}
	for _, r := range run(ctx, db, p, `SELECT option_name, LEFT(option_value, 65535) AS option_value FROM `+t+`options WHERE option_name IN ('siteurl', 'home', 'active_plugins', 'admin_email')`) {
		if r["option_name"] == "active_plugins" {
			p.Extensions = serializedStrings(r["option_value"])
			continue
		}
		p.Settings[r["option_name"]] = r["option_value"]
	}
	opts := run(ctx, db, p, `SELECT option_name, LEFT(option_value, 65535) AS option_value FROM `+t+`options WHERE `+scriptLike("option_value")+` ORDER BY option_id DESC LIMIT `+fmt.Sprint(maxRows))
	truncated(p, opts, "options with scripts")
	for _, r := range opts {
		p.Injected = append(p.Injected, scriptsIn("option "+r["option_name"], r["option_value"]))
	}
	posts := run(ctx, db, p, `SELECT ID, post_type, LEFT(post_content, 65535) AS post_content FROM `+t+`posts WHERE post_status = 'publish' AND `+scriptLike("post_content")+` ORDER BY ID DESC LIMIT `+fmt.Sprint(maxRows))
	truncated(p, posts, "posts with scripts")
	for _, r := range posts {
		p.Injected = append(p.Injected, scriptsIn(r["post_type"]+" "+r["ID"], r["post_content"]))
	}
}

// scriptPatterns are the shapes stored scripts take; skimmers rarely stop at a plain <script>.
var scriptPatterns = []string{"<script", "<iframe", "javascript:", "eval(", "atob(", "fromcharcode", "document.write", "onerror="}

// scriptLike builds a SQL condition matching any script pattern in col, case-insensitively.
func scriptLike(col string) string {
	parts := make([]string, len(scriptPatterns))
	for i, pat := range scriptPatterns {
		parts[i] = "LOWER(" + col + ") LIKE '%" + pat + "%'"
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

func truncated(p *Profile, rows []map[string]string, what string) {
	if len(rows) >= maxRows {
		p.Issues = append(p.Issues, fmt.Sprintf("%s: only the first %d rows read", what, maxRows))
	}
}

var roleRe = regexp.MustCompile(`s:\d+:"([a-z0-9_-]+)";a:\d+:\{s:4:"name";s:\d+:"[^"]*";s:12:"capabilities";a:\d+:\{([^}]*)\}`)

// rolesWithCaps returns the roles of a serialized wp_user_roles value that hold any of caps.
func rolesWithCaps(serialized string, caps []string) []string {
	var out []string
	for _, m := range roleRe.FindAllStringSubmatch(serialized, -1) {
		if slices.ContainsFunc(grantedKeys(m[2]), func(k string) bool { return slices.Contains(caps, k) }) {
			out = append(out, m[1])
		}
	}
	return out
}

var grantedRe = regexp.MustCompile(`s:\d+:"([^"]+)";b:1;`)

// grantedKeys lists the keys set to true in a serialized capability array.
func grantedKeys(serialized string) []string {
	var out []string
	for _, m := range grantedRe.FindAllStringSubmatch(serialized, -1) {
		out = append(out, m[1])
	}
	return out
}

func magentoChecks(ctx context.Context, db querier, t string, p *Profile) {
	for _, r := range run(ctx, db, p, `SELECT user_id, username, email, created, logdate, is_active FROM `+t+`admin_user LIMIT `+fmt.Sprint(maxRows)) {
		p.Admins = append(p.Admins, Admin{ID: r["user_id"], Name: r["username"], Email: r["email"], Created: r["created"], LastLogin: r["logdate"], Active: r["is_active"]})
	}
	for _, r := range run(ctx, db, p, `SELECT path, scope, scope_id, LEFT(value, 65535) AS value FROM `+t+`core_config_data WHERE path IN ('web/unsecure/base_url', 'web/secure/base_url') OR `+scriptLike("value")+` ORDER BY config_id DESC LIMIT `+fmt.Sprint(maxRows)) {
		if strings.HasSuffix(r["path"], "base_url") && len(scriptsIn("", r["value"]).Domains) == 0 && !strings.Contains(strings.ToLower(r["value"]), "<script") {
			p.Settings[r["path"]+"@"+r["scope"]+":"+r["scope_id"]] = r["value"]
			continue
		}
		p.Injected = append(p.Injected, scriptsIn("config "+r["path"]+" ("+r["scope"]+" "+r["scope_id"]+")", r["value"]))
	}
	for _, table := range []string{"cms_block", "cms_page"} {
		id := map[string]string{"cms_block": "block_id", "cms_page": "page_id"}[table]
		for _, r := range run(ctx, db, p, `SELECT `+id+` AS id, identifier, LEFT(content, 65535) AS content FROM `+t+table+` WHERE `+scriptLike("content")+` LIMIT `+fmt.Sprint(maxRows)) {
			p.Injected = append(p.Injected, scriptsIn(table+" "+r["identifier"]+" ("+r["id"]+")", r["content"]))
		}
	}
}

// drupalChecks treats as administrators the users holding any role flagged is_admin in the
// configuration (the role is not necessarily called administrator), and user 1, who bypasses
// every permission check.
func drupalChecks(ctx context.Context, db querier, t string, p *Profile) {
	roles := []any{"administrator"}
	for _, r := range run(ctx, db, p, `SELECT name FROM `+t+`config WHERE name LIKE 'user.role.%' AND (data LIKE '%s:8:"is_admin";b:1;%'
		OR data LIKE '%"administer permissions"%' OR data LIKE '%"administer users"%' OR data LIKE '%"administer modules"%')`) {
		if id := strings.TrimPrefix(r["name"], "user.role."); !slices.Contains(roles, any(id)) {
			roles = append(roles, id)
		}
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(roles)), ",")
	for _, r := range run(ctx, db, p, `SELECT DISTINCT u.uid, u.name, u.mail, u.created, u.access, u.status FROM `+t+`users_field_data u
		LEFT JOIN `+t+`user__roles r ON r.entity_id = u.uid WHERE u.uid = 1 OR r.roles_target_id IN (`+placeholders+`) LIMIT `+fmt.Sprint(maxRows), roles...) {
		p.Admins = append(p.Admins, Admin{ID: r["uid"], Name: r["name"], Email: r["mail"], Created: unixTime(r["created"]), LastLogin: unixTime(r["access"]), Active: r["status"]})
	}
	for _, r := range run(ctx, db, p, `SELECT LEFT(data, 1048576) AS data FROM `+t+`config WHERE name = 'core.extension'`) {
		p.Extensions = serializedKeysUnder(r["data"], "module")
	}
	for _, r := range run(ctx, db, p, `SELECT entity_id, bundle, LEFT(body_value, 65535) AS body_value FROM `+t+`node__body WHERE `+scriptLike("body_value")+` LIMIT `+fmt.Sprint(maxRows)) {
		p.Injected = append(p.Injected, scriptsIn(r["bundle"]+" "+r["entity_id"], r["body_value"]))
	}
}

// drupal7Checks counts as administrators user 1, who bypasses every permission, and the users
// of roles that may administer users or permissions, whatever the role is called.
func drupal7Checks(ctx context.Context, db querier, t string, p *Profile) {
	for _, r := range run(ctx, db, p, `SELECT DISTINCT u.uid, u.name, u.mail, u.created, u.access, u.status FROM `+t+`users u
		LEFT JOIN `+t+`users_roles ur ON ur.uid = u.uid
		WHERE u.uid = 1 OR ur.rid IN (SELECT rid FROM `+t+`role_permission WHERE permission IN ('administer permissions', 'administer users', 'administer modules'))
		ORDER BY u.uid LIMIT `+fmt.Sprint(maxRows)) {
		p.Admins = append(p.Admins, Admin{ID: r["uid"], Name: r["name"], Email: r["mail"], Created: unixTime(r["created"]), LastLogin: unixTime(r["access"]), Active: r["status"]})
	}
	for _, r := range run(ctx, db, p, `SELECT name FROM `+t+`system WHERE type = 'module' AND status = 1 LIMIT 1000`) {
		p.Extensions = append(p.Extensions, r["name"])
	}
}

var (
	scriptSrc     = regexp.MustCompile(`(?i)<(?:script|iframe)[^>]*\bsrc\s*=\s*["']?(?:https?:)?//([^/"'\s>:]+)`)
	inlineScript  = regexp.MustCompile(`(?i)<script(?:\s[^>]*)?>\s*[^<\s]`)
	urlInScript   = regexp.MustCompile(`(?i)https?://([a-z0-9.-]+\.[a-z]{2,})`)
	serializedStr = regexp.MustCompile(`s:\d+:"([^"]*)"`)
)

// scriptsIn lists the domains scripts in content load from or talk to.
func scriptsIn(where, content string) Injected {
	lower := strings.ToLower(content)
	inj := Injected{Where: where, Inline: inlineScript.MatchString(content) || slices.ContainsFunc(scriptPatterns[2:], func(p string) bool { return strings.Contains(lower, p) })}
	add := func(d string) {
		d = strings.ToLower(d)
		if !slices.Contains(inj.Domains, d) {
			inj.Domains = append(inj.Domains, d)
		}
	}
	for _, m := range scriptSrc.FindAllStringSubmatch(content, -1) {
		add(m[1])
	}
	if inj.Inline {
		for _, m := range urlInScript.FindAllStringSubmatch(content, -1) {
			add(m[1])
		}
	}
	return inj
}

// serializedStrings returns the string values of a PHP serialized array.
func serializedStrings(s string) []string {
	var out []string
	for _, m := range serializedStr.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// serializedKeysUnder returns the keys of the array stored under key in a PHP serialized
// structure, such as the module list in Drupal's core.extension.
func serializedKeysUnder(s, key string) []string {
	i := strings.Index(s, `s:`+fmt.Sprint(len(key))+`:"`+key+`";a:`)
	if i < 0 {
		return nil
	}
	body := s[i:]
	if end := strings.Index(body, "}"); end >= 0 {
		body = body[:end]
	}
	var out []string
	for j, m := range serializedStr.FindAllStringSubmatch(body, -1) {
		if j > 0 {
			out = append(out, m[1])
		}
	}
	return out
}

func unixTime(s string) string {
	var sec int64
	if _, err := fmt.Sscan(s, &sec); err != nil || sec == 0 {
		return s
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

// connectMySQL opens the database only at an endpoint endpoint() trusts, through a dialer that
// bounds what the server can send. Only SELECT statements are ever sent.
func connectMySQL(ctx context.Context, src collector.Source, cfg dbConfig, allowed []string) (querier, func(), error) {
	network, addr, err := endpoint(ctx, src, cfg, allowed)
	if err != nil {
		return nil, nil, err
	}
	registerDialers()
	mc := mysql.NewConfig()
	mc.User, mc.Passwd, mc.DBName = cfg.User, cfg.Password, cfg.Name
	mc.Timeout, mc.ReadTimeout, mc.WriteTimeout = connectTimeout, queryTimeout, queryTimeout
	mc.Net, mc.Addr = dialTCP, addr
	if network == "unix" {
		mc.Net = dialUnix
	}
	mc.MaxAllowedPacket = 4 << 20

	db, err := sql.Open("mysql", mc.FormatDSN())
	if err != nil {
		return nil, nil, err
	}
	db.SetMaxOpenConns(1)
	pingCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return sqlQuerier{db}, func() { _ = db.Close() }, nil
}

type sqlQuerier struct{ db *sql.DB }

func (q sqlQuerier) query(ctx context.Context, query string, args ...any) ([]map[string]string, error) {
	rows, err := q.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []map[string]string
	for rows.Next() && len(out) < maxRows {
		values := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return out, err
		}
		row := map[string]string{}
		for i, c := range cols {
			row[c] = values[i].String
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
