package apps

import (
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

// dbConfig is how an application reaches its database. Password never leaves the sensor.
type dbConfig struct {
	Driver   string
	Host     string
	Port     string
	Socket   string
	Name     string
	User     string
	Password string
	Prefix   string
}

// String describes the database without its credentials.
func (c dbConfig) String() string {
	where := c.Host
	if c.Socket != "" {
		where = c.Socket
	} else if c.Port != "" {
		where += ":" + c.Port
	}
	return c.Name + "@" + where
}

// appConfig is what the application's own configuration says about it.
type appConfig struct {
	DB       *dbConfig
	Settings map[string]string
	Warnings []string
	Modules  []string
}

// validPrefix guards table prefixes, which are written into SQL: the configuration file that
// holds them may have been written by an attacker.
var validPrefix = regexp.MustCompile(`^[A-Za-z0-9_]{0,32}$`)

var (
	wpDefine   = regexp.MustCompile(`define\(\s*['"](\w+)['"]\s*,\s*(?:['"]((?:[^'"\\]|\\.)*)['"]|(true|false|\d+))\s*\)`)
	wpPrefix   = regexp.MustCompile(`\$table_prefix\s*=\s*['"]([^'"]*)['"]`)
	phpArrayKV = regexp.MustCompile(`['"](\w+)['"]\s*=>\s*['"]((?:[^'"\\]|\\.)*)['"]`)
	// phpEnvKV matches 'key' => getenv('NAME') ?: 'default', the usual way containerised
	// applications take their settings from the environment.
	phpEnvKV   = regexp.MustCompile(`['"](\w+)['"]\s*=>\s*getenv\(\s*['"](\w+)['"][^)]*\)\s*\?:\s*['"]((?:[^'"\\]|\\.)*)['"]`)
	magentoMod = regexp.MustCompile(`['"]([A-Za-z0-9]+_[A-Za-z0-9]+)['"]\s*=>\s*1`)
	dotenvLine = regexp.MustCompile(`^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$`)
)

func readConfig(fsys fs.FS, root, framework string, env map[string]string, issues *collector.Issues) appConfig {
	switch framework {
	case "wordpress":
		return wordpressConfig(fsys, root, issues)
	case "magento":
		return magentoConfig(fsys, root, issues)
	case "drupal", "drupal7":
		return drupalConfig(fsys, root, env, issues)
	case "laravel":
		return laravelConfig(fsys, root, issues)
	}
	return appConfig{}
}

func read(fsys fs.FS, name string, issues *collector.Issues) string {
	data, err := fs.ReadFile(fsys, name)
	issues.Add(err)
	return string(data)
}

func wordpressConfig(fsys fs.FS, root string, issues *collector.Issues) appConfig {
	src := read(fsys, path.Join(root, "wp-config.php"), issues)
	if src == "" {
		// wp-config.php may live one level above the web root.
		src = read(fsys, path.Join(path.Dir(root), "wp-config.php"), issues)
	}
	cfg := appConfig{Settings: map[string]string{}}
	defines := map[string]string{}
	for _, m := range wpDefine.FindAllStringSubmatch(stripComments(src), -1) {
		defines[m[1]] = m[2] + m[3]
	}
	if defines["DB_NAME"] != "" {
		db := &dbConfig{Driver: "mysql", Name: defines["DB_NAME"], User: defines["DB_USER"], Password: defines["DB_PASSWORD"], Prefix: "wp_"}
		db.Host, db.Port, db.Socket = splitHost(defines["DB_HOST"])
		if m := wpPrefix.FindStringSubmatch(src); m != nil {
			db.Prefix = m[1]
		}
		cfg.DB = db
	}
	for _, flag := range []string{"WP_DEBUG", "WP_DEBUG_DISPLAY", "SCRIPT_DEBUG"} {
		if defines[flag] == "true" {
			cfg.Warnings = append(cfg.Warnings, flag+" is enabled")
		}
	}
	if defines["DISALLOW_FILE_EDIT"] != "true" {
		cfg.Warnings = append(cfg.Warnings, "DISALLOW_FILE_EDIT is not set: administrators can edit PHP files from the dashboard")
	}
	return cfg
}

func magentoConfig(fsys fs.FS, root string, issues *collector.Issues) appConfig {
	env := read(fsys, path.Join(root, "app/etc/env.php"), issues)
	cfg := appConfig{Settings: map[string]string{}}
	if i := strings.Index(env, "'connection'"); i >= 0 {
		kv := map[string]string{}
		for _, m := range phpArrayKV.FindAllStringSubmatch(env[i:], -1) {
			if _, seen := kv[m[1]]; !seen {
				kv[m[1]] = m[2]
			}
		}
		db := &dbConfig{Driver: "mysql", Name: kv["dbname"], User: kv["username"], Password: kv["password"]}
		db.Host, db.Port, db.Socket = splitHost(kv["host"])
		cfg.DB = db
	}
	for _, m := range phpArrayKV.FindAllStringSubmatch(env, -1) {
		switch m[1] {
		case "table_prefix":
			if cfg.DB != nil {
				cfg.DB.Prefix = m[2]
			}
		case "MAGE_MODE":
			cfg.Settings["mode"] = m[2]
			if m[2] != "production" {
				cfg.Warnings = append(cfg.Warnings, "MAGE_MODE is "+m[2]+", not production")
			}
		case "frontName":
			cfg.Settings["admin_path"] = m[2]
		}
	}
	for _, m := range magentoMod.FindAllStringSubmatch(read(fsys, path.Join(root, "app/etc/config.php"), issues), -1) {
		cfg.Modules = append(cfg.Modules, m[1])
	}
	return cfg
}

// drupalConfig reads settings.php and then settings.local.php, which Drupal includes after it
// and which therefore wins. Values may come from the environment with getenv() ?: default.
func drupalConfig(fsys fs.FS, root string, env map[string]string, issues *collector.Issues) appConfig {
	cfg := appConfig{Settings: map[string]string{}}
	kv := map[string]string{}
	for _, name := range []string{"sites/default/settings.php", "sites/default/settings.local.php"} {
		src := stripComments(read(fsys, path.Join(root, name), issues))
		i := strings.Index(src, "$databases")
		if i < 0 {
			continue
		}
		local := map[string]string{}
		for _, m := range phpEnvKV.FindAllStringSubmatch(src[i:], -1) {
			if _, seen := local[m[1]]; !seen {
				local[m[1]] = cmpOr(env[m[2]], m[3])
			}
		}
		for _, m := range phpArrayKV.FindAllStringSubmatch(src[i:], -1) {
			if _, seen := local[m[1]]; !seen {
				local[m[1]] = m[2]
			}
		}
		for k, v := range local {
			kv[k] = v
		}
	}
	if kv["database"] == "" || (kv["driver"] != "" && kv["driver"] != "mysql") {
		if kv["driver"] != "" && kv["driver"] != "mysql" {
			issues.Add(errUnsupportedDriver(kv["driver"]))
		}
		return cfg
	}
	cfg.DB = &dbConfig{Driver: "mysql", Name: kv["database"], User: kv["username"], Password: kv["password"], Host: kv["host"], Port: kv["port"], Prefix: kv["prefix"]}
	if cfg.DB.Host == "" {
		cfg.DB.Host = "localhost"
	}
	return cfg
}

func laravelConfig(fsys fs.FS, root string, issues *collector.Issues) appConfig {
	env := map[string]string{}
	for _, line := range strings.Split(read(fsys, path.Join(root, ".env"), issues), "\n") {
		if m := dotenvLine.FindStringSubmatch(line); m != nil && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			env[m[1]] = strings.Trim(m[2], `"'`)
		}
	}
	cfg := appConfig{Settings: map[string]string{"env": env["APP_ENV"]}}
	if strings.EqualFold(env["APP_DEBUG"], "true") {
		cfg.Warnings = append(cfg.Warnings, "APP_DEBUG is true: errors expose code, environment and credentials")
	}
	if env["APP_KEY"] == "" {
		cfg.Warnings = append(cfg.Warnings, "APP_KEY is empty")
	}
	switch env["DB_CONNECTION"] {
	case "mysql", "mariadb":
		db := &dbConfig{Driver: "mysql", Name: env["DB_DATABASE"], User: env["DB_USERNAME"], Password: env["DB_PASSWORD"], Host: env["DB_HOST"], Port: env["DB_PORT"], Socket: env["DB_SOCKET"]}
		if db.Name != "" {
			cfg.DB = db
		}
	case "":
	default:
		issues.Add(errUnsupportedDriver(env["DB_CONNECTION"]))
	}
	return cfg
}

// splitHost understands the host forms CMS configurations use: host, host:port, and
// localhost:/path/to/socket.
func splitHost(h string) (host, port, socket string) {
	host, rest, found := strings.Cut(h, ":")
	if !found {
		return host, "", ""
	}
	if strings.HasPrefix(rest, "/") {
		return host, "", rest
	}
	return host, rest, ""
}

var phpComment = regexp.MustCompile(`(?m)(^\s*(//|#).*$)|(/\*[\s\S]*?\*/)`)

// stripComments removes whole-line and block comments, which in sample configurations often
// hold credentials that are not the ones in use.
func stripComments(src string) string {
	return phpComment.ReplaceAllString(src, "")
}

type errUnsupportedDriver string

func (e errUnsupportedDriver) Error() string {
	return "database driver " + string(e) + " not supported yet"
}
