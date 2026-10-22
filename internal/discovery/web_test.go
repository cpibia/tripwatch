package discovery

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
)

func text(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s), Mode: 0o644} }

// magentoNginx is the nginx configuration shipped with Magento, trimmed, with two extra
// entry points in the PHP allow-list as found on a compromised production server.
const magentoNginx = `
upstream fastcgi_backend {
    server unix:/run/php/php8.1-fpm.sock;
}
server {
    listen 80;
    listen [::]:80;
    server_name www.commerce.example.com commerce.example.com;
    set $MAGE_ROOT /var/www/commerce;
    access_log /var/log/nginx/commerce.access.log;
    include /etc/nginx/conf.d/magento.sample;
}
`

const magentoSample = `
root $MAGE_ROOT/pub;
index index.php;
location ~ ^/setup($|/) {
    root $MAGE_ROOT;
    location ~ ^/setup/index.php {
        fastcgi_pass fastcgi_backend;
    }
}
location / {
    try_files $uri $uri/ /index.php$is_args$args;
}
location /media/ {
    try_files $uri $uri/ /get.php$is_args$args;
    location ~ ^/media/theme_customization/.*\.xml {
        deny all;
    }
}
location /media/custom_options/ {
    deny all;
}
location /errors/ {
    location ~* \.xml$ {
        deny all;
    }
}
# PHP entry point for main application
location ~ ^/(index|get|static|errors/report|errors/404|errors/503|health_check|adminer|tools/bridge)\.php$ {
    try_files $uri =404;
    fastcgi_pass   fastcgi_backend;
    fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
}
location ~* (\.php$|\.phtml$|\.htaccess$|\.git) {
    deny all;
}
`

const debianNginx = `
user www-data;
events { worker_connections 768; }
http {
    # a comment with ; and { inside
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    include /etc/nginx/conf.d/*.conf;
    include sites-enabled/*;
}
`

func nginxHost() fstest.MapFS {
	return fstest.MapFS{
		"etc/nginx/nginx.conf":             text(debianNginx),
		"etc/nginx/conf.d/magento.sample":  text(magentoSample),
		"etc/nginx/sites-enabled/commerce": text(magentoNginx),
		"etc/nginx/sites-enabled/api":      text(`server { listen 443 ssl; server_name "api.example.com"; location / { proxy_pass http://127.0.0.1:8080; } }`),
		"etc/nginx/conf.d/loop.conf":       text(`# included by http, includes nothing`),
	}
}

func TestNginxSites(t *testing.T) {
	sites, _, issues := NginxSites(nginxHost())
	if len(issues) != 0 {
		t.Fatalf("issues = %v", issues)
	}
	if len(sites) != 2 {
		t.Fatalf("sites = %+v", sites)
	}

	api, commerce := sites[0], sites[1]
	if !slices.Equal(api.Names, []string{"api.example.com"}) || !slices.Equal(api.Upstreams, []string{"http://127.0.0.1:8080"}) {
		t.Errorf("api = %+v", api)
	}
	if api.Root != "/etc/nginx/html" || !slices.Equal(api.AccessLogs, []string{"/var/log/nginx/access.log"}) {
		t.Errorf("api defaults: root %q logs %v", api.Root, api.AccessLogs)
	}

	if commerce.Root != "/var/www/commerce/pub" {
		t.Errorf("root = %q, want $MAGE_ROOT expanded", commerce.Root)
	}
	if !slices.Equal(commerce.Names, []string{"www.commerce.example.com", "commerce.example.com"}) || !slices.Equal(commerce.Listen, []string{"80", "[::]:80"}) {
		t.Errorf("commerce = %+v", commerce)
	}
	if !slices.Equal(commerce.AccessLogs, []string{"/var/log/nginx/commerce.access.log"}) || commerce.Config != "/etc/nginx/sites-enabled/commerce" {
		t.Errorf("logs %v config %q", commerce.AccessLogs, commerce.Config)
	}
	if !slices.Equal(commerce.Upstreams, []string{"fastcgi_backend"}) {
		t.Errorf("upstreams = %v", commerce.Upstreams)
	}
}

func TestNginxExecutes(t *testing.T) {
	sites, _, _ := NginxSites(nginxHost())
	commerce := sites[1]

	tests := map[string]bool{
		"/index.php":        true,
		"/errors/503.php":   true,
		"/adminer.php":      true,
		"/tools/bridge.php": true,
		"/setup/index.php":  true,
		"/helper.php":       false,
		"/media/custom_options/quote/s/e/shell.php": false,
		"/media/customer_address/s/e/sess_x.php":    false,
		"/media/wysiwyg/js/app.js":                  false,
		"/errors/local.xml":                         false,
		"/static/frontend/x.js":                     false,
		"/get.php":                                  true,
		"/media/theme_customization/a.xml":          false,
	}
	for uri, want := range tests {
		if got := commerce.Executes(uri); got != want {
			t.Errorf("Executes(%q) = %v, want %v", uri, got, want)
		}
	}
}

func TestFindLocationOrder(t *testing.T) {
	loc := func(mod, pattern string, executes bool, nested ...Location) Location {
		l := Location{Modifier: mod, Pattern: pattern, Executes: executes, Locations: nested}
		if l.isRegex() {
			l.re = compileLocation(mod, pattern)
		}
		return l
	}
	locs := []Location{
		loc("=", "/exact.php", true),
		loc("^~", "/static/", false),
		loc("", "/uploads/", false, loc("~", `\.php$`, false)),
		loc("~*", `\.PHP$`, true),
		loc("~", `[unbalanced`, false),
	}

	tests := []struct {
		uri  string
		want string
	}{
		{"/exact.php", "/exact.php"},
		{"/static/x.php", "/static/"},
		{"/uploads/x.php", `\.php$`},
		{"/other/x.php", `\.PHP$`},
		{"/other/x.txt", `[unbalanced`},
	}
	for _, tt := range tests {
		got := findLocation(locs, tt.uri)
		if got == nil || got.Pattern != tt.want {
			t.Errorf("findLocation(%q) = %+v, want pattern %q", tt.uri, got, tt.want)
		}
	}
	if findLocation(locs[:3], "/nothing") != nil {
		t.Error("no location should match /nothing")
	}
}

func TestTokenizeNginx(t *testing.T) {
	got := tokenizeNginx("set $a \"x;y\" ; # comment {\nreturn 200 'it\\'s';log a\\ b;")
	want := []string{"set", "$a", "x;y", ";", "return", "200", "it's", ";", "log", "a b", ";"}
	if !slices.Equal(got, want) {
		t.Errorf("tokens = %q, want %q", got, want)
	}
}

func TestNginxIncludeLoop(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/nginx/nginx.conf": text("http { include loop.conf; }"),
		"etc/nginx/loop.conf":  text("include loop.conf;"),
	}
	_, _, issues := NginxSites(fsys)
	if len(issues) == 0 {
		t.Error("an include loop must be reported, not followed forever")
	}
}

func apacheHost() fstest.MapFS {
	return fstest.MapFS{
		"etc/apache2/apache2.conf": text("ServerRoot \"/etc/apache2\"\n" +
			"ErrorLog ${APACHE_LOG_DIR}/error.log\n" +
			"IncludeOptional mods-enabled/*.load\n" +
			"IncludeOptional conf-enabled/*.conf\n" +
			"IncludeOptional sites-enabled/*.conf\n"),
		"etc/apache2/envvars":                      text("export APACHE_RUN_USER=www-data\n: ${APACHE_LOG_DIR:=/var/log/apache2$SUFFIX}\nexport APACHE_LOG_DIR\n"),
		"etc/apache2/mods-enabled/proxy_fcgi.load": text("LoadModule proxy_fcgi_module /usr/lib/apache2/modules/mod_proxy_fcgi.so\n"),
		"etc/apache2/conf-enabled/php8.1-fpm.conf": text("<FilesMatch \".+\\.ph(?:ar|p|tml)$\">\n" +
			"    SetHandler \"proxy:unix:/run/php/php8.1-fpm.sock|fcgi://localhost\"\n</FilesMatch>\n"),
		"etc/apache2/sites-enabled/blog.conf": text("<VirtualHost *:80>\n" +
			"    ServerName blog.example.com\n    ServerAlias www.blog.example.com \\\n        old.blog.example.com\n" +
			"    DocumentRoot /var/www/blog\n" +
			"    CustomLog ${APACHE_LOG_DIR}/blog_access.log combined\n" +
			"    ErrorLog \"|/usr/bin/rotatelogs /var/log/x 86400\"\n" +
			"    ProxyPass /api http://127.0.0.1:9000/\n" +
			"</VirtualHost>\n"),
	}
}

func TestApacheSites(t *testing.T) {
	sites, _, issues := ApacheSites(apacheHost())
	if len(issues) != 0 {
		t.Fatalf("issues = %v", issues)
	}
	if len(sites) != 1 {
		t.Fatalf("sites = %+v", sites)
	}
	blog := sites[0]
	want := Site{
		Server:           ServerApache,
		Config:           "/etc/apache2/sites-enabled/blog.conf",
		Names:            []string{"blog.example.com", "www.blog.example.com", "old.blog.example.com"},
		Listen:           []string{"*:80"},
		Root:             "/var/www/blog",
		AccessLogs:       []string{"/var/log/apache2/blog_access.log"},
		Upstreams:        []string{"http://127.0.0.1:9000/"},
		ScriptExtensions: phpHandlerExtensions,
	}
	if !equalSites(blog, want) {
		t.Errorf("site:\n got  %+v\n want %+v", blog, want)
	}
	if !blog.Executes("/wp-login.php") || !blog.Executes("/x.PHTML") || blog.Executes("/x.html") {
		t.Error("PHP handler not applied")
	}
}

func TestApacheWithoutPHPAndMainServer(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/httpd/conf/httpd.conf": text("ServerRoot /etc/httpd\nDocumentRoot \"/var/www/html\"\nServerName static.example.com\nCustomLog logs/access_log combined\n"),
	}
	sites, _, _ := ApacheSites(fsys)
	if len(sites) != 1 || sites[0].Root != "/var/www/html" || sites[0].AccessLogs[0] != "/etc/httpd/logs/access_log" {
		t.Fatalf("sites = %+v", sites)
	}
	if sites[0].Executes("/index.php") {
		t.Error("PHP is not configured: nothing executes")
	}
}

const caddyConfig = `
{
	email admin@example.com
}

(common) {
	header -Server
}

shop.example.com, www.shop.example.com {
	root * /srv/shop/public
	php_fastcgi unix//run/php/php8.3-fpm.sock
	file_server
	log {
		output file /var/log/caddy/shop.log
	}
}

api.example.com {
	reverse_proxy localhost:8080 # backend
}
`

func TestCaddySites(t *testing.T) {
	sites, _, issues := CaddySites(fstest.MapFS{"etc/caddy/Caddyfile": text(caddyConfig)})
	if len(issues) != 0 || len(sites) != 2 {
		t.Fatalf("sites = %+v, issues = %v", sites, issues)
	}
	shop, api := sites[0], sites[1]
	if !slices.Equal(shop.Names, []string{"shop.example.com", "www.shop.example.com"}) || shop.Root != "/srv/shop/public" {
		t.Errorf("shop = %+v", shop)
	}
	if !slices.Equal(shop.AccessLogs, []string{"/var/log/caddy/shop.log"}) || !shop.Executes("/index.php") {
		t.Errorf("shop logs %v, executes php %v", shop.AccessLogs, shop.Executes("/index.php"))
	}
	if !slices.Equal(api.Upstreams, []string{"localhost:8080"}) || api.Executes("/index.php") {
		t.Errorf("api = %+v", api)
	}
}

func TestMissingWebServers(t *testing.T) {
	inv := Inspect(fstest.MapFS{})
	if len(inv.Sites) != 0 || len(inv.Applications) != 0 || len(inv.Issues) != 0 {
		t.Errorf("inventory = %+v", inv)
	}
}

func appsHost() fstest.MapFS {
	fsys := nginxHost()
	files := map[string]string{
		"var/www/commerce/bin/magento":                                                "#!/usr/bin/env php",
		"var/www/commerce/app/etc/di.xml":                                             "<config/>",
		"var/www/commerce/pub/index.php":                                              "<?php",
		"var/www/commerce/vendor/magento/magento2-base/composer.json":                 `{"name": "magento/magento2-base", "version": "2.4.7-p3"}`,
		"var/www/commerce/vendor/acme/lib/package.json":                               "{}",
		"var/www/blog/wp-includes/version.php":                                        "<?php\n$wp_version = '6.6.2';\n",
		"var/www/html/readme.txt":                                                     "",
		"srv/shop/artisan":                                                            "",
		"srv/shop/bootstrap/app.php":                                                  "",
		"srv/shop/public/index.php":                                                   "",
		"srv/shop/vendor/laravel/framework/src/Illuminate/Foundation/Application.php": "const VERSION = '11.9.2';",
		"srv/shop/node_modules/x/package.json":                                        "{}",
		"opt/api/Cargo.toml":                                                          "",
		"home/deploy/app/manage.py":                                                   "",
		"home/deploy/.cache/x/package.json":                                           "{}",
		"data/sites/legacy/bin/magento":                                               "",
		"data/sites/legacy/app/etc/di.xml":                                            "",
		"data/sites/legacy/pub/index.php":                                             "",
		"proc/10/comm":                                                                "nginx\n",
		"proc/11/comm":                                                                "php-fpm8.1\n",
		"proc/12/comm":                                                                "python3.11\n",
		"proc/13/comm":                                                                "bash\n",
		"proc/self/comm":                                                              "sensor\n",
	}
	for name, content := range files {
		fsys[name] = text(content)
	}
	fsys["etc/nginx/sites-enabled/legacy"] = text(`server { server_name legacy.example.com; root /data/sites/legacy/pub; }`)
	fsys["etc/nginx/sites-enabled/html"] = text(`server { server_name html.example.com; root /var/www/html; }`)
	return fsys
}

func TestInspect(t *testing.T) {
	inv := Inspect(appsHost())

	type app struct{ path, framework, version string }
	var got []app
	for _, a := range inv.Applications {
		got = append(got, app{a.Path, a.Framework, a.Version})
	}
	want := []app{
		{"/data/sites/legacy", "magento", ""},
		{"/home/deploy/app", "django", ""},
		{"/opt/api", "rust", ""},
		{"/srv/shop", "laravel", "11.9.2"},
		{"/var/www/blog", "wordpress", "6.6.2"},
		{"/var/www/commerce", "magento", "2.4.7-p3"},
		{"/var/www/html", "unknown", ""},
	}
	if !slices.Equal(got, want) {
		t.Errorf("applications:\n got  %v\n want %v", got, want)
	}

	for _, a := range inv.Applications {
		if a.Path == "/var/www/commerce" && !slices.Equal(a.Sites, []string{"www.commerce.example.com"}) {
			t.Errorf("commerce sites = %v", a.Sites)
		}
	}
	if !slices.Equal(inv.Runtimes, []string{"nginx", "php-fpm", "python"}) {
		t.Errorf("runtimes = %v", inv.Runtimes)
	}
}

func equalSites(a, b Site) bool {
	return a.Server == b.Server && a.Config == b.Config && a.Root == b.Root &&
		slices.Equal(a.Names, b.Names) && slices.Equal(a.Listen, b.Listen) &&
		slices.Equal(a.AccessLogs, b.AccessLogs) && slices.Equal(a.ErrorLogs, b.ErrorLogs) &&
		slices.Equal(a.Upstreams, b.Upstreams) && slices.Equal(a.ScriptExtensions, b.ScriptExtensions)
}

// Seven files that include each other through a glob would take 7^10 file reads with only a
// depth limit; the budget must stop the parse quickly and say so.
func TestNginxIncludeFanOut(t *testing.T) {
	fsys := fstest.MapFS{"etc/nginx/nginx.conf": text("http { include /var/www/app/*.conf; }")}
	for i := range 7 {
		fsys[fmt.Sprintf("var/www/app/%d.conf", i)] = text("include /var/www/app/*.conf;")
	}

	done := make(chan collector.Issues, 1)
	go func() { _, _, issues := NginxSites(fsys); done <- issues }()
	select {
	case issues := <-done:
		if !slices.ContainsFunc(issues, func(s string) bool { return strings.Contains(s, "parsing stopped") }) {
			t.Errorf("issues = %v, want the budget reported", issues)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("include fan-out did not terminate")
	}
}

func TestNginxDeepNesting(t *testing.T) {
	deep := "http { server { root /srv; } " + strings.Repeat("a {", 100000) + strings.Repeat("}", 100000) + " }"
	sites, _, issues := NginxSites(fstest.MapFS{"etc/nginx/nginx.conf": text(deep)})
	if len(sites) != 1 || !slices.ContainsFunc(issues, func(s string) bool { return strings.Contains(s, "nested deeper") }) {
		t.Errorf("sites = %d, issues = %v", len(sites), issues)
	}
}

func TestInspectListsConfigFiles(t *testing.T) {
	inv := Inspect(nginxHost())
	var got []string
	for _, f := range inv.ConfigFiles {
		got = append(got, f.Path)
		if len(f.SHA256) != 64 {
			t.Errorf("%s has no hash", f.Path)
		}
	}
	want := []string{"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/loop.conf", "/etc/nginx/sites-enabled/api", "/etc/nginx/sites-enabled/commerce", "/etc/nginx/conf.d/magento.sample"}
	if !slices.Equal(got, want) {
		t.Errorf("config files = %v, want %v", got, want)
	}
}

func TestDefaultIndexDoesNotHideApplications(t *testing.T) {
	fsys := fstest.MapFS{
		"var/www/html/index.html":                   text("Apache2 Default Page"),
		"var/www/html/blog/wp-includes/version.php": text("<?php $wp_version = '6.6';"),
		"var/www/html/tools/package.json":           text("{}"),
		"var/www/html/store/bin/magento":            text(""),
		"var/www/html/store/app/etc/di.xml":         text(""),
		"etc/nginx/nginx.conf":                      text("http { server { server_name blog.example.com; root /var/www/html/blog; } server { server_name www.example.com; root /var/www/html; } }"),
	}
	inv := Inspect(fsys)
	type app struct{ path, framework, sites string }
	var got []app
	for _, a := range inv.Applications {
		got = append(got, app{a.Path, a.Framework, strings.Join(a.Sites, ",")})
	}
	want := []app{
		{"/var/www/html", "static", "www.example.com"},
		{"/var/www/html/blog", "wordpress", "blog.example.com"},
		{"/var/www/html/store", "magento", ""},
	}
	if !slices.Equal(got, want) {
		t.Errorf("applications = %v, want %v", got, want)
	}
}
