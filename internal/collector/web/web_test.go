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
		"var/www/commerce/.git/HEAD":                                                             text("ref: refs/heads/main"),
		"var/www/commerce/generated/link":                                                        {Data: []byte("../vendor"), Mode: 0o777 | 1<<27},
	}
	return fsys
}

func run(t *testing.T, fsys fstest.MapFS) Result {
	t.Helper()
	out, err := Collector{}.Collect(context.Background(), collector.Source{FS: fsys})
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
	}
	slices.SortFunc(got, func(a, b finding) int { return strings.Compare(a.path, b.path) })
	slices.SortFunc(want, func(a, b finding) int { return strings.Compare(a.path, b.path) })
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got  %+v\n want %+v", got, want)
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
	}
	for _, c := range clean {
		if sigs := matchSignatures([]byte(c), true); len(sigs) != 0 {
			t.Errorf("%q matched %v", c, sigs)
		}
	}

	malicious := map[string]string{
		`<?php @eval(@base64_decode('ZWNobyAx'));`:      "eval_decoded_payload",
		`<?php PassThru($_REQUEST['x']);`:               "exec_request_input",
		`<?php assert($_COOKIE['a']);`:                  "eval_request_input",
		`<?php $_GET['f']($_GET['a']);`:                 "request_input_as_function",
		"<?php echo `$_POST[c]`;":                       "backtick_request_input",
		`<?php preg_replace('/.*/e', $_POST['x'], '');`: "preg_replace_eval",
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
	out, err := (Collector{}).Collect(ctx, collector.Source{FS: compromisedShop()})
	if err != nil {
		t.Fatal(err)
	}
	res := out.(Result)
	if len(res.Apps) != 0 || !slices.ContainsFunc(res.Issues, func(s string) bool { return strings.Contains(s, "not scanned") }) {
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
	out, err := Collector{}.Collect(context.Background(), collector.NewSource(dir))
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

	out, err := Collector{}.Collect(context.Background(), collector.NewSource(dir))
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
	out, err := Collector{}.Collect(context.Background(), collector.NewSource(tr.root))
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

// An upload directory that is a symlink to a shared directory is scanned through the link.
func TestSymlinkedUploadDirectoryIsScanned(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/releases/5/index.php", "<?php echo 1;")
	tr.file("var/www/shared/uploads/2026/shell.php", `<?php system($_GET['c']);`)
	tr.link("../../shared/uploads", "var/www/releases/5/uploads")
	tr.link("../uploads", "var/www/shared/uploads/2026/loop")

	got := findingsOf(tr.scan())
	if !slices.Contains(got, KindScriptInUploads+" /var/www/releases/5/uploads/2026/shell.php") {
		t.Errorf("findings = %v", got)
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
