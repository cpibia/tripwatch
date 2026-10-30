package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/discovery"
)

// The second run names the code files that changed since the first one was delivered; data
// directories stay out, and a run whose snapshot was not delivered is compared again.
func TestManifestNamesChangedFiles(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/shop/bin/magento", "#!/usr/bin/env php")
	tr.file("var/www/shop/app/etc/di.xml", "<config/>")
	tr.file("var/www/shop/pub/index.php", "<?php require 'app/bootstrap.php';")
	tr.file("var/www/shop/vendor/acme/framework/App/View.php", "<?php class View {}")
	tr.file("var/www/shop/vendor/acme/framework/App/Old.php", "<?php class Old {}")
	tr.file("var/www/shop/var/log/system.log", "one")
	c := &Collector{StateDir: t.TempDir()}
	collect := func() AppReport {
		t.Helper()
		out, err := c.Collect(context.Background(), collector.NewSource(tr.root))
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range out.(Result).Apps {
			if a.Path == "/var/www/shop" {
				return a
			}
		}
		t.Fatal("application not found")
		return AppReport{}
	}
	if first := collect(); first.ChangeCount != 0 || first.Changes != nil {
		t.Fatalf("a first run names changes: %+v", first.Changes)
	}
	if err := c.Commit(); err != nil {
		t.Fatal(err)
	}

	tr.file("var/www/shop/vendor/acme/framework/App/View.php", "<?php class View { function render() { include($_COOKIE['t']); } }")
	tr.file("var/www/shop/pub/sysapi.php", `<?php $f = "sy"."stem"; $f($_GET["c"]);`)
	tr.file("var/www/shop/pub/odd\nname.php", "<?php")
	tr.file("var/www/shop/var/log/system.log", "two")
	if err := os.Remove(filepath.Join(tr.root, "var/www/shop/vendor/acme/framework/App/Old.php")); err != nil {
		t.Fatal(err)
	}
	want := "[{/var/www/shop/pub/odd\nname.php added} {/var/www/shop/pub/sysapi.php added} " +
		"{/var/www/shop/vendor/acme/framework/App/Old.php removed} {/var/www/shop/vendor/acme/framework/App/View.php modified}]"
	got := func(r AppReport) string {
		var out []string
		for _, ch := range r.Changes {
			out = append(out, fmt.Sprintf("{%s %s}", ch.Path, ch.Change))
		}
		return fmt.Sprint(out)
	}
	second := collect()
	if got(second) != want || second.ChangeCount != 4 {
		t.Fatalf("changes %s (%d), want %s", got(second), second.ChangeCount, want)
	}
	if second.Changes[1].SHA256 == "" || second.Changes[2].SHA256 != "" {
		t.Errorf("hashes: %+v", second.Changes)
	}
	// Not committed: the next run still compares with the first.
	if third := collect(); got(third) != want {
		t.Fatalf("after an undelivered run: %s", got(third))
	}
	if err := c.Commit(); err != nil {
		t.Fatal(err)
	}
	if fourth := collect(); fourth.ChangeCount != 0 {
		t.Fatalf("after commit: %s", got(fourth))
	}
}

func TestComparePaths(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"a/b", "a/b", 0},
		{"a/b", "a/c", -1},
		{"a/b/z", "a/c", -1},
		// Directory a is listed before the file a-b, so its content comes first too.
		{"a-b", "a/b", 1},
		{"a/b", "a-b", -1},
		{"a", "a/b", -1},
	} {
		if got := comparePaths(c.a, c.b); got != c.want {
			t.Errorf("comparePaths(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// Two fingerprints of a file too large to hash are compared; a fingerprint against a hash is
// not, since that only says the budget ran out in one of the runs.
func TestDiffComparesUnhashedFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, lines ...string) string {
		p := filepath.Join(dir, name)
		var b strings.Builder
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
		if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sum := strings.Repeat("a", 64)
	prev := write("prev", `"a/big.php" unhashed:size:9:ctime:1:id:1`, `"a/mixed.php" `+sum, `"a/same.php" unhashed:size:9:ctime:1:id:2`)
	cur := write("cur", `"a/big.php" unhashed:size:9:ctime:2:id:1`, `"a/mixed.php" unhashed:size:9:ctime:1:id:3`, `"a/same.php" unhashed:size:9:ctime:1:id:2`)
	changes, n, _, err := diffManifests(prev, cur)
	if err != nil || n != 1 || changes[0].Path != "/a/big.php" || changes[0].Change != ChangeModified || changes[0].SHA256 != "" {
		t.Errorf("changes %+v (%d), err %v", changes, n, err)
	}
}

// A manifest that cannot be written says so instead of switching the naming of changes off, and
// manifests no run has rewritten for a week are removed.
func TestManifestFailuresAndStaleManifests(t *testing.T) {
	state := t.TempDir()
	m, err := newManifestWriter(state, "/var/www/shop")
	if err != nil {
		t.Fatal(err)
	}
	m.add("var/www/shop/b.php", "x")
	m.add("var/www/shop/a.php", "x")
	s := &scanner{manifest: m, report: AppReport{Application: discovery.Application{Path: "/var/www/shop"}}}
	if next := s.finishManifest(context.Background(), state); next != "" || len(s.issues) != 1 || !strings.Contains(s.issues[0], "manifest not written, changed files not named: files listed out of order") {
		t.Errorf("next %q, issues %v", next, s.issues)
	}

	dir := filepath.Join(state, manifestDir)
	old, fresh := filepath.Join(dir, "gone"), filepath.Join(dir, "live")
	for _, p := range []string{old, fresh} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	if err := os.Chtimes(old, now.Add(-8*24*time.Hour), now.Add(-8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleManifests(state, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("a stale manifest is kept")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("a manifest in use was removed")
	}
	if err := removeStaleManifests(t.TempDir(), now); err != nil {
		t.Errorf("no manifest directory: %v", err)
	}
	// An application found in this run keeps its manifest however old: commits stop while the
	// verifier is out of reach.
	kept := manifestPath(state, "/var/www/shop")
	if err := os.WriteFile(kept, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(kept, now.Add(-30*24*time.Hour), now.Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleManifests(state, now, "/var/www/shop"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Error("the manifest of an application found in this run was removed")
	}
}

// A release's link to its shared wp-config.php is code included on every request: a line
// appended to the shared file is a change named under the link.
func TestManifestNamesAChangedSharedFile(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/deploy/releases/5/wp-includes/version.php", "<?php $wp_version = '6.6.2';")
	tr.file("var/www/deploy/releases/5/index.php", "<?php")
	tr.file("var/www/deploy/shared/wp-config.php", "<?php define('DB_NAME', 'site');")
	tr.link("../../shared/wp-config.php", "var/www/deploy/releases/5/wp-config.php")
	c := &Collector{StateDir: t.TempDir()}
	collect := func() AppReport {
		t.Helper()
		out, err := c.Collect(context.Background(), collector.NewSource(tr.root))
		if err != nil {
			t.Fatal(err)
		}
		return out.(Result).Apps[0]
	}
	collect()
	if err := c.Commit(); err != nil {
		t.Fatal(err)
	}
	tr.file("var/www/deploy/shared/wp-config.php", "<?php define('DB_NAME', 'site'); @include '/tmp/.sess_x';")
	if r := collect(); r.ChangeCount != 1 || r.Changes[0].Path != "/var/www/deploy/releases/5/wp-config.php" || r.Changes[0].Change != "modified" {
		t.Fatalf("changes = %+v", r.Changes)
	}
}

// The run that first hashes the content behind a shared link is not a change of it; a later
// change of that content is.
func TestManifestFirstHashOfASharedLink(t *testing.T) {
	dir := t.TempDir()
	write := func(name, sum string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(strconv.Quote("var/www/site/wp-config.php")+" "+sum+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	before := write("before", "link:../../shared/wp-config.php")
	first := write("first", "link:../../shared/wp-config.php:"+strings.Repeat("a", 64))
	changed := write("changed", "link:../../shared/wp-config.php:"+strings.Repeat("b", 64))
	if _, n, _, err := diffManifests(before, first); err != nil || n != 0 {
		t.Errorf("first hash: %d changes, %v", n, err)
	}
	if _, n, _, err := diffManifests(first, changed); err != nil || n != 1 {
		t.Errorf("changed content: %d changes, %v", n, err)
	}
}

// Scripts a run cut short has not read for skimmers keep their old entry in the manifest it hands
// on, marked pending: the next run finds them changed again and reads them, instead of taking them
// for seen. After three runs in a row they are named in the result.
func TestUnreadScriptsStayPending(t *testing.T) {
	state := t.TempDir()
	prev := manifestPath(state, "/var/www/shop")
	if err := os.MkdirAll(filepath.Dir(prev), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(prev, []byte(`"var/www/shop/a.js" `+strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var s *scanner
	for run := 1; run <= 3; run++ {
		m, err := newManifestWriter(state, "/var/www/shop")
		if err != nil {
			t.Fatal(err)
		}
		m.add("var/www/shop/a.js", strings.Repeat("b", 64))
		m.add("var/www/shop/b.js", strings.Repeat("c", 64))
		s = &scanner{src: collector.NewSource(t.TempDir()), manifest: m, budget: newHashBudget(), findings: map[string]int{}, report: AppReport{Application: discovery.Application{Path: "/var/www/shop"}}}
		next := s.finishManifest(ctx, state)
		if next == "" {
			t.Fatalf("run %d: no manifest: %v", run, s.issues)
		}
		data, err := os.ReadFile(next) //nolint:gosec // the test's own state directory
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf(`"var/www/shop/a.js" pending:%d:`+strings.Repeat("a", 64), run)
		if !strings.Contains(string(data), want) || !strings.Contains(string(data), fmt.Sprintf(`"var/www/shop/b.js" pending:%d:new`, run)) {
			t.Fatalf("run %d: unread scripts handed on as seen:\n%s", run, data)
		}
		if err := os.Rename(next, prev); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(s.report.UnreadScripts, []UnreadScript{{"/var/www/shop/a.js", 3}, {"/var/www/shop/b.js", 3}}) {
		t.Errorf("unread scripts = %+v", s.report.UnreadScripts)
	}
	if !slices.ContainsFunc(s.issues, func(i string) bool { return strings.Contains(i, "kept pending for the next") }) {
		t.Errorf("issues %q", s.issues)
	}
}

// A scan cut short counts the runs in a row it was, and one run scanned whole starts over.
func TestTruncatedRunsCounted(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/shop/index.php", "<?php")
	tr.file("var/www/shop/wp-includes/version.php", "<?php $wp_version = '6.6';")
	c := &Collector{}
	cut, cancel := context.WithCancel(context.Background())
	cancel()
	runs := func(ctx context.Context) int {
		t.Helper()
		out, err := c.Collect(ctx, collector.NewSource(tr.root))
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range out.(Result).Apps {
			return a.TruncatedRuns
		}
		t.Fatal("no application")
		return 0
	}
	if r1, r2 := runs(cut), runs(cut); r1 != 1 || r2 != 2 {
		t.Errorf("runs cut: %d then %d", r1, r2)
	}
	if r := runs(context.Background()); r != 0 {
		t.Errorf("after a whole run: %d", r)
	}
}
