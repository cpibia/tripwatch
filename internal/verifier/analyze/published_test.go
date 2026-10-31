package analyze

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cpibia/tripwatch/internal/collector/web"
	"github.com/cpibia/tripwatch/internal/discovery"
	"github.com/cpibia/tripwatch/internal/verifier/refs"
	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// The changed files of a plugin are compared with its release as published: same SHA-256 at the
// same path matches; another content, or a file the release does not have, does not.
func TestPublishedComparison(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/plugin-checksums/shop/1.2.3.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"files":{"shop.php":{"sha256":"aaaa"},"assets/app.js":{"sha256":["bbbb","cccc"]}}}`))
	}))
	defer srv.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	a := &Analyzer{Refs: &refs.Resolver{Store: st, Fetcher: &refs.Fetcher{Sources: map[string]string{refs.WordPressPlugin: srv.URL}}, Enabled: true, PerRound: 5, PerHostDay: 20}}
	root := "/var/www/blog/wp-content/plugins/shop"
	state := State{Web: &web.Result{Apps: []web.AppReport{{
		Application: discovery.Application{Path: "/var/www/blog"},
		Releases:    []web.PackageRelease{{Root: root, Ecosystem: web.EcosystemWordPressPlugin, Slug: "shop", Version: "1.2.3"}},
		Changes: []web.FileChange{
			{Path: root + "/shop.php", Change: web.ChangeModified, SHA256: "aaaa"},
			{Path: root + "/assets/app.js", Change: web.ChangeModified, SHA256: "cccc"},
			{Path: root + "/assets/skim.js", Change: web.ChangeAdded, SHA256: "dddd"},
			{Path: root + "/shop2.php", Change: web.ChangeModified, SHA256: "aaaa"},
			{Path: root + "/gone.php", Change: web.ChangeRemoved},
			{Path: "/var/www/blog/wp-includes/load.php", Change: web.ChangeModified, SHA256: "aaaa"},
		},
	}}}}
	got := a.published(context.Background(), "web-01", state)
	want := map[string]Published{
		root + "/shop.php":       {Release: "shop 1.2.3", Matches: true, Listed: true},
		root + "/assets/app.js":  {Release: "shop 1.2.3", Matches: true, Listed: true},
		root + "/assets/skim.js": {Release: "shop 1.2.3"},
		root + "/shop2.php":      {Release: "shop 1.2.3"},
	}
	if len(got) != len(want) {
		t.Errorf("published = %+v", got)
	}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%s: %+v, want %+v", p, got[p], w)
		}
	}
	if (&Analyzer{}).published(context.Background(), "web-01", state) != nil {
		t.Error("judged without references")
	}
}

// A plugin updated to its release as published raises nothing; a file that differs from it, or
// that it does not have, is a high alert naming the release; a downgrade is a medium one.
func TestReleaseRules(t *testing.T) {
	root := "/var/www/blog/wp-content/plugins/shop"
	app := func(version string, hash string, changes ...web.FileChange) *web.Result {
		return &web.Result{Apps: []web.AppReport{{
			Application: discovery.Application{Path: "/var/www/blog"},
			DirHashes:   map[string]string{root: hash},
			Releases:    []web.PackageRelease{{Root: root, Ecosystem: web.EcosystemWordPressPlugin, Slug: "shop", Version: version}},
			Changes:     changes, ChangeCount: len(changes),
		}}}
	}
	prev := &State{Web: app("1.2.2", "old")}
	update := []web.FileChange{{Path: root + "/shop.php", Change: web.ChangeModified, SHA256: "aaaa"}, {Path: root + "/assets/app.js", Change: web.ChangeModified, SHA256: "cccc"}}
	matched := map[string]Published{root + "/shop.php": {Release: "shop 1.2.3", Matches: true, Listed: true}, root + "/assets/app.js": {Release: "shop 1.2.3", Matches: true, Listed: true}}
	if got := Evaluate(prev, State{Web: app("1.2.3", "new", update...), Published: matched}); len(got) != 0 {
		t.Errorf("an update as published raised %+v", got)
	}
	// Without references the same update raises what it did before.
	if got := Evaluate(prev, State{Web: app("1.2.3", "new", update...)}); len(got) == 0 {
		t.Error("an update without references raised nothing")
	}
	skim := append(update, web.FileChange{Path: root + "/assets/skim.js", Change: web.ChangeAdded, SHA256: "dddd"})
	tampered := map[string]Published{root + "/shop.php": {Release: "shop 1.2.3", Listed: true}, root + "/assets/app.js": matched[root+"/assets/app.js"], root + "/assets/skim.js": {Release: "shop 1.2.3"}}
	got := map[string]Finding{}
	for _, f := range Evaluate(prev, State{Web: app("1.2.3", "new", skim...), Published: tampered}) {
		got[f.Fingerprint] = f
	}
	if f := got["web-change:release-differs:"+root+"/shop.php:aaaa"]; f.Severity != "high" || !strings.Contains(f.Detail, "shop 1.2.3") || !strings.Contains(f.Detail, "other content") {
		t.Errorf("changed file: %+v", f)
	}
	if f := got["web-change:release-differs:"+root+"/assets/skim.js:dddd"]; f.Severity != "high" || !strings.Contains(f.Detail, "no file at this path") {
		t.Errorf("added file: %+v", f)
	}
	if _, ok := got["web-change:code:"+root+":new"]; !ok {
		t.Errorf("the directory with a file off its release is not raised: %v", got)
	}
	down := Evaluate(&State{Web: app("1.10.0", "old")}, State{Web: app("1.9.5", "new", update...), Published: matched})
	if len(down) != 1 || down[0].Severity != "medium" || !strings.Contains(down[0].Title, "downgraded") {
		t.Errorf("downgrade: %+v", down)
	}
	if lowerVersion("1.10", "1.9") || !lowerVersion("1.9", "1.10") || lowerVersion("2.0", "2.0") || !lowerVersion("2.0", "2.0.1") {
		t.Error("lowerVersion compares wrongly")
	}
}
