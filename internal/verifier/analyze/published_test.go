package analyze

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/collector/web"
	"github.com/cpibia/tripwatch/internal/discovery"
	"github.com/cpibia/tripwatch/internal/protocol"
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
	// The directory's change is named in the more severe alert of one of its files.
	if _, ok := got["web-change:code:"+root+":new"]; ok || len(got) != 2 || !strings.Contains(got["web-change:release-differs:"+root+"/shop.php:aaaa"].Detail, "Its directory's code changed: "+root) {
		t.Errorf("the directory with a file off its release is not folded: %v", got)
	}
	// The verifier remembers the last version of each package whatever snapshot named it: a
	// downgrade is raised even when the snapshot before named the package with no change.
	known := map[string]store.HostRelease{root: {Root: root, Ecosystem: web.EcosystemWordPressPlugin, Slug: "shop", Version: "2.0.0"}}
	down := Evaluate(prev, State{Web: app("1.0.0", "new", update...), Published: matched, KnownReleases: known})
	if len(down) != 1 || down[0].Severity != "medium" || down[0].Title != "Plugin downgraded: shop" {
		t.Errorf("downgrade: %+v", down)
	}
	// A plugin the host never had is raised as installed even when it matches its release; on a
	// host with nothing remembered yet, the first snapshot only records.
	other := map[string]store.HostRelease{"/var/www/blog": {Root: "/var/www/blog", Ecosystem: web.EcosystemWordPressCore, Slug: "en_US", Version: "6.6.2"}}
	added := []web.FileChange{{Path: root + "/shop.php", Change: web.ChangeAdded, SHA256: "aaaa"}}
	addedMatch := map[string]Published{root + "/shop.php": {Release: "shop 1.2.3", Matches: true, Listed: true}}
	got2 := Evaluate(prev, State{Web: app("1.2.3", "new", added...), Published: addedMatch, KnownReleases: other})
	if len(got2) != 1 || got2[0].Severity != "medium" || got2[0].Title != "Plugin installed: shop" {
		t.Errorf("installed: %+v", got2)
	}
	if got := Evaluate(prev, State{Web: app("1.2.3", "new", added...), Published: addedMatch, KnownReleases: map[string]store.HostRelease{}}); len(got) != 0 {
		t.Errorf("first snapshot: %+v", got)
	}
	if lowerVersion("1.10", "1.9") || !lowerVersion("1.9", "1.10") || lowerVersion("2.0", "2.0") || !lowerVersion("2.0", "2.0.1") {
		t.Error("lowerVersion compares wrongly")
	}
}

// The core's release judges the files outside wp-content, which plugins' releases judge.
func TestPublishedCore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer srv.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Now()
	if err := st.PutContentRef(context.Background(), store.ContentRef{Ecosystem: refs.WordPressCore, Slug: "it_IT", Version: "6.6.2",
		Files: map[string][]string{"wp-includes/load.php": {"aaaa"}, "wp-content/index.php": {"bbbb"}}}, now); err != nil {
		t.Fatal(err)
	}
	a := &Analyzer{Refs: &refs.Resolver{Store: st, Fetcher: &refs.Fetcher{Sources: map[string]string{}}, Enabled: true, PerRound: 5, PerHostDay: 20}}
	state := State{Web: &web.Result{Apps: []web.AppReport{{
		Application: discovery.Application{Path: "/var/www/blog"},
		Releases:    []web.PackageRelease{{Root: "/var/www/blog", Ecosystem: web.EcosystemWordPressCore, Slug: "it_IT", Version: "6.6.2"}},
		Changes: []web.FileChange{
			{Path: "/var/www/blog/wp-includes/load.php", Change: web.ChangeModified, SHA256: "aaaa"},
			{Path: "/var/www/blog/wp-content/index.php", Change: web.ChangeModified, SHA256: "bbbb"},
		},
	}}}}
	got := a.published(context.Background(), "web-01", state)
	if len(got) != 1 || got["/var/www/blog/wp-includes/load.php"] != (Published{Release: "WordPress 6.6.2 (it_IT)", Matches: true, Listed: true}) {
		t.Errorf("published = %+v", got)
	}
}

// End to end, with snapshots as the sensor sends them (every package's release, changed or not):
// the verifier remembers each package's version across snapshots, so a downgrade is raised when
// the snapshot before named the plugin with nothing changed, and a plugin the host never had is
// raised as installed although it matches its release.
func TestReleasesRemembered(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	shop := "/var/www/blog/wp-content/plugins/shop"
	files := "/var/www/blog/wp-content/plugins/filemgr"
	if err := h.store.PutContentRef(ctx, store.ContentRef{Ecosystem: refs.WordPressPlugin, Slug: "filemgr", Version: "6.0",
		Files: map[string][]string{"filemgr.php": {"c1"}}}, h.clock); err != nil {
		t.Fatal(err)
	}
	if err := h.store.PutContentRef(ctx, store.ContentRef{Ecosystem: refs.WordPressPlugin, Slug: "shop", Version: "1.0",
		Files: map[string][]string{"shop.php": {"a1"}}}, h.clock); err != nil {
		t.Fatal(err)
	}
	h.an.Refs = &refs.Resolver{Store: h.store, Fetcher: &refs.Fetcher{Sources: map[string]string{}}, Enabled: true, PerRound: 5, PerHostDay: 20, Now: func() time.Time { return h.clock }}
	snap := func(hash, releases, changes string) string {
		return `{"snapshot":{"results":{"web":{"apps":[{"path":"/var/www/blog","framework":"wordpress","dir_hashes":{"/var/www/blog/wp-content/plugins":"` + hash +
			`"},"releases":[` + releases + `],"changes":[` + changes + `],"change_count":` + strconv.Itoa(strings.Count(changes, `"path"`)) + `}]}}}}`
	}
	rel := func(root, slug, version string) string {
		return `{"root":"` + root + `","ecosystem":"wordpress-plugin","slug":"` + slug + `","version":"` + version + `"}`
	}
	h.deliver(protocol.KindSnapshot, gz(t, snap("a", rel(shop, "shop", "2.0"), "")))
	h.analyse()
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, snap("a", rel(shop, "shop", "2.0"), "")))
	h.analyse()
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, snap("b", rel(shop, "shop", "1.0"), `{"path":"`+shop+`/shop.php","change":"modified","sha256":"a1"}`)))
	h.analyse()
	if _, ok := h.open()["web-change:release-downgrade:"+shop+":1.0"]; !ok {
		t.Errorf("the downgrade is not raised: %v", h.open())
	}
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, snap("c", rel(shop, "shop", "1.0")+","+rel(files, "filemgr", "6.0"), `{"path":"`+files+`/filemgr.php","change":"added","sha256":"c1"}`)))
	h.analyse()
	if a, ok := h.open()["web-change:release-installed:"+files+":6.0"]; !ok || a.Severity != "medium" {
		t.Errorf("the installed plugin is not raised: %v", h.open())
	}
}
