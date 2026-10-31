package analyze

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
