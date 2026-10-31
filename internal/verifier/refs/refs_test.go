package refs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

const shopFixture = `{"plugin":{"slug":"shop","version":"1.2.3"},"files":{
	"shop.php":{"md5":"x","sha256":"aaaa"},
	"assets/app.js":{"md5":"y","sha256":["bbbb","cccc"]}}}`

// source serves fixture checksum lists and counts what it is asked for.
func source(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var asked atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		switch r.URL.Path {
		case "/plugin-checksums/shop/1.2.3.json":
			_, _ = w.Write([]byte(shopFixture))
		case "/plugin-checksums/huge/1.0.json":
			_, _ = w.Write([]byte(`{"files":{"a":{"sha256":"` + strings.Repeat("a", maxReferenceBytes) + `"}}}`))
		case "/plugin-checksums/moved/1.0.json":
			http.Redirect(w, r, "http://elsewhere.example/x.json", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &asked
}

func resolver(t *testing.T, base string) *Resolver {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &Resolver{Store: st, Fetcher: &Fetcher{Sources: map[string]string{WordPressPlugin: base}}, Enabled: true, PerRound: 5, PerHostDay: 20}
}

// A release is fetched once and kept; its files carry every SHA-256 the source lists.
func TestLookupFetchesAndKeeps(t *testing.T) {
	srv, asked := source(t)
	r := resolver(t, srv.URL)
	for range 3 {
		ref, ok := r.Lookup(context.Background(), "web-01", Key{WordPressPlugin, "shop", "1.2.3"})
		if !ok || len(ref.Files) != 2 || ref.Files["shop.php"][0] != "aaaa" || len(ref.Files["assets/app.js"]) != 2 {
			t.Fatalf("reference = %+v, %v", ref, ok)
		}
	}
	if asked.Load() != 1 {
		t.Errorf("asked %d times", asked.Load())
	}
}

// A release the source does not have is remembered for a day; one too large, behind a redirect
// to another host, or named by a key of another shape gives no reference.
func TestLookupRefusals(t *testing.T) {
	srv, asked := source(t)
	r := resolver(t, srv.URL)
	now := time.Now()
	r.Now = func() time.Time { return now }
	for range 2 {
		if _, ok := r.Lookup(context.Background(), "web-01", Key{WordPressPlugin, "gone", "1.0"}); ok {
			t.Error("a missing release gave a reference")
		}
	}
	if asked.Load() != 1 {
		t.Errorf("a missing release asked %d times in a day", asked.Load())
	}
	now = now.Add(25 * time.Hour)
	r.NewRound()
	r.Lookup(context.Background(), "web-01", Key{WordPressPlugin, "gone", "1.0"})
	if asked.Load() != 2 {
		t.Errorf("a missing release not asked again after a day: %d", asked.Load())
	}
	for _, k := range []Key{
		{WordPressPlugin, "huge", "1.0"},
		{WordPressPlugin, "moved", "1.0"},
		{WordPressPlugin, "../../etc", "1.0"},
		{WordPressPlugin, "shop", "1.0/../../x?y="},
		{WordPressPlugin, "Shop", "1.2.3"},
		{"wordpress-theme", "shop", "1.2.3"},
	} {
		if _, ok := r.Lookup(context.Background(), "web-01", k); ok {
			t.Errorf("%+v gave a reference", k)
		}
	}
}

// Fetches are bounded per round and per host and day; off, nothing is fetched.
func TestLookupBounds(t *testing.T) {
	srv, asked := source(t)
	r := resolver(t, srv.URL)
	r.PerRound, r.PerHostDay = 2, 3
	for i := range 5 {
		r.Lookup(context.Background(), "web-01", Key{WordPressPlugin, "p" + string(rune('a'+i)), "1.0"})
	}
	if asked.Load() != 2 {
		t.Errorf("one round fetched %d", asked.Load())
	}
	r.NewRound()
	for i := range 5 {
		r.Lookup(context.Background(), "web-01", Key{WordPressPlugin, "q" + string(rune('a'+i)), "1.0"})
	}
	if asked.Load() != 3 {
		t.Errorf("one host fetched %d in a day", asked.Load())
	}
	r.NewRound()
	r.Lookup(context.Background(), "web-02", Key{WordPressPlugin, "shop", "1.2.3"})
	if asked.Load() != 4 {
		t.Errorf("another host was held by the first one's bound: %d", asked.Load())
	}
	off := resolver(t, srv.URL)
	off.Enabled = false
	if _, ok := off.Lookup(context.Background(), "web-01", Key{WordPressPlugin, "shop", "1.2.3"}); ok || asked.Load() != 4 {
		t.Error("references off still fetched")
	}
}

// Past their bound the references used least recently go first.
func TestContentRefsBound(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	saved := store.MaxContentRefBytes
	store.MaxContentRefBytes = 2 * 300
	t.Cleanup(func() { store.MaxContentRefBytes = saved })
	ctx, now := context.Background(), time.Now()
	for i, slug := range []string{"a", "b", "c"} {
		// Hashes that do not compress, about 300 bytes a release: two fit, three do not.
		files := map[string][]string{}
		for j := range 4 {
			sum := sha256.Sum256([]byte(slug + string(rune('0'+j))))
			files[slug+string(rune('0'+j))+".php"] = []string{hex.EncodeToString(sum[:])}
		}
		ref := store.ContentRef{Ecosystem: WordPressPlugin, Slug: slug, Version: "1.0", Files: files}
		if err := st.PutContentRef(ctx, ref, now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			// a is used again, so b is the least recently used when c comes.
			if _, ok, err := st.ContentRef(ctx, WordPressPlugin, "a", "1.0", now.Add(90*time.Second)); err != nil || !ok {
				t.Fatal(ok, err)
			}
		}
	}
	kept := map[string]bool{}
	for _, slug := range []string{"a", "b", "c"} {
		_, ok, err := st.ContentRef(ctx, WordPressPlugin, slug, "1.0", now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		kept[slug] = ok
	}
	if kept["b"] || !kept["c"] {
		t.Errorf("kept %v", kept)
	}
}
