package refs

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // the fixture's MD5 list, as WordPress publishes one
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func coreArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create("wordpress/" + name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func md5List(files map[string]string) []byte {
	sums := map[string]string{}
	for name, content := range files {
		s := md5.Sum([]byte(content)) //nolint:gosec // the fixture's MD5 list
		sums[name] = hex.EncodeToString(s[:])
	}
	b, _ := json.Marshal(map[string]any{"checksums": sums})
	return b
}

// coreSource serves an archive and an MD5 list for 6.6.2 in en_US and it_IT, the list for a
// version given apart from the archive's, and false for a version WordPress does not have.
func coreSource(t *testing.T, archive, list map[string]string) *Resolver {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/core/checksums/1.0/" && r.URL.Query().Get("version") == "6.6.2":
			_, _ = w.Write(md5List(list))
		case r.URL.Path == "/core/checksums/1.0/":
			_, _ = w.Write([]byte(`{"checksums":false}`))
		case r.URL.Path == "/release/wordpress-6.6.2.zip" || r.URL.Path == "/release/it_IT/wordpress-6.6.2.zip":
			_, _ = w.Write(coreArchive(t, archive))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	r := resolver(t, srv.URL)
	r.Fetcher.Sources = map[string]string{WordPressCore: srv.URL, wordPressAPI: srv.URL}
	return r
}

// A core release is hashed from its archive and kept when every file of WordPress's MD5 list
// matches; one that does not, an archive past its bounds, or a version WordPress lacks gives none.
func TestCoreReference(t *testing.T) {
	files := map[string]string{"index.php": "<?php // index", "wp-includes/load.php": "<?php // load"}
	r := coreSource(t, files, files)
	for _, locale := range []string{"en_US", "it_IT"} {
		ref, ok := r.Lookup(context.Background(), "web-01", Key{WordPressCore, locale, "6.6.2"})
		want := sha256.Sum256([]byte("<?php // load"))
		if !ok || len(ref.Files) != 2 || ref.Files["wp-includes/load.php"][0] != hex.EncodeToString(want[:]) {
			t.Errorf("%s: %+v, %v", locale, ref, ok)
		}
	}
	if _, ok := r.Lookup(context.Background(), "web-01", Key{WordPressCore, "en_US", "0.0.1"}); ok {
		t.Error("a version WordPress lacks gave a reference")
	}
	for _, k := range []Key{{WordPressCore, "../x", "6.6.2"}, {WordPressCore, "en_US&x=1", "6.6.2"}, {WordPressCore, "EN", "6.6.2"}} {
		if _, ok := r.Lookup(context.Background(), "web-01", k); ok {
			t.Errorf("%+v gave a reference", k)
		}
	}

	tampered := map[string]string{"index.php": "<?php // index", "wp-includes/load.php": "<?php eval($_POST[1]);"}
	r = coreSource(t, tampered, files)
	if _, ok := r.Lookup(context.Background(), "web-01", Key{WordPressCore, "en_US", "6.6.2"}); ok {
		t.Error("an archive that differs from the MD5 list gave a reference")
	}

	saved := maxExpandedBytes
	maxExpandedBytes = 64
	t.Cleanup(func() { maxExpandedBytes = saved })
	big := map[string]string{"index.php": strings.Repeat("a", 100)}
	r = coreSource(t, big, big)
	if _, ok := r.Lookup(context.Background(), "web-01", Key{WordPressCore, "en_US", "6.6.2"}); ok {
		t.Error("an archive past its expanded bound gave a reference")
	}
}

// A theme's release is hashed from its archive in WordPress's directory.
func TestThemeReference(t *testing.T) {
	files := map[string]string{"style.css": "/* Theme Name: Calm */", "functions.php": "<?php // calm"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/theme/calm.1.4.zip" {
			http.NotFound(w, r)
			return
		}
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for name, content := range files {
			fw, _ := zw.Create("calm/" + name)
			_, _ = fw.Write([]byte(content))
		}
		_ = zw.Close()
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()
	r := resolver(t, srv.URL)
	r.Fetcher.Sources = map[string]string{WordPressTheme: srv.URL}
	ref, ok := r.Lookup(context.Background(), "web-01", Key{WordPressTheme, "calm", "1.4"})
	want := sha256.Sum256([]byte("<?php // calm"))
	if !ok || ref.Files["functions.php"][0] != hex.EncodeToString(want[:]) {
		t.Errorf("theme reference = %+v, %v", ref, ok)
	}
	if _, ok := r.Lookup(context.Background(), "web-01", Key{WordPressTheme, "calm", "9.9"}); ok {
		t.Error("a release the directory lacks gave a reference")
	}
}
