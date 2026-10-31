package refs

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // the fixture's MD5, as drupal.org publishes one
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// drupalSource serves a release history whose archive entry the test chooses, and the archive.
func drupalSource(t *testing.T, entry func(srv string, md5sum string, size int) string) *Resolver {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string]string{"token.module": "<?php // token", "token.info.yml": "name: Token\nversion: '8.x-1.18'\nproject: 'token'\n"} //nolint:gosec // a fixture, no credential
	for name, content := range files {
		fw, _ := zw.Create("token/" + name)
		_, _ = fw.Write([]byte(content))
	}
	_ = zw.Close()
	archive := buf.Bytes()
	sum := md5.Sum(archive) //nolint:gosec // the fixture's MD5
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/release-history/token/current":
			_, _ = fmt.Fprintf(w, `<?xml version="1.0"?><project><releases><release><version>8.x-1.18</version><files>%s</files></release></releases></project>`,
				entry(srv.URL, hex.EncodeToString(sum[:]), len(archive)))
		case "/files/projects/token-8.x-1.18.zip":
			_, _ = w.Write(archive)
		default:
			_, _ = w.Write([]byte(`<?xml version="1.0"?><error>No release history was found.</error>`))
		}
	}))
	t.Cleanup(srv.Close)
	r := resolver(t, srv.URL)
	r.Fetcher.Sources = map[string]string{DrupalProject: srv.URL, drupalFiles: srv.URL}
	return r
}

func zipEntry(url, md5sum string, size int) string {
	return fmt.Sprintf(`<file><url>%s</url><archive_type>tar.gz</archive_type><md5>x</md5><size>1</size></file><file><url>%s</url><archive_type>zip</archive_type><md5>%s</md5><size>%d</size></file>`,
		url, url, md5sum, size)
}

// A drupal.org release is hashed from the zip archive its history names, which must come from the
// file host with the size and MD5 the history gives.
func TestDrupalReference(t *testing.T) {
	r := drupalSource(t, func(srv, md5sum string, size int) string {
		return zipEntry(srv+"/files/projects/token-8.x-1.18.zip", md5sum, size)
	})
	ref, ok := r.Lookup(context.Background(), "web-01", Key{DrupalProject, "token", "8.x-1.18"})
	want := sha256.Sum256([]byte("<?php // token"))
	if !ok || ref.Files["token.module"][0] != hex.EncodeToString(want[:]) {
		t.Errorf("reference = %+v, %v", ref, ok)
	}
	for name, k := range map[string]Key{"other version": {DrupalProject, "token", "8.x-1.17"}, "unknown project": {DrupalProject, "nothing", "1.0"},
		"hostile name": {DrupalProject, "token/../x", "8.x-1.18"}} {
		if _, ok := r.Lookup(context.Background(), "web-01", k); ok {
			t.Errorf("%s gave a reference", name)
		}
	}
	for name, entry := range map[string]func(string, string, int) string{
		"archive elsewhere": func(_, md5sum string, size int) string {
			return zipEntry("https://elsewhere.example/files/projects/token-8.x-1.18.zip", md5sum, size)
		},
		"outside the projects": func(srv, md5sum string, size int) string { return zipEntry(srv+"/other/token.zip", md5sum, size) },
		"wrong MD5": func(srv, _ string, size int) string {
			return zipEntry(srv+"/files/projects/token-8.x-1.18.zip", "00", size)
		},
		"wrong size": func(srv, md5sum string, size int) string {
			return zipEntry(srv+"/files/projects/token-8.x-1.18.zip", md5sum, size+1)
		},
	} {
		r := drupalSource(t, entry)
		if _, ok := r.Lookup(context.Background(), "web-01", Key{DrupalProject, "token", "8.x-1.18"}); ok {
			t.Errorf("%s gave a reference", name)
		}
	}
}
