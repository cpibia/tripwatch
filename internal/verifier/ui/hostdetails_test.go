package ui

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// An administrator names a server, labels it and writes a note: the name shows wherever the
// server appears, the search finds the labels, and the identity stays the same.
func TestHostDetails(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.store.Enroll(ctx, "web-01", make([]byte, 32), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	csrf := h.login()
	if res, _ := h.post("/hosts/web-01/details", url.Values{"csrf": {csrf}, "name": {"Shop front"}, "labels": {"env=prod bad label"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad label: %d", res.StatusCode)
	}
	if res, _ := h.post("/hosts/web-01/details", url.Values{"csrf": {csrf}, "name": {"Shop front"}, "labels": {"env=prod, client=acme"}, "note": {"Behind the <b>CDN</b>."}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("save: %d", res.StatusCode)
	}
	host, _ := h.store.Host(ctx, "web-01")
	if host.Name != "Shop front" || strings.Join(host.Labels, " ") != "client=acme env=prod" {
		t.Fatalf("stored %+v", host)
	}
	_, body := h.get("/hosts/web-01")
	if !strings.Contains(body, "<h1>Shop front</h1>") || !strings.Contains(body, "Behind the &lt;b&gt;CDN&lt;/b&gt;.") {
		t.Error("host page lacks the name or the escaped note")
	}
	if _, body := h.get("/hosts?q=client%3Dacme"); !strings.Contains(body, `href="/hosts/web-01" title="web-01">Shop front</a>`) {
		t.Error("search by label or name in the list failed")
	}
}
