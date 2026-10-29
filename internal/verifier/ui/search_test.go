package ui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// One search finds a text among servers, alerts and real-time events at once, and shows what the
// servers sent as text.
func TestSearchAcrossTheFleet(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, id := range []string{"web-01", "web-02"} {
		if err := h.store.Enroll(ctx, id, make([]byte, 32), now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.store.SetFacts(ctx, "web-02", store.HostFacts{Apps: []store.AppFact{{Path: "/srv/shop", Framework: "laravel", Sites: []string{"shop.example.com"}}}, SeenAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Raise(ctx, store.Alert{HostID: "web-01", Fingerprint: "web:x", Severity: "critical", Kind: "web", Title: "Code inside a data file", Detail: "/srv/shop/storage/<i>x</i>.log"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.AddEvents(ctx, []store.Event{{HostID: "web-01", Seq: 1, At: now, Class: "upload", Op: "create", Path: "/srv/shop/uploads/a.php",
		Data: []byte(`{"class":"upload","op":"create","path":"/srv/shop/uploads/a.php"}`)}}, now); err != nil {
		t.Fatal(err)
	}
	h.login()

	_, body := h.get("/search?q=%2Fsrv%2Fshop")
	for _, want := range []string{`href="/hosts/web-02"`, "Code inside a data file", "/srv/shop/uploads/a.php", "1 server", "1 alert", "1 real-time event"} {
		if !strings.Contains(body, want) {
			t.Errorf("search lacks %q", want)
		}
	}
	if strings.Contains(body, "<i>x</i>") {
		t.Error("text from a server rendered as markup")
	}
	if _, body := h.get("/search?q=nothing-matches-this"); !strings.Contains(body, "No server matches") || !strings.Contains(body, "No alert matches") {
		t.Error("empty results not said")
	}
	if _, body := h.get("/search"); !strings.Contains(body, "Type in the box above") {
		t.Error("empty search not explained")
	}
}
