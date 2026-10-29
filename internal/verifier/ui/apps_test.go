package ui

import (
	"testing"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// Applications with open alerts come first, the most severe on top; an alert counts for the
// deepest application holding its path, and a resolved one for none.
func TestHostApps(t *testing.T) {
	f := store.HostFacts{Apps: []store.AppFact{
		{Path: "/srv/static/a", Framework: "static", Sites: []string{"a.example"}},
		{Path: "/srv/html", Framework: "unknown", Sites: []string{"_"}},
		{Path: "/srv/shop", Framework: "laravel", Sites: []string{"shop.example", "www.shop.example"}},
		{Path: "/srv/shop/admin", Framework: "php", Sites: []string{"admin.example"}},
	}}
	alerts := []store.Alert{
		{Severity: "high", Status: store.StatusOpen, Detail: "/srv/shop/storage/x.log"},
		{Severity: "critical", Status: store.StatusOpen, Detail: "/srv/shop/admin/up/x.php"},
		{Severity: "critical", Status: store.StatusResolved, Detail: "/srv/static/a/x.php"},
	}
	got := hostApps(f, alerts)
	want := []struct {
		path, worst, site string
		open, others      int
	}{
		{"/srv/shop/admin", "critical", "admin.example", 1, 0},
		{"/srv/shop", "high", "shop.example", 1, 1},
		{"/srv/static/a", "", "a.example", 0, 0},
		{"/srv/html", "", "", 0, 0},
	}
	if len(got) != len(want) {
		t.Fatalf("%d apps", len(got))
	}
	for i, w := range want {
		g := got[i]
		if g.Path != w.path || g.Worst != w.worst || g.Site != w.site || g.Open != w.open || g.Others != w.others {
			t.Errorf("%d: got %s %q %q open %d others %d, want %+v", i, g.Path, g.Worst, g.Site, g.Open, g.Others, w)
		}
	}
	if got[1].Dir != "/srv/" || got[1].Base != "shop" {
		t.Errorf("split %q %q", got[1].Dir, got[1].Base)
	}
}
