package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/discovery"
)

// A stale configuration file is explained with its times when the sensor sends them, and says
// when only the inode changed; an older sensor's alert names the file alone.
func TestStaleConfigDetail(t *testing.T) {
	loaded := time.Date(2026, 10, 29, 8, 0, 0, 0, time.UTC)
	inv := discovery.Inventory{
		StaleConfig: []string{"/etc/nginx/nginx.conf"},
		StaleTimes:  []discovery.StaleFile{{Path: "/etc/nginx/nginx.conf", Changed: loaded.Add(time.Hour), Loaded: loaded}},
		ConfigFiles: []collector.File{{Path: "/etc/nginx/nginx.conf", ModTime: loaded.AddDate(-2, 0, 0)}},
	}
	d := staleDetail(inv, "/etc/nginx/nginx.conf")
	for _, want := range []string{"Inode changed 2026-10-29T09:00:00Z", "read its configuration 2026-10-29T08:00:00Z", "Content last modified 2024-10-29", "only the owner, the mode or the links changed"} {
		if !strings.Contains(d, want) {
			t.Errorf("detail lacks %q: %s", want, d)
		}
	}
	inv.ConfigFiles[0].ModTime = loaded.Add(time.Hour)
	if d := staleDetail(inv, "/etc/nginx/nginx.conf"); strings.Contains(d, "only the owner") {
		t.Errorf("an edit taken for a change of owner: %s", d)
	}
	if d := staleDetail(discovery.Inventory{StaleConfig: []string{"/etc/a"}}, "/etc/a"); d != "/etc/a" {
		t.Errorf("without times: %q", d)
	}
}
