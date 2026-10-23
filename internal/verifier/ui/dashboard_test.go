package ui

import (
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// The overview's figures come from the alerts as raised: columns stack them by severity in the
// hour or day they arrived, rules rank by alerts, web attacks by requests from each source.
func TestDashboardFigures(t *testing.T) {
	at := time.Date(2026, 10, 23, 12, 30, 0, 0, time.Local)
	raised := []store.Raised{
		{Fingerprint: "web:script_in_uploads:/srv/up/a.php", Severity: "critical", Kind: "web", Title: "Script in upload directories", CreatedAt: at.Add(-10 * time.Minute)},
		{Fingerprint: "web:script_in_uploads:/srv/up/b.php", Severity: "critical", Kind: "web", Title: "Script in upload directories", CreatedAt: at.Add(-70 * time.Minute)},
		{Fingerprint: "ssh-change:key:root|x", Severity: "high", Kind: "ssh-change", Title: "New SSH key for root", CreatedAt: at.Add(-3 * 24 * time.Hour)},
		{ID: 7, Fingerprint: "weblog:upload_script:/up/x.php|GET /up/x.php", Severity: "high", Kind: "weblog", Title: "Log: upload script", Occurrences: 1,
			Detail: "GET /up/x.php, status 200, 5 requests from 2 addresses (first 203.0.113.7), log /var/log/nginx/access.log.", CreatedAt: at.Add(-2 * time.Hour)},
		{ID: 9, Fingerprint: "weblog:upload_script:/up/y.php|GET /up/y.php", Severity: "high", Kind: "weblog", Title: "Log: upload script", Occurrences: 1,
			Detail: "GET /up/y.php, status 301, 4 richieste da 2 indirizzi (primo 198.51.100.4), log /var/log/nginx/access.log.", CreatedAt: at.Add(-3 * time.Hour)},
		{Fingerprint: "verifier:quota", Severity: "high", Kind: "verifier", Title: "Quota", CreatedAt: at.Add(-time.Minute)},
	}

	day := buildTimeline(raised, "24h", at)
	if len(day.Columns) != 24 || day.Total != 5 || day.Max != 2 {
		t.Fatalf("24 h: %d columns, total %d, max %d", len(day.Columns), day.Total, day.Max)
	}
	if last := day.Columns[23]; len(last.Segments) != 2 || last.Segments[0].Severity != "critical" || last.Title != "12:00: 1 critical, 1 high" {
		t.Errorf("current hour = %+v", last)
	}
	week := buildTimeline(raised, "7d", at)
	if len(week.Columns) != 7 || week.Total != 6 {
		t.Errorf("7 days: %d columns, total %d", len(week.Columns), week.Total)
	}
	if c := week.Columns[6]; len(c.Segments) != 2 || c.Segments[0].Severity != "critical" || c.Segments[0].Y < c.Segments[1].Y {
		t.Errorf("today's column does not stack critical at the base: %+v", c.Segments)
	}

	rules := buildRules(raised, 8)
	if len(rules) != 3 || rules[0].Label != "Script in upload directories" || rules[0].N != 2 || rules[0].Severity != "critical" || rules[1].Href != "/alerts/7" {
		t.Fatalf("rules = %+v", rules)
	}
	if rules[0].Segments[0].W != 100 || rules[1].Segments[0].W != 100 || rules[2].Segments[0].W != 50 {
		t.Errorf("bars are not relative to the longest: %+v", rules)
	}

	web := buildWeb(raised, 6)
	// Requests come from the detail, not from how often the alert was seen; older alerts say it
	// in Italian.
	if web.Total != 9 || len(web.Sources) != 2 || web.Sources[0].Label != "203.0.113.7" || web.Sources[0].N != 5 ||
		web.Sources[1].Label != "198.51.100.4" || web.Sources[1].Href != "/alerts/9" || web.Targets[0].Label != "/up/x.php" || web.Targets[0].Href != "/alerts/7" {
		t.Errorf("web = %+v", web)
	}

	hosts := buildHosts(map[string]map[string]int{"web-01": {"critical": 2, "low": 1}, "db-01": {"high": 1}}, 8)
	if hosts[0].Label != "web-01" || len(hosts[0].Segments) != 2 || hosts[0].Segments[0].Severity != "critical" || hosts[1].Segments[0].W != 100.0/3 {
		t.Errorf("hosts = %+v", hosts)
	}
}
