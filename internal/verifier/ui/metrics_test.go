package ui

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// Metrics take a bearer token, as the API does, and count the servers, the alerts, the analysis
// queue and the database in Prometheus' text format.
func TestMetrics(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, id := range []string{"web-01", "db-01"} {
		if err := h.store.Enroll(ctx, id, make([]byte, 32), now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.store.Alive(ctx, "web-01", now); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Raise(ctx, store.Alert{HostID: "web-01", Fingerprint: "f", Severity: "high", Kind: "web", Title: "x"}, now); err != nil {
		t.Fatal(err)
	}
	csrf := h.login()
	if code, _ := h.api("GET", "/metrics", ""); code != http.StatusUnauthorized {
		t.Fatalf("metrics without a token: %d", code)
	}
	_, body := h.post("/settings/api", url.Values{"csrf": {csrf}, "name": {"prometheus"}, "days": {"30"}})
	token := regexp.MustCompile(`twk_[A-Za-z0-9_-]+`).FindString(body)
	code, body := h.api("GET", "/metrics", token)
	if code != http.StatusOK {
		t.Fatalf("metrics: %d", code)
	}
	for _, line := range []string{
		`tripwatch_hosts{state="reporting"} 1`,
		`tripwatch_hosts{state="silent"} 1`,
		`tripwatch_alerts{status="open",severity="high"} 1`,
		`tripwatch_alerts{status="acknowledged",severity="critical"} 0`,
		`tripwatch_analysis_pending 0`,
		`# TYPE tripwatch_database_bytes gauge`,
	} {
		if !strings.Contains(body, line+"\n") {
			t.Errorf("missing %q in:\n%s", line, body)
		}
	}
}
