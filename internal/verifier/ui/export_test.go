package ui

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// The list exports as it is filtered, every page of it; text the host wrote cannot become a
// spreadsheet formula, and the export is in the audit log.
func TestExportAlerts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.store.Enroll(ctx, "web-01", make([]byte, 32), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, a := range []store.Alert{
		{HostID: "web-01", Fingerprint: "f", Severity: "high", Kind: "web", Title: `=HYPERLINK("http://x.example/","open")`, Detail: "-2+3"},
		{HostID: "web-01", Fingerprint: "g", Severity: "low", Kind: "web", Title: "low note"},
	} {
		if _, err := h.store.Raise(ctx, a, now); err != nil {
			t.Fatal(err)
		}
	}
	h.login()
	if _, body := h.get("/alerts"); !strings.Contains(body, `href="/alerts/export?format=csv"`) {
		t.Error("no export link on the list")
	}
	res, body := h.get("/alerts/export?format=csv")
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Disposition"), "attachment;") {
		t.Fatalf("status %d, disposition %q", res.StatusCode, res.Header.Get("Content-Disposition"))
	}
	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1][5] != `'=HYPERLINK("http://x.example/","open")` || rows[1][6] != "'-2+3" {
		t.Errorf("rows = %q", rows)
	}
	_, body = h.get("/alerts/export?format=json&sev=low&sev=high")
	var out struct {
		Alerts    []apiAlert `json:"alerts"`
		Truncated bool       `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || len(out.Alerts) != 2 || out.Truncated {
		t.Errorf("json = %s, %v", body, err)
	}
	if res, _ := h.get("/alerts/export?format=xml"); res.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown format: %d", res.StatusCode)
	}
	log, _ := h.store.AuditLog(ctx, 5)
	if len(log) < 2 || log[0].Action != "alerts exported" || !strings.HasPrefix(log[0].Detail, "2 alerts as json") {
		t.Errorf("audit = %+v", log)
	}
}
