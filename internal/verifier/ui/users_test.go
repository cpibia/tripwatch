package ui

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// An administrator invites an operator, who chooses a password through the link; the operator
// handles alerts but sees neither the settings nor the configuration; demoted to viewer, they
// can only read; every step is in the audit log.
func TestRolesAndInvitations(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	csrf := h.login()
	if _, err := h.store.Raise(ctx, store.Alert{HostID: "web-01", Fingerprint: "a", Severity: "high", Kind: "web", Title: "x"}, now); err != nil {
		t.Fatal(err)
	}
	if err := h.store.Enroll(ctx, "web-01", make([]byte, 32), now); err != nil {
		t.Fatal(err)
	}
	_, body := h.post("/users", url.Values{"csrf": {csrf}, "email": {"analyst@example.net"}, "role": {"operator"}})
	m := regexp.MustCompile(`/invite\?t=([A-Za-z0-9_-]+)`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no invitation link shown")
	}
	if _, body := h.get("/users"); strings.Contains(body, m[1]) {
		t.Fatal("invitation link shown again")
	}
	h.post("/logout", url.Values{"csrf": {csrf}})

	if res, body := h.post("/invite", url.Values{"t": {m[1]}, "password": {"short"}, "again": {"short"}}); res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "at least 12") {
		t.Fatalf("short password: %d", res.StatusCode)
	}
	if res, _ := h.post("/invite", url.Values{"t": {m[1]}, "password": {"a long new password"}, "again": {"a long new password"}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("accept: %d", res.StatusCode)
	}
	_, body = h.get("/")
	ops := csrfField.FindStringSubmatch(body)[1]
	if strings.Contains(body, `href="/users"`) || strings.Contains(body, `href="/notifications"`) {
		t.Error("operator sees administrator pages in the menu")
	}
	for _, path := range []string{"/users", "/audit", "/notifications", "/enroll"} {
		if res, _ := h.get(path); res.StatusCode != http.StatusForbidden {
			t.Errorf("operator on %s: %d", path, res.StatusCode)
		}
	}
	alerts, _ := h.store.Alerts(ctx, store.AlertFilter{HostID: "web-01"})
	if res, _ := h.post("/alerts/"+itoa(alerts[0].ID)+"/ack", url.Values{"csrf": {ops}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("operator ack: %d", res.StatusCode)
	}
	if res, _ := h.post("/hosts/web-01/revoke", url.Values{"csrf": {ops}, "confirm": {"web-01"}}); res.StatusCode != http.StatusForbidden {
		t.Errorf("operator revoked a server: %d", res.StatusCode)
	}

	if err := h.store.SetRole(ctx, "analyst@example.net", store.RoleViewer); err != nil {
		t.Fatal(err)
	}
	if res, _ := h.post("/alerts/"+itoa(alerts[0].ID)+"/resolve", url.Values{"csrf": {ops}}); res.StatusCode != http.StatusForbidden {
		t.Errorf("viewer resolved: %d", res.StatusCode)
	}
	if res, _ := h.get("/alerts"); res.StatusCode != http.StatusOK {
		t.Errorf("viewer cannot read: %d", res.StatusCode)
	}

	log, _ := h.store.AuditLog(ctx, 20)
	var actions []string
	for _, e := range log {
		actions = append(actions, e.Actor+" "+e.Action)
	}
	joined := strings.Join(actions, "; ")
	for _, want := range []string{email + " user invited", "analyst@example.net invitation accepted", "analyst@example.net alert acknowledged"} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit lacks %q: %s", want, joined)
		}
	}
}
