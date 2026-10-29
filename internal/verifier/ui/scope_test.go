package ui

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// A user limited to a label sees only the servers carrying it, on every page and in every
// count, gets "not found" for the others, and cannot change their alerts even with a form made
// by hand.
func TestScopedUserSeesOnlyTheirServers(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, id := range []string{"acme-web", "other-db"} {
		if err := h.store.Enroll(ctx, id, make([]byte, 32), now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := h.store.Alive(ctx, id, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.store.SetHostDetails(ctx, "acme-web", "", []string{"client=acme"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetHostDetails(ctx, "other-db", "", []string{"client=acmex"}, ""); err != nil {
		t.Fatal(err)
	}
	for _, a := range []store.Alert{
		{HostID: "acme-web", Fingerprint: "w", Severity: "high", Kind: "web", Title: "seen-title", Detail: "/srv/shared/x.php"},
		{HostID: "other-db", Fingerprint: "d", Severity: "critical", Kind: "web", Title: "hidden-title", Detail: "/srv/shared/y.php"},
	} {
		if _, err := h.store.Raise(ctx, a, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.store.AddEvents(ctx, []store.Event{{HostID: "other-db", Seq: 1, At: now, Class: "upload", Op: "create", Path: "/srv/shared/hidden-event.php",
		Data: []byte(`{"path":"/srv/shared/hidden-event.php"}`)}}, now); err != nil {
		t.Fatal(err)
	}
	all, _ := h.store.Alerts(ctx, store.AlertFilter{})
	var hidden int64
	for _, a := range all {
		if a.HostID == "other-db" {
			hidden = a.ID
		}
	}

	csrf := h.login()
	token, _, err := h.store.CreateInvite(ctx, "acme@example.net", store.RoleOperator, email, now)
	if err != nil {
		t.Fatal(err)
	}
	h.post("/logout", url.Values{"csrf": {csrf}})
	h.post("/invite", url.Values{"t": {token}, "password": {"a long new password"}, "again": {"a long new password"}})
	if err := h.store.SetScope(ctx, "acme@example.net", "client=acme"); err != nil {
		t.Fatal(err)
	}
	_, body := h.get("/")
	ops := csrfField.FindStringSubmatch(body)[1]

	for _, path := range []string{"/", "/hosts", "/alerts?view=all", "/search?q=%2Fsrv%2Fshared", "/search?q=other",
		"/alerts/export?view=all&format=csv", "/alerts/export?view=all&format=json"} {
		_, body := h.get(path)
		if strings.Contains(body, "other-db") || strings.Contains(body, "hidden-title") || strings.Contains(body, "hidden-event") {
			t.Errorf("%s shows a server out of scope", path)
		}
	}
	if _, body := h.get("/alerts?view=all"); !strings.Contains(body, "seen-title") {
		t.Error("own alert missing")
	}
	for _, path := range []string{"/hosts/other-db", "/alerts/" + itoa(hidden)} {
		if res, _ := h.get(path); res.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, res.StatusCode)
		}
	}
	h.post("/bulk/resolve", url.Values{"csrf": {ops}, "id": {itoa(hidden)}})
	h.post("/alerts/"+itoa(hidden)+"/ack", url.Values{"csrf": {ops}})
	if a, _ := h.store.Alert(ctx, hidden); a.Status != store.StatusOpen {
		t.Errorf("out-of-scope alert changed to %s", a.Status)
	}
	if strings.Contains(body, "favicon-alarm") {
		t.Error("the tab icon tells about a critical alert out of scope")
	}
}
