package ui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// An alert's page shows what else happened on its server an hour either side: other alerts and
// real-time events, not those further away or on another server.
func TestAlertShowsWhatHappenedAround(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.store.Enroll(ctx, "web-01", make([]byte, 32), now.Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	raise := func(host, fp, title string, at time.Time) {
		if _, err := h.store.Raise(ctx, store.Alert{HostID: host, Fingerprint: fp, Severity: "high", Kind: "web", Title: title}, at); err != nil {
			t.Fatal(err)
		}
	}
	raise("web-01", "a", "the alert", now)
	raise("web-01", "b", "near-alert", now.Add(-30*time.Minute))
	raise("web-01", "c", "far-alert", now.Add(-2*time.Hour))
	raise("web-02", "d", "other-server-alert", now)
	if _, err := h.store.AddEvents(ctx, []store.Event{
		{HostID: "web-01", Seq: 1, At: now.Add(10 * time.Minute), Class: "upload", Op: "create", Path: "/srv/up/near-event.php", Data: []byte(`{}`)},
		{HostID: "web-01", Seq: 2, At: now.Add(3 * time.Hour), Class: "upload", Op: "create", Path: "/srv/up/far-event.php", Data: []byte(`{}`)},
	}, now); err != nil {
		t.Fatal(err)
	}
	var id int64
	all, _ := h.store.Alerts(ctx, store.AlertFilter{HostID: "web-01"})
	for _, a := range all {
		if a.Title == "the alert" {
			id = a.ID
		}
	}
	h.login()
	_, body := h.get("/alerts/" + itoa(id))
	for _, want := range []string{"near-alert", "near-event.php"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, not := range []string{"far-alert", "far-event.php", "other-server-alert"} {
		if strings.Contains(body, not) {
			t.Errorf("shows %s", not)
		}
	}
}
