package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// An accepted finding is not raised again while its evidence is the same; a change brings it
// back, and so does withdrawing the acceptance.
func TestAcceptedFindingStaysQuietUntilItChanges(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)
	file := Alert{HostID: "web-01", Fingerprint: "web:hidden_script:/srv/app/vendor/x/.cs.php", Severity: "high", Kind: "web",
		Title: "Script nascosto", Detail: "/srv/app/vendor/x/.cs.php\n222 byte, SHA-256 aaaa"}
	if _, err := s.Raise(ctx, file, at); err != nil {
		t.Fatal(err)
	}
	id, err := s.AlertID(ctx, "web-01", file.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptAlert(ctx, id, "ops@example.net", at); err != nil {
		t.Fatal(err)
	}
	status := func() string {
		t.Helper()
		a, err := s.Alert(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return a.Status
	}

	if fresh, err := s.Raise(ctx, file, at.Add(time.Hour)); err != nil || fresh || status() != StatusResolved {
		t.Fatalf("same evidence: fresh %v, status %q, %v", fresh, status(), err)
	}
	list, _ := s.Acceptances(ctx, "web-01")
	if len(list) != 1 || list[0].AcceptedBy != "ops@example.net" || list[0].Title != "Script nascosto" {
		t.Fatalf("acceptances = %+v", list)
	}

	changed := file
	changed.Detail = "/srv/app/vendor/x/.cs.php\n230 byte, SHA-256 bbbb"
	if fresh, err := s.Raise(ctx, changed, at.Add(2*time.Hour)); err != nil || !fresh || status() != "open" {
		t.Fatalf("changed evidence: fresh %v, status %q, %v", fresh, status(), err)
	}
	if list, _ := s.Acceptances(ctx, "web-01"); len(list) != 0 {
		t.Fatalf("an acceptance outlived the change: %+v", list)
	}

	if err := s.AcceptAlert(ctx, id, "ops@example.net", at); err != nil {
		t.Fatal(err)
	}
	if err := s.Withdraw(ctx, "web-01", changed.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if fresh, err := s.Raise(ctx, changed, at.Add(3*time.Hour)); err != nil || !fresh {
		t.Fatalf("after withdrawal: fresh %v, %v", fresh, err)
	}
}

func TestAcceptedProcessSurvivesARestart(t *testing.T) {
	if evidence("PID 812 (helper) esegue /opt/x/helper, rimosso dal disco. Hash ab.") != evidence("PID 9031 (helper) esegue /opt/x/helper, rimosso dal disco. Hash ab.") {
		t.Error("a new PID broke the acceptance of the same executable")
	}
	if evidence("PID 812 (helper) esegue /opt/x/helper. Hash ab.") == evidence("PID 812 (helper) esegue /opt/x/helper. Hash cd.") {
		t.Error("a new hash kept the acceptance")
	}
}

func TestVerifierAlertsCannotBeAccepted(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)
	for _, a := range []Alert{
		{HostID: "web-01", Fingerprint: "silence", Severity: "critical", Kind: "silence", Title: "Muto"},
		{HostID: "web-01", Fingerprint: "chain:broken", Severity: "critical", Kind: "chain", Title: "Catena rotta"},
	} {
		if _, err := s.Raise(ctx, a, at); err != nil {
			t.Fatal(err)
		}
		id, _ := s.AlertID(ctx, a.HostID, a.Fingerprint)
		if err := s.AcceptAlert(ctx, id, "ops@example.net", at); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s accepted: %v", a.Kind, err)
		}
	}
}
