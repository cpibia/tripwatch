package notify

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

func TestCompose(t *testing.T) {
	subject, body := Compose([]store.Alert{
		{ID: 7, HostID: "web-01", Severity: "critical", Title: "Secondo account root: svcadmin", Detail: "UID 0\nHome /var/lib/x"},
		{ID: 8, HostID: "web-02", Severity: "high", Title: "Nuova chiave SSH"},
	}, "https://tripwatch.example.com/")
	if subject != "[tripwatch] 1 critici, 2 allarmi su 2 server" {
		t.Errorf("subject = %q", subject)
	}
	for _, want := range []string{"CRITICAL · web-01 · Secondo account root", "  UID 0\n  Home /var/lib/x", "https://tripwatch.example.com/alerts/7"} {
		if !strings.Contains(body, want) {
			t.Errorf("body misses %q:\n%s", want, body)
		}
	}
	if strings.ContainsAny(subject, "\r\n") {
		t.Error("header injection through the subject")
	}
}

func TestRoundSendsOnceAndReportsFailures(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	for _, a := range []store.Alert{
		{HostID: "web-01", Fingerprint: "a", Severity: "critical", Kind: "accounts", Title: "root"},
		{HostID: "web-01", Fingerprint: "b", Severity: "low", Kind: "web", Title: "minor"},
	} {
		if _, err := st.Raise(ctx, a, now); err != nil {
			t.Fatal(err)
		}
	}

	failing := true
	var sent []string
	n := &Notifier{Store: st, Now: func() time.Time { return now }, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Mailer: Mailer{Host: "smtp.example.net", From: "tw@example.net", To: []string{"ops@example.net"}},
		send: func(_ Mailer, subject, _ string) error {
			if failing {
				return errors.New("starttls not offered")
			}
			sent = append(sent, subject)
			return nil
		}}

	n.Round(ctx)
	open, _ := st.Alerts(ctx, store.AlertFilter{HostID: "verifier", Statuses: []string{store.StatusOpen}})
	if len(open) != 1 || open[0].Fingerprint != "notify:smtp" {
		t.Fatalf("a failing mailer raised %+v", open)
	}

	failing = false
	n.Round(ctx)
	n.Round(ctx)
	if len(sent) != 1 || sent[0] != "[tripwatch] 1 critici, 1 allarmi su 1 server" {
		t.Fatalf("sent = %v, want one message with the critical alert only", sent)
	}
	if open, _ := st.Alerts(ctx, store.AlertFilter{HostID: "verifier", Statuses: []string{store.StatusOpen}}); len(open) != 0 {
		t.Fatalf("the mailer alert stayed open after a successful send: %+v", open)
	}

	disabled := &Notifier{Store: st, Now: n.Now, Log: n.Log, send: n.send}
	disabled.Round(ctx)
	if len(sent) != 1 {
		t.Fatal("a notifier without SMTP settings sent mail")
	}
}
