package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
)

var t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAlertsDedupeAndSeverityRules(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	raise := func(fp, sev string) bool {
		t.Helper()
		isNew, err := s.Raise(ctx, Alert{HostID: "h", Fingerprint: fp, Severity: sev, Kind: "web", Title: fp}, t0)
		if err != nil {
			t.Fatal(err)
		}
		return isNew
	}
	if !raise("a", "medium") || raise("a", "medium") {
		t.Fatal("first raise must be new, the second an update")
	}
	raise("b", "critical")

	// The condition behind both disappears: the medium alert closes, the critical one waits for a person.
	if err := s.ResolveMissing(ctx, "h", "web", nil, t0); err != nil {
		t.Fatal(err)
	}
	alerts, _ := s.Alerts(ctx, AlertFilter{HostID: "h"})
	status := map[string]string{}
	for _, a := range alerts {
		status[a.Fingerprint] = a.Status
	}
	if status["a"] != StatusResolved || status["b"] != StatusOpen {
		t.Errorf("statuses = %v", status)
	}
	if !raise("a", "medium") {
		t.Error("a resolved condition that comes back must count as new")
	}

	// Resolved before the notifier ran: still to be sent.
	raise("c", "high")
	_ = s.ResolveGone(ctx, "h", "web", nil, t0)
	pending, _ := s.Unnotified(ctx, []string{"critical", "high"})
	if len(pending) != 2 {
		t.Errorf("unnotified = %+v", pending)
	}
}

func TestRetentionKeepsBaselineAndRecentSnapshots(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(nil)
	if err := s.Enroll(ctx, "h", pub, t0); err != nil {
		t.Fatal(err)
	}
	sealer := protocol.NewSealer("h", priv, protocol.ChainState{})
	var state protocol.ChainState
	for day := range 40 {
		at := t0.Add(time.Duration(day) * 24 * time.Hour)
		e := sealer.Seal(protocol.KindSnapshot, []byte{byte(day)}, at)
		next, err := protocol.Verify(e, "h", pub, state)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Accept(ctx, e, state, next, at); err != nil {
			t.Fatal(err)
		}
		state = next
		ids, _ := s.PendingSnapshots(ctx, 100)
		for _, id := range ids {
			_ = s.MarkAnalyzed(ctx, id)
		}
	}
	snaps, _ := s.LatestSnapshots(ctx, "h", 1000)
	if len(snaps) != 32 || snaps[len(snaps)-1].Payload[0] != 0 {
		t.Errorf("kept %d snapshots, oldest payload %v; want 30 days plus the baseline", len(snaps), snaps[len(snaps)-1].Payload)
	}

	// A stale verification (another envelope got in first) cannot be stored.
	e := sealer.Seal(protocol.KindHeartbeat, nil, t0)
	if err := s.Accept(ctx, e, protocol.ChainState{Sequence: 1}, protocol.ChainState{Sequence: 2}, t0); !errors.Is(err, ErrChainMoved) {
		t.Errorf("err = %v", err)
	}
}

func TestLoginAndSessions(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.SetUser(ctx, "ops@example.com", "correct horse battery", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, "ops@example.com", "wrong", t0); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := s.Login(ctx, "nobody@example.com", "x", t0); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("unknown user: %v", err)
	}
	token, err := s.Login(ctx, "ops@example.com", "correct horse battery", t0)
	if err != nil {
		t.Fatal(err)
	}
	if email, err := s.Session(ctx, token, t0.Add(time.Hour)); err != nil || email != "ops@example.com" {
		t.Errorf("session = %q, %v", email, err)
	}
	if _, err := s.Session(ctx, token, t0.Add(SessionLifetime+time.Minute)); err == nil {
		t.Error("expired session accepted")
	}
	_ = s.SetUser(ctx, "ops@example.com", "another long password", t0)
	if _, err := s.Session(ctx, token, t0.Add(time.Hour)); err == nil {
		t.Error("a password change must end existing sessions")
	}
}
