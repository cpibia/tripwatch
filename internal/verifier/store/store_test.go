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

func TestHostsActivityAndSnapshots(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	pub, _, _ := ed25519.GenerateKey(nil)
	for _, id := range []string{"web-02", "web-01"} {
		if err := s.Enroll(ctx, id, pub, t0); err != nil {
			t.Fatal(err)
		}
	}
	deliver := func(kind protocol.Kind, at time.Time) {
		t.Helper()
		h, _ := s.Host(ctx, "web-01")
		e := protocol.Envelope{HostID: "web-01", Kind: kind, Sequence: h.Chain.Sequence + 1, SentAt: at, Payload: []byte("payload")}
		if err := s.Accept(ctx, e, h.Chain, protocol.ChainState{Sequence: e.Sequence}, at); err != nil {
			t.Fatal(err)
		}
	}
	deliver(protocol.KindHeartbeat, t0.Add(time.Minute))
	deliver(protocol.KindHeartbeat, t0.Add(90*time.Second)) // same minute: recorded once
	deliver(protocol.KindSnapshot, t0.Add(2*time.Minute))
	deliver(protocol.KindHeartbeat, t0.Add(8*24*time.Hour)) // pushes the first marks out of retention

	hosts, err := s.Hosts(ctx)
	if err != nil || len(hosts) != 2 || hosts[0].ID != "web-01" {
		t.Fatalf("hosts = %+v, %v", hosts, err)
	}
	marks, err := s.Activity(ctx, "web-01", t0)
	if err != nil || len(marks) != 1 || marks[0].Kind != protocol.KindHeartbeat {
		t.Fatalf("activity after retention = %+v, %v", marks, err)
	}
	heads, err := s.SnapshotHeads(ctx, "web-01", 10)
	if err != nil || len(heads) != 1 || heads[0].Size != len("payload") || heads[0].Analyzed {
		t.Fatalf("snapshot heads = %+v, %v", heads, err)
	}
	if n, _ := s.CountSnapshots(ctx, "web-01", t0); n != 1 {
		t.Fatalf("count = %d", n)
	}
	if err := s.Revoke(ctx, "web-02"); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking an unknown host: %v", err)
	}
	if _, err := s.Host(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown host: %v", err)
	}
}

func TestAlertLifecycle(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.Raise(ctx, Alert{HostID: "web-01", Fingerprint: "a", Severity: "high", Kind: "ssh", Title: "key"}, t0); err != nil {
		t.Fatal(err)
	}
	a, _ := s.Alerts(ctx, AlertFilter{})
	id := a[0].ID
	if err := s.Ack(ctx, id, "ops@example.net", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Ack(ctx, id, "ops@example.net", t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second ack: %v", err)
	}
	un, _ := s.Unnotified(ctx, []string{"high"})
	if len(un) != 1 {
		t.Fatalf("unnotified = %+v", un)
	}
	if err := s.MarkNotified(ctx, []int64{id}, t0); err != nil {
		t.Fatal(err)
	}
	if un, _ := s.Unnotified(ctx, []string{"high"}); len(un) != 0 {
		t.Fatalf("still unnotified: %+v", un)
	}
	if err := s.Resolve(ctx, id, "ops@example.net", t0); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Alert(ctx, id); got.Status != StatusResolved || got.AckedBy != "ops@example.net" {
		t.Fatalf("after resolve: %+v", got)
	}
	if _, err := s.Alert(ctx, id+1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing alert: %v", err)
	}
}

// Hourly snapshots: the last 48 hours stay whole, older days keep their last snapshot, the
// baseline and the snapshots marked as evidence.
func TestRetentionThinsOlderSnapshots(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(nil)
	if err := s.Enroll(ctx, "h", pub, t0); err != nil {
		t.Fatal(err)
	}
	sealer := protocol.NewSealer("h", priv, protocol.ChainState{})
	var state protocol.ChainState
	var evidence int64
	const hours = 5 * 24
	for hour := range hours {
		at := t0.Add(time.Duration(hour) * time.Hour)
		e := sealer.Seal(protocol.KindSnapshot, []byte{byte(hour)}, at)
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
			if hour == 30 {
				evidence = id
				_ = s.Keep(ctx, id)
			}
			_ = s.MarkAnalyzed(ctx, id)
		}
	}
	snaps, _ := s.LatestSnapshots(ctx, "h", 1000)
	kept := map[int64]bool{}
	for _, sn := range snaps {
		kept[sn.ID] = true
	}
	// Hours 71 to 119 are within 48 hours of the newest: 49. Of the older ones, the last of
	// days 0 and 1 (day 2 ends inside the dense window), the baseline and the evidence: 4.
	if len(snaps) != 53 {
		t.Errorf("kept %d snapshots, want 53", len(snaps))
	}
	if !kept[evidence] || snaps[len(snaps)-1].Payload[0] != 0 {
		t.Error("evidence or baseline thinned out")
	}
}
