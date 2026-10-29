package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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
	pending, _ := s.Unnotified(ctx, []string{"critical", "high"}, 100)
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
	un, _ := s.Unnotified(ctx, []string{"high"}, 10)
	if len(un) != 1 {
		t.Fatalf("unnotified = %+v", un)
	}
	if err := s.MarkNotified(ctx, []int64{id}, t0); err != nil {
		t.Fatal(err)
	}
	if un, _ := s.Unnotified(ctx, []string{"high"}, 10); len(un) != 0 {
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

// One host's flood of findings is bounded, cannot hide another host's alert, and cannot mute a
// new finding of another rule on the same host.
func TestAlertFloodIsBounded(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	raise := func(a Alert) bool {
		t.Helper()
		fresh, err := s.Raise(ctx, a, t0)
		if err != nil {
			t.Fatal(err)
		}
		return fresh
	}
	long := strings.Repeat("é", MaxDetail)
	// Anyone can make the web logs report scripts in the upload directory.
	for i := range MaxOpenPerGroup + 50 {
		raise(Alert{HostID: "noisy", Fingerprint: "weblog:script_in_upload:/u/p" + strconv.Itoa(i) + ".php" + strings.Repeat("x", 600), Severity: "critical", Kind: "weblog",
			Title: strings.Repeat("t", 1000), Detail: long})
	}
	if !raise(Alert{HostID: "noisy", Fingerprint: "ssh-change:key:root:SHA256:abc", Severity: "high", Kind: "ssh-change", Title: "Nuova chiave SSH per root"}) {
		t.Fatal("a new SSH key was swallowed by the log noise")
	}
	// Medium findings of many rules hit the per-host bound.
	for i := range MaxOpenPerHost {
		raise(Alert{HostID: "noisy", Fingerprint: "web:r" + strconv.Itoa(i) + ":x", Severity: "medium", Kind: "web", Title: "m"})
	}
	if _, err := s.Raise(ctx, Alert{HostID: "quiet", Fingerprint: "ssh:one:x", Severity: "high", Kind: "ssh", Title: "key"}, t0); err != nil {
		t.Fatal(err)
	}

	open := map[string]Alert{}
	all, _ := s.Alerts(ctx, AlertFilter{HostID: "noisy", Statuses: []string{StatusOpen}})
	for _, a := range all {
		open[a.Fingerprint] = a
	}
	if _, ok := open["flood:critical:weblog:script_in_upload"]; !ok {
		t.Error("no aggregate alert for the noisy rule")
	}
	if f, ok := open[FloodFingerprint]; !ok || f.Severity != "high" {
		t.Errorf("no host flood alert for the medium findings: %+v", f)
	}
	if n := len(all); n > MaxOpenPerGroup+1+1+MaxOpenPerHost+1 {
		t.Errorf("%d open alerts: unbounded", n)
	}
	sums, err := s.Summaries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if q := sums["quiet"]; q.Open != 1 || q.Worst.Title != "key" {
		t.Errorf("the quiet host's alert is hidden: %+v", q)
	}
	for _, a := range all[:5] {
		if len(a.Title) > MaxTitle+len("…") || len(a.Detail) > MaxDetail+len("…") || len(a.Fingerprint) > MaxFingerprint || !utf8.ValidString(a.Detail) {
			t.Fatalf("unbounded or broken fields: title %d, detail %d, fingerprint %d", len(a.Title), len(a.Detail), len(a.Fingerprint))
		}
	}
	if _, err := s.Alert(ctx, 0); err == nil {
		t.Fatal("alert 0 exists")
	}
	un, err := s.Unnotified(ctx, []string{"critical", "high"}, 10)
	if err != nil || len(un) != 10 || un[0].Severity != "critical" {
		t.Fatalf("unnotified = %d alerts, %v", len(un), err)
	}
}

func TestAcceptDroppedKeepsLivenessOnly(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := s.Enroll(ctx, "h", pub, t0); err != nil {
		t.Fatal(err)
	}
	e := protocol.Envelope{HostID: "h", Kind: protocol.KindSnapshot, Sequence: 1, SentAt: t0, Payload: []byte("big")}
	if err := s.AcceptDropped(ctx, e, protocol.ChainState{}, protocol.ChainState{Sequence: 1}, t0); err != nil {
		t.Fatal(err)
	}
	h, _ := s.Host(ctx, "h")
	if h.Chain.Sequence != 1 || h.LastHeartbeat.IsZero() || !h.LastSnapshot.IsZero() {
		t.Fatalf("host = %+v", h)
	}
	if n, _ := s.SnapshotBytes(ctx, "h", t0.Add(-time.Hour)); n != 0 {
		t.Fatalf("a dropped snapshot was stored: %d bytes", n)
	}
	e.Sequence = 2
	if err := s.Accept(ctx, e, protocol.ChainState{Sequence: 1}, protocol.ChainState{Sequence: 2}, t0); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.SnapshotBytes(ctx, "h", t0.Add(-time.Hour)); n != 3 {
		t.Fatalf("stored bytes = %d", n)
	}
}

func TestEnrollTokensWorkOnce(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	secret, expires, err := s.CreateEnrollToken(ctx, "web-01", "ops@example.net", t0)
	if err != nil || !expires.Equal(t0.Add(EnrollTokenLifetime)) {
		t.Fatal(err)
	}
	if _, _, err := s.ConsumeEnrollToken(ctx, secret, t0.Add(2*EnrollTokenLifetime)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired token accepted: %v", err)
	}
	secret, _, _ = s.CreateEnrollToken(ctx, "web-01", "ops@example.net", t0)
	replaced, _, _ := s.CreateEnrollToken(ctx, "web-01", "ops@example.net", t0)
	if _, _, err := s.ConsumeEnrollToken(ctx, secret, t0); !errors.Is(err, ErrNotFound) {
		t.Fatal("a replaced token still works")
	}
	host, by, err := s.ConsumeEnrollToken(ctx, replaced, t0)
	if err != nil || host != "web-01" || by != "ops@example.net" {
		t.Fatalf("consume = %q %q %v", host, by, err)
	}
	if host, _, err := s.ConsumeEnrollToken(ctx, replaced, t0); !errors.Is(err, ErrTokenReused) || host != "web-01" {
		t.Fatalf("a used token presented again: %q %v, want the reuse reported with its host", host, err)
	}
	// Revoking a host cancels the token waiting for it.
	pending, _, _ := s.CreateEnrollToken(ctx, "web-02", "ops@example.net", t0)
	pub, _, _ := ed25519.GenerateKey(nil)
	_ = s.Enroll(ctx, "web-02", pub, t0)
	if err := s.Revoke(ctx, "web-02"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ConsumeEnrollToken(ctx, pending, t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the token of a revoked host still works: %v", err)
	}
}

func TestPruneResolved(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	for _, fp := range []string{"a:x:1", "a:x:2"} {
		if _, err := s.Raise(ctx, Alert{HostID: "h", Fingerprint: fp, Severity: "low", Kind: "a", Title: fp}, t0); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := s.Alerts(ctx, AlertFilter{})
	_ = s.Resolve(ctx, all[0].ID, "ops@example.net", t0)
	if err := s.PruneResolved(ctx, t0.Add(ResolvedRetention+time.Hour)); err != nil {
		t.Fatal(err)
	}
	left, _ := s.Alerts(ctx, AlertFilter{})
	if len(left) != 1 || left[0].Status != StatusOpen {
		t.Fatalf("left = %+v", left)
	}
}

// The bounding counts of Raise use the partial indexes, so resolved alerts cost nothing.
func TestRaiseCountsUseOpenIndexes(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	for _, q := range []string{
		`EXPLAIN QUERY PLAN SELECT COUNT(*) FROM alerts WHERE host_id = 'h' AND fingerprint >= 'a:' AND fingerprint < 'a;' AND severity = 'low' AND status != 'resolved'`,
		`EXPLAIN QUERY PLAN SELECT COUNT(*) FROM alerts WHERE host_id = 'h' AND status != 'resolved'`,
	} {
		rows, err := s.db.QueryContext(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		plan := ""
		for rows.Next() {
			var id, parent, unused int
			var detail string
			_ = rows.Scan(&id, &parent, &unused, &detail)
			plan += detail + "\n"
		}
		_ = rows.Close()
		if !strings.Contains(plan, "alerts_open_") {
			t.Errorf("query does not use a partial index:\n%s\n%s", q, plan)
		}
	}
}

// Noise sent to one script does not mute another script of the same rule, and an aggregate that
// keeps growing is mailed again after an hour.
func TestScriptGroupsAndAggregateRenotify(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	raise := func(fp string, at time.Time) bool {
		t.Helper()
		fresh, err := s.Raise(ctx, Alert{HostID: "h", Fingerprint: fp, Severity: "critical", Kind: "weblog", Title: "cmd"}, at)
		if err != nil {
			t.Fatal(err)
		}
		return fresh
	}
	for i := range MaxOpenPerGroup + 1 {
		raise("weblog:command_in_parameters:/index.php|/index.php?cmd=id&n="+strconv.Itoa(i), t0)
	}
	if !raise("weblog:command_in_parameters:/wp-content/uploads/x.php|/wp-content/uploads/x.php?cmd=id", t0) {
		t.Fatal("the real script was swallowed by noise sent to another one")
	}
	flood := "flood:critical:weblog:command_in_parameters:/index.php"
	agg, _ := s.Alerts(ctx, AlertFilter{HostID: "h", Statuses: []string{StatusOpen}})
	var id int64
	for _, a := range agg {
		if a.Fingerprint == flood {
			id = a.ID
		}
	}
	if id == 0 {
		t.Fatal("no aggregate for the noisy script")
	}
	_ = s.MarkNotified(ctx, []int64{id}, t0)
	raise("weblog:command_in_parameters:/index.php|/index.php?cmd=id&n=x1", t0.Add(10*time.Minute))
	if a, _ := s.Alert(ctx, id); a.NotifiedAt.IsZero() {
		t.Fatal("the aggregate was mailed again within the hour")
	}
	raise("weblog:command_in_parameters:/index.php|/index.php?cmd=id&n=x2", t0.Add(2*time.Hour))
	if a, _ := s.Alert(ctx, id); !a.NotifiedAt.IsZero() {
		t.Fatal("a growing aggregate is never mailed again")
	}
}

// Evidence of an alert still open outlives the 30-day retention; once the alert is resolved it
// goes like the rest.
func TestEvidenceOfOpenAlertsOutlivesRetention(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(nil)
	if err := s.Enroll(ctx, "h", pub, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Raise(ctx, Alert{HostID: "h", Fingerprint: "accounts:uid0:backup", Severity: "critical", Kind: "accounts", Title: "root"}, t0); err != nil {
		t.Fatal(err)
	}
	alertID, err := s.AlertID(ctx, "h", "accounts:uid0:backup")
	if err != nil {
		t.Fatal(err)
	}
	sealer := protocol.NewSealer("h", priv, protocol.ChainState{})
	var state protocol.ChainState
	var evidence int64
	deliver := func(day int) {
		at := t0.Add(time.Duration(day) * 24 * time.Hour)
		e := sealer.Seal(protocol.KindSnapshot, []byte(strconv.Itoa(day)), at)
		next, _ := protocol.Verify(e, "h", pub, state)
		if err := s.Accept(ctx, e, state, next, at); err != nil {
			t.Fatal(err)
		}
		state = next
		ids, _ := s.PendingSnapshots(ctx, 10)
		for _, id := range ids {
			if day == 1 {
				evidence = id
				_ = s.Keep(ctx, id, Evidence{AlertID: alertID})
			}
			_ = s.MarkAnalyzed(ctx, id)
		}
	}
	has := func(id int64) bool {
		snaps, _ := s.LatestSnapshots(ctx, "h", 1000)
		return slices.ContainsFunc(snaps, func(sn Snapshot) bool { return sn.ID == id })
	}
	for day := range 36 {
		deliver(day)
	}
	if !has(evidence) {
		t.Fatal("evidence of an open alert was deleted at 30 days")
	}
	if err := s.Resolve(ctx, alertID, "ops@example.net", t0); err != nil {
		t.Fatal(err)
	}
	deliver(36)
	if has(evidence) {
		t.Fatal("evidence of a resolved alert outlived the retention")
	}
}

// A snapshot is evidence of every alert it showed: closing the noise raised with a real change
// does not delete the proof of the change while it stays open.
func TestEvidenceOfEveryAlertInTheSnapshot(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = s.Enroll(ctx, "h", pub, t0)
	raise := func(fp, sev string) int64 {
		_, _ = s.Raise(ctx, Alert{HostID: "h", Fingerprint: fp, Severity: sev, Kind: "k", Title: fp}, t0)
		id, _ := s.AlertID(ctx, "h", fp)
		return id
	}
	change, noise := raise("accounts-change:new:admin2", "high"), raise("weblog:command_in_parameters:/index.php|x", "critical")
	sealer := protocol.NewSealer("h", priv, protocol.ChainState{})
	var state protocol.ChainState
	var evidence int64
	for day := range 40 {
		at := t0.Add(time.Duration(day) * 24 * time.Hour)
		e := sealer.Seal(protocol.KindSnapshot, []byte(strconv.Itoa(day)), at)
		next, _ := protocol.Verify(e, "h", pub, state)
		if err := s.Accept(ctx, e, state, next, at); err != nil {
			t.Fatal(err)
		}
		state = next
		ids, _ := s.PendingSnapshots(ctx, 10)
		for _, id := range ids {
			if day == 1 {
				evidence = id
				_ = s.Keep(ctx, id, Evidence{AlertID: noise}, Evidence{AlertID: change})
				_ = s.Resolve(ctx, noise, "ops@example.net", at)
			}
			_ = s.MarkAnalyzed(ctx, id)
		}
	}
	snaps, _ := s.LatestSnapshots(ctx, "h", 1000)
	if !slices.ContainsFunc(snaps, func(sn Snapshot) bool { return sn.ID == evidence }) {
		t.Fatal("the proof of an open change went with the noise closed beside it")
	}
}

// A password set from the command line with capitals reaches the same user as the console.
func TestUserEmailsAreCaseInsensitive(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.SetUser(ctx, "admin@example.com", "first-password-long", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, "admin@example.com", "first-password-long", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUser(ctx, " Admin@Example.COM", "second-password-long", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, "admin@example.com", "first-password-long", t0); err == nil {
		t.Fatal("the old password still works after a reset typed with capitals")
	}
	if _, err := s.Login(ctx, "ADMIN@example.com", "second-password-long", t0); err != nil {
		t.Fatalf("the new password does not work: %v", err)
	}
}

// Alerts are found by text in their host, title or detail, taken literally, and narrowed to
// kinds and ordered as asked.
func TestAlertsSearchAndOrder(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	for i, a := range []Alert{
		{HostID: "web-1", Fingerprint: "a", Severity: "high", Kind: "weblog", Title: "Command in parameters", Detail: "GET /x from 198.51.100.7"},
		{HostID: "db-1", Fingerprint: "b", Severity: "critical", Kind: "web", Title: "Script in uploads", Detail: "/var/www/a_b/uploads/x.php"},
		{HostID: "db-1", Fingerprint: "c", Severity: "medium", Kind: "ssh", Title: "Root login with a password", Detail: "PermitRootLogin yes"},
	} {
		if _, err := s.Raise(ctx, a, t0.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(f AlertFilter) []string {
		t.Helper()
		list, err := s.Alerts(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, a := range list {
			out = append(out, a.Fingerprint)
		}
		return out
	}
	for name, c := range map[string]struct {
		f    AlertFilter
		want []string
	}{
		"address in the detail": {AlertFilter{Query: "198.51.100.7"}, []string{"a"}},
		"host, any case":        {AlertFilter{Query: "DB-1"}, []string{"b", "c"}},
		"underscore literal":    {AlertFilter{Query: "a_b"}, []string{"b"}},
		"percent literal":       {AlertFilter{Query: "%"}, nil},
		"kinds":                 {AlertFilter{Kinds: []string{"ssh", "weblog"}}, []string{"a", "c"}},
		"newest":                {AlertFilter{Sort: SortNewest}, []string{"c", "b", "a"}},
		"oldest":                {AlertFilter{Sort: SortOldest}, []string{"a", "b", "c"}},
		"by host":               {AlertFilter{Sort: SortHost}, []string{"b", "c", "a"}},
		"severity first":        {AlertFilter{}, []string{"b", "a", "c"}},
	} {
		if got := ids(c.f); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// A backup is a database of its own with what the store held, and never overwrites a file.
func TestBackup(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.Enroll(ctx, "web-01", make([]byte, 32), t0); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "copy.db")
	if err := s.Backup(ctx, dst); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(ctx, dst); err == nil {
		t.Error("a backup overwrote an existing file")
	}
	copied, err := Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = copied.Close() }()
	if _, err := copied.Host(ctx, "web-01"); err != nil {
		t.Errorf("the backup lacks the host: %v", err)
	}
}
