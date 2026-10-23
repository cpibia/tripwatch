package analyze

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/verifier/store"
)

var now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

type harness struct {
	t     *testing.T
	store *store.Store
	an    *Analyzer
	clock time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h := &harness{t: t, store: st, clock: now}
	h.an = &Analyzer{Store: st, Now: func() time.Time { return h.clock }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := st.Enroll(context.Background(), "web-01", make([]byte, 32), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	return h
}

// deliver stores an envelope of web-01 as the ingest would after verifying it.
func (h *harness) deliver(kind protocol.Kind, payload []byte) {
	h.t.Helper()
	ctx := context.Background()
	host, err := h.store.Host(ctx, "web-01")
	if err != nil {
		h.t.Fatal(err)
	}
	e := protocol.Envelope{HostID: "web-01", Kind: kind, Sequence: host.Chain.Sequence + 1, SentAt: h.clock, Payload: payload}
	if err := h.store.Accept(ctx, e, host.Chain, protocol.ChainState{Sequence: e.Sequence}, h.clock); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) open() map[string]store.Alert {
	h.t.Helper()
	all, err := h.store.Alerts(context.Background(), store.AlertFilter{Statuses: []string{store.StatusOpen}})
	if err != nil {
		h.t.Fatal(err)
	}
	out := map[string]store.Alert{}
	for _, a := range all {
		out[a.Fingerprint] = a
	}
	return out
}

const (
	rootOnly   = `{"snapshot":{"results":{"accounts":{"accounts":[{"name":"root","uid":0}]}}}}`
	secondRoot = `{"snapshot":{"results":{"accounts":{"accounts":[{"name":"root","uid":0},{"name":"backup","uid":0}]}}}}`
)

// The worker drains the queue in order: a second root account appearing in the newer snapshot
// raises a critical alert, and an undecodable snapshot raises its own.
func TestWorkerAnalysesQueuedSnapshots(t *testing.T) {
	h := newHarness(t)
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, secondRoot))
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, []byte("not gzip"))

	ctx, cancel := context.WithCancel(context.Background())
	wake := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() { h.an.Worker(ctx, wake); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		pending, err := h.store.PendingSnapshots(context.Background(), 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(pending) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still pending: %v", pending)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	alerts := h.open()
	if a, ok := alerts["accounts:uid0:backup"]; !ok || a.Severity != "critical" {
		t.Errorf("second root account: %+v", alerts)
	}
	if a, ok := alerts["snapshot:undecodable"]; !ok || a.Severity != "high" {
		t.Errorf("undecodable snapshot: %+v", alerts)
	}
}

func TestSilentSensor(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Enrolled an hour ago and never heard from.
	h.an.Silent(ctx, 3*time.Minute, 3*time.Hour)
	if _, ok := h.open()["sensor:silent"]; !ok {
		t.Fatal("a host never heard from raised no silence alert")
	}

	// It reports again: the silence alert closes by itself, even though it is critical.
	h.deliver(protocol.KindHeartbeat, nil)
	h.an.Silent(ctx, 3*time.Minute, 3*time.Hour)
	if _, ok := h.open()["sensor:silent"]; ok {
		t.Fatal("the silence alert stayed open after a heartbeat")
	}

	// Heartbeats keep coming but snapshots stop.
	h.clock = h.clock.Add(4 * time.Hour)
	h.deliver(protocol.KindHeartbeat, nil)
	h.an.Silent(ctx, 3*time.Minute, 3*time.Hour)
	alerts := h.open()
	if _, ok := alerts["sensor:no-snapshots"]; !ok {
		t.Fatalf("heartbeats without snapshots raised nothing: %+v", alerts)
	}
	if _, ok := alerts["sensor:silent"]; ok {
		t.Fatal("a host sending heartbeats is reported silent")
	}

	// A revoked host is no longer watched.
	if err := h.store.Revoke(ctx, "web-01"); err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(time.Hour)
	h.an.Silent(ctx, 3*time.Minute, 3*time.Hour)
	if a, ok := h.open()["sensor:silent"]; ok {
		t.Fatalf("revoked host reported silent: %+v", a)
	}
}

func TestFindingsPerSnapshotAreBounded(t *testing.T) {
	h := newHarness(t)
	accounts := `{"name":"root","uid":0}`
	for i := range 300 {
		accounts += fmt.Sprintf(`,{"name":"r%d","uid":0}`, i)
	}
	h.deliver(protocol.KindSnapshot, gz(t, `{"snapshot":{"results":{"accounts":{"accounts":[`+accounts+`]}}}}`))
	ids, _ := h.store.PendingSnapshots(context.Background(), 1)
	h.an.RunSnapshot(context.Background(), ids[0])
	// 200 findings of one rule reach the store: 100 alerts, then the rule's aggregate; plus the
	// summary of the 101 findings the snapshot cap dropped.
	alerts := h.open()
	if len(alerts) != store.MaxOpenPerGroup+2 {
		t.Fatalf("%d alerts, want %d", len(alerts), store.MaxOpenPerGroup+2)
	}
	if _, ok := alerts["snapshot:too-many-findings"]; !ok {
		t.Fatal("no summary of the dropped findings")
	}
}

// The snapshot that shows a change and the one before it survive the thinning.
func TestChangeKeepsBothSnapshots(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, secondRoot))
	ids, _ := h.store.PendingSnapshots(ctx, 10)
	for _, id := range ids {
		h.an.RunSnapshot(ctx, id)
		_ = h.store.MarkAnalyzed(ctx, id)
	}
	// Three days of unchanged hourly snapshots push both past the dense window.
	for range 72 {
		h.clock = h.clock.Add(time.Hour)
		h.deliver(protocol.KindSnapshot, gz(t, secondRoot))
		next, _ := h.store.PendingSnapshots(ctx, 10)
		for _, id := range next {
			h.an.RunSnapshot(ctx, id)
			_ = h.store.MarkAnalyzed(ctx, id)
		}
	}
	snaps, _ := h.store.LatestSnapshots(ctx, "web-01", 1000)
	kept := map[int64]bool{}
	for _, s := range snaps {
		kept[s.ID] = true
	}
	if !kept[ids[0]] || !kept[ids[1]] {
		t.Fatalf("the snapshots around the change were thinned: kept %d snapshots", len(snaps))
	}
}

// A log request repeated in every snapshot raises its alert once: only the snapshot where it
// started (and the one before) outlives the retention, not every snapshot that shows it again.
func TestRepeatedEventDoesNotKeepEverySnapshot(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	payload := gz(t, `{"snapshot":{"results":{"weblog":{"events":[{"rule":"command_in_parameters","severity":"critical","log":"/var/log/nginx/access.log","attacker_controlled":{"request":"/index.php?c=id"}}]}}}}`)
	for range 40 {
		h.deliver(protocol.KindSnapshot, payload)
		ids, _ := h.store.PendingSnapshots(ctx, 10)
		for _, id := range ids {
			h.an.RunSnapshot(ctx, id)
			_ = h.store.MarkAnalyzed(ctx, id)
		}
		h.clock = h.clock.Add(24 * time.Hour)
	}
	snaps, _ := h.store.LatestSnapshots(ctx, "web-01", 1000)
	if len(snaps) > 33 {
		t.Fatalf("%d of 40 daily snapshots kept: the repeated event pins them past 30 days", len(snaps))
	}
}

// An alert made to reopen at every snapshot keeps one proof a day, not one per snapshot.
func TestFlappingAlertKeepsOneProofADay(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for i := range 48 {
		payload := rootOnly
		if i%2 == 1 {
			payload = secondRoot
		}
		h.deliver(protocol.KindSnapshot, gz(t, payload))
		ids, _ := h.store.PendingSnapshots(ctx, 10)
		for _, id := range ids {
			h.an.RunSnapshot(ctx, id)
			_ = h.store.MarkAnalyzed(ctx, id)
		}
		// Resolved by hand each time, so the next snapshot with it reopens the alert.
		alerts, _ := h.store.Alerts(ctx, store.AlertFilter{HostID: "web-01", Statuses: []string{store.StatusOpen}})
		for _, a := range alerts {
			_ = h.store.Resolve(ctx, a.ID, "ops@example.net", h.clock)
		}
		h.clock = h.clock.Add(time.Hour)
	}
	// Three days later the thinning runs: of the 48 hourly snapshots only the proofs (one a
	// day with the snapshot before it), the last of each day and the baseline remain.
	h.clock = h.clock.Add(72 * time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	snaps, _ := h.store.SnapshotHeads(ctx, "web-01", 100)
	if len(snaps) > 10 {
		t.Fatalf("%d snapshots kept: a flapping alert keeps one per reopening", len(snaps))
	}
}

func (h *harness) analyse() {
	h.t.Helper()
	ctx := context.Background()
	ids, _ := h.store.PendingSnapshots(ctx, 10)
	for _, id := range ids {
		h.an.RunSnapshot(ctx, id)
		_ = h.store.MarkAnalyzed(ctx, id)
	}
}

func rootWith(name, home string) string {
	return `{"snapshot":{"results":{"accounts":{"accounts":[{"name":"root","uid":0},{"name":"` + name + `","uid":0,"home":"` + home + `"}]}}}}`
}

// Noise anyone can raise uses up only its own kind's daily bound: an alert only root can cause,
// arriving after it, is still kept as evidence.
func TestRootAlertKeptAfterTheNoise(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	h.analyse()
	for i := range 40 {
		h.clock = h.clock.Add(10 * time.Minute)
		h.deliver(protocol.KindSnapshot, gz(t, fmt.Sprintf(`{"snapshot":{"results":{"accounts":{"accounts":[{"name":"root","uid":0}]},"weblog":{"events":[{"rule":"command_in_parameters","severity":"critical","log":"/l","attacker_controlled":{"request":"/x%d.php?cmd=id"}}]}}}}`, i)))
		h.analyse()
	}
	day := now.Truncate(24 * time.Hour)
	h.clock = h.clock.Add(10 * time.Minute)
	h.deliver(protocol.KindSnapshot, gz(t, secondRoot))
	h.analyse()
	id, _ := h.store.AlertID(ctx, "web-01", "accounts:uid0:backup")
	if ok, _ := h.store.HasEvidenceSince(ctx, id, criticalDigest(t, h, id), day); !ok {
		t.Fatal("a root alert after the noise was not kept as evidence")
	}
}

// criticalDigest is the digest the analyser gave the alert's current content.
func criticalDigest(t *testing.T, h *harness, id int64) string {
	t.Helper()
	a, err := h.store.Alert(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(a.Severity + "\x00" + a.Detail))
	return hex.EncodeToString(sum[:8])
}

// A harmless decoy raised early does not take the day's proof from different content raised
// later under the same alert.
func TestDecoyDoesNotTakeTheDaysProof(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	h.analyse()
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, rootWith("backup", "/decoy")))
	h.analyse()
	id, _ := h.store.AlertID(ctx, "web-01", "accounts:uid0:backup")
	_ = h.store.Resolve(ctx, id, "ops@example.net", h.clock)
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	h.analyse()
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, rootWith("backup", "/var/lib/real")))
	h.analyse()
	genuine, _ := h.store.SnapshotHeads(ctx, "web-01", 1)
	// A later snapshot the same day, so the genuine one is not kept just as the day's last.
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, rootWith("backup", "/var/lib/real")))
	h.analyse()

	h.clock = h.clock.Add(72 * time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	snaps, _ := h.store.SnapshotHeads(ctx, "web-01", 100)
	if !slices.ContainsFunc(snaps, func(s store.SnapshotHead) bool { return s.ID == genuine[0].ID }) {
		t.Fatal("the snapshot with the real content went with the thinning")
	}
}

// A critical log alert, which anyone can raise with one request, is bounded like any other
// kind: a new script each snapshot does not keep every snapshot.
func TestAnonymousCriticalAlertsAreBounded(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for i := range 40 {
		h.clock = h.clock.Add(10 * time.Minute)
		h.deliver(protocol.KindSnapshot, gz(t, fmt.Sprintf(`{"snapshot":{"results":{"weblog":{"events":[{"rule":"command_in_parameters","severity":"critical","log":"/var/log/nginx/access.log","attacker_controlled":{"request":"/x%d.php?cmd=id"}}]}}}}`, i)))
		h.analyse()
	}
	kept, _ := h.store.EvidenceSnapshotsSince(ctx, "web-01", now.Truncate(24*time.Hour))
	if kept["weblog"] == 0 || kept["weblog"] > maxEvidencePerDay+1 {
		t.Fatalf("%d snapshots kept as evidence of anonymous critical alerts", kept["weblog"])
	}
}
