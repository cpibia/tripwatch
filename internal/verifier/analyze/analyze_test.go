package analyze

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
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
