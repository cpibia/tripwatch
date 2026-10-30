package ingest

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/watch"
)

func batch(t *testing.T, packageManager bool, dropped int64, events ...watch.Event) []byte {
	t.Helper()
	b := watch.Batch{Event: watch.BatchEvent, Dropped: dropped, PackageManager: packageManager}
	for _, e := range events {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		b.Events = append(b.Events, raw)
	}
	p, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Events let go over the budget of the scratch and upload directories are an alert of their
// own, so that a busy /tmp does not hide a sensor falling behind.
func TestEventsLostToBudgetApart(t *testing.T) {
	h := newHarness(t)
	c, _ := h.sensor("web-01")
	ctx := context.Background()
	for i, b := range []watch.Batch{{Dropped: 500, DroppedBudget: 500}, {Dropped: 7, DroppedBudget: 5}} {
		b.Event = watch.BatchEvent
		p, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		h.clock = now.Add(time.Duration(i) * time.Minute)
		if err := c.Send(ctx, protocol.KindEvent, p, h.clock); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]string{}
	for _, a := range h.alerts() {
		got[a.Fingerprint] = a.Severity + " " + strings.Join(strings.Fields(a.Detail)[:5], " ")
	}
	want := map[string]string{
		"events:lost-budget:2026-10-22": "medium The sensor let 5 events",
		"events:lost:2026-10-22":        "high The sensor lost 2 events:",
	}
	if !maps.Equal(got, want) {
		t.Errorf("alerts %v, want %v", got, want)
	}
	if c := h.ingest.Counts(); !slices.Contains(c, Count{Kind: "event", Status: http.StatusOK, N: 2}) {
		t.Errorf("counts = %+v", c)
	}
}

// A script dropped in the uploads and removed two batches later is stored, raises one alert
// when it lands and a critical one when it goes; what was lost on the way is reported too.
func TestEventBatchesRaiseAlerts(t *testing.T) {
	h := newHarness(t)
	c, _ := h.sensor("web-01")
	ctx := context.Background()
	shell := "/var/www/site/pub/media/x.php"
	uid := uint32(33)
	steps := []struct {
		events  []watch.Event
		dropped int64
	}{
		{events: []watch.Event{{At: now, Class: watch.ClassUpload, Op: watch.OpCreate, Path: shell, Size: 42, SHA256: "ab12", UID: &uid, Mode: "-rw-r--r--"},
			{At: now, Class: watch.ClassUpload, Op: watch.OpCreate, Path: "/var/www/site/pub/media/cat.jpg", Size: 900}}},
		{events: []watch.Event{{At: now.Add(time.Minute), Class: watch.ClassHook, Op: watch.OpWrite, Path: "/etc/profile.d/z.sh", Size: 10, SHA256: "cd34"}}, dropped: 3},
		{events: []watch.Event{{At: now.Add(3 * time.Minute), Class: watch.ClassUpload, Op: watch.OpDelete, Path: shell}}},
	}
	for i, s := range steps {
		h.clock = now.Add(time.Duration(i) * time.Minute)
		if err := c.Send(ctx, protocol.KindEvent, batch(t, false, s.dropped, s.events...), h.clock); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]string{}
	for _, a := range h.alerts() {
		got[a.Fingerprint] = a.Severity
	}
	want := map[string]string{
		"realtime:upload-script:" + shell + " sha256:ab12":                                                 "high",
		"realtime:upload-transient:" + shell + " at:" + strconv.FormatInt(now.Unix(), 10) + " sha256:ab12": "critical",
		"realtime:hook:/etc/profile.d/z.sh sha256:cd34":                                                    "high",
		"events:lost:2026-10-22":                                                                           "high",
	}
	for fp, sev := range want {
		if got[fp] != sev {
			t.Errorf("%s: severity %q, want %q (alerts %v)", fp, got[fp], sev, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("alerts %v", got)
	}
	evs, err := h.store.HostEvents(ctx, "web-01", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 4 || evs[0].Path != shell || evs[0].Op != watch.OpDelete || !strings.Contains(string(evs[3].Data), `"sha256":"ab12"`) {
		t.Fatalf("stored %+v", evs)
	}
}

// A batch filled to the batcher's bound, sealed in an envelope, stays within what the ingest
// accepts for an event: the payload is base64 there, a third larger.
func TestFullBatchFitsTheEventEnvelope(t *testing.T) {
	in := make(chan watch.Event, 2000)
	for i := range cap(in) {
		in <- watch.Event{Class: watch.ClassUpload, Op: watch.OpCreate, Path: "/var/www/site/wp-content/uploads/" + strconv.Itoa(i) + strings.Repeat("é", 100) + ".php"}
	}
	var payloads [][]byte
	b := &watch.Batcher{In: in, Send: func(_ context.Context, p []byte) error {
		payloads = append(payloads, p)
		return nil
	}, Lost: func() (int64, int64) { return 1 << 40, 1 << 40 }, LostSystem: func() int64 { return 1 << 40 }, LostBudget: func() int64 { return 1 << 40 }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b.Run(ctx)
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sealer := protocol.NewSealer(strings.Repeat("h", 64), key, protocol.ChainState{})
	largest := 0
	for _, p := range payloads {
		body, err := json.Marshal(sealer.Seal(protocol.KindEvent, p, time.Now()))
		if err != nil {
			t.Fatal(err)
		}
		largest = max(largest, len(body))
	}
	if len(payloads) == 0 || largest > MaxSmallSize || largest < MaxSmallSize/2 {
		t.Fatalf("%d batches, largest envelope %d bytes, ingest accepts %d", len(payloads), largest, MaxSmallSize)
	}
}
