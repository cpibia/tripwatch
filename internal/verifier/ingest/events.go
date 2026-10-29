package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/verifier/analyze"
	"github.com/cpibia/tripwatch/internal/verifier/store"
	"github.com/cpibia/tripwatch/internal/watch"
)

// Bounds on one batch of events: the sensor sends far fewer, a compromised one may send more.
const (
	maxBatchEvents   = 1000
	maxBatchFindings = 200
)

// watched stores a batch of events reported in real time and raises the alerts they call for.
func (s *Server) watched(ctx context.Context, host string, e protocol.Envelope, now time.Time) {
	var b watch.Batch
	if err := json.Unmarshal(e.Payload, &b); err != nil {
		s.Log.Warn("undecodable event batch", "host", host, "seq", e.Sequence, "err", err)
		return
	}
	if len(b.Events) > maxBatchEvents {
		b.Dropped += int64(len(b.Events) - maxBatchEvents)
		b.Events = b.Events[:maxBatchEvents]
	}
	events := make([]watch.Event, 0, len(b.Events))
	rows := make([]store.Event, 0, len(b.Events))
	for _, raw := range b.Events {
		var ev watch.Event
		if json.Unmarshal(raw, &ev) != nil || ev.Class == "" {
			continue
		}
		analyze.CleanHostText(&ev)
		// The sensor's clock dates the event; one far off is dated by its arrival instead.
		if ev.At.IsZero() || ev.At.After(now.Add(time.Hour)) || ev.At.Before(now.Add(-store.EventRetention)) {
			ev.At = now
		}
		subject := ev.Path
		if ev.Class == watch.ClassExec {
			subject = ev.Exe
		}
		events = append(events, ev)
		rows = append(rows, store.Event{HostID: host, Seq: e.Sequence, At: ev.At, Class: ev.Class, Op: ev.Op, Path: subject, PackageManager: b.PackageManager, Owner: ev.Owner, Data: raw})
	}
	kept, err := s.Store.AddEvents(ctx, rows, now)
	if err != nil {
		s.Log.Error("store events", "host", host, "err", err)
	}
	// Events of this batch not stored still count for the rules: a script dropped and removed in
	// the same batch is judged even past the quota.
	unstored := map[string][]watch.Event{}
	for i, ev := range events {
		if err != nil || !kept[i] {
			unstored[rows[i].Path] = append(unstored[rows[i].Path], ev)
		}
	}
	if err == nil && len(unstored) > 0 {
		s.raise(ctx, store.Alert{HostID: host, Fingerprint: "events:quota", Severity: "high", Kind: "sensor",
			Title:  "Real-time events not kept: daily quota exceeded",
			Detail: fmt.Sprintf("The server reported more than %d events in 24 hours. The ones over the quota still raise alerts but are not kept for the timeline: an intact sensor on a normal server does not report that many.", store.MaxEventsPerDay),
		}, now)
	}

	// Each path's history is read once for the batch, from the earliest time any event of the
	// batch can look back to, and filtered for each event.
	earliest := now
	for _, ev := range events {
		if ev.At.Before(earliest) {
			earliest = ev.At
		}
	}
	earliest = earliest.Add(-analyze.TransientWindow)
	read := map[string][]store.Event{}
	history := func(path string, since time.Time) []watch.Event {
		past, ok := read[path]
		if !ok {
			past, _ = s.Store.PathEvents(ctx, host, path, earliest)
			read[path] = past
		}
		out := make([]watch.Event, 0, len(past))
		for _, p := range past {
			if p.At.Before(since) {
				continue
			}
			var ev watch.Event
			if json.Unmarshal(p.Data, &ev) == nil {
				analyze.CleanHostText(&ev)
				ev.At = p.At
				out = append(out, ev)
			}
		}
		for _, ev := range unstored[path] {
			if !ev.At.Before(since) {
				out = append(out, ev)
			}
		}
		slices.SortStableFunc(out, func(a, b watch.Event) int { return a.At.Compare(b.At) })
		return out
	}
	findings := analyze.EvaluateEvents(events, b.PackageManager, history)
	if len(findings) > maxBatchFindings {
		findings = findings[:maxBatchFindings]
	}
	for _, f := range findings {
		s.raise(ctx, store.Alert{HostID: host, Fingerprint: f.Fingerprint, Severity: f.Severity, Kind: f.Kind, Title: f.Title, Detail: f.Detail}, now)
	}

	if b.Dropped > 0 {
		s.raise(ctx, store.Alert{HostID: host, Fingerprint: "events:lost:" + now.UTC().Format("2006-01-02"), Severity: "high", Kind: "sensor",
			Title:  "Real-time events lost",
			Detail: fmt.Sprintf("The sensor lost %d events: they came faster than it could read or send them. Flooding the watched directories is a way to hide one change among many; the next snapshot still shows the state they left.", b.Dropped),
		}, now)
	}
	if b.DroppedSystem > 0 {
		s.raise(ctx, store.Alert{HostID: host, Fingerprint: "events:lost-system:" + now.UTC().Format("2006-01-02"), Severity: "high", Kind: "sensor",
			Title:  "Real-time events on system paths lost",
			Detail: fmt.Sprintf("Among the lost events, %d were changes to root's accounts, SSH, privileges, services, scheduled tasks or start-up scripts: the sensor's queue was full of them. Check those places on the server; the next snapshot shows their state.", b.DroppedSystem),
		}, now)
	}
	if b.Skipped > 0 {
		s.raise(ctx, store.Alert{HostID: host, Fingerprint: "events:skipped", Severity: "low", Kind: "sensor",
			Title:  "Process starts not inspected",
			Detail: fmt.Sprintf("More processes started than the sensor inspects in a second: %d were not looked at. A build or a busy cron job does this; so does an attempt to slip a process past the sensor.", b.Skipped),
		}, now)
	}
}
