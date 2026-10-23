package ingest

import (
	"context"
	"encoding/json"
	"fmt"
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
		// The sensor's clock dates the event; one far off is dated by its arrival instead.
		if ev.At.IsZero() || ev.At.After(now.Add(time.Hour)) || ev.At.Before(now.Add(-store.EventRetention)) {
			ev.At = now
		}
		subject := ev.Path
		if ev.Class == watch.ClassExec {
			subject = ev.Exe
		}
		events = append(events, ev)
		rows = append(rows, store.Event{HostID: host, Seq: e.Sequence, At: ev.At, Class: ev.Class, Op: ev.Op, Path: subject, PackageManager: b.PackageManager, Data: raw})
	}
	stored, err := s.Store.AddEvents(ctx, rows, now)
	if err != nil {
		s.Log.Error("store events", "host", host, "err", err)
	}
	if stored < len(rows) && err == nil {
		s.raise(ctx, store.Alert{HostID: host, Fingerprint: "events:quota", Severity: "high", Kind: "sensor",
			Title:  "Real-time events not kept: daily quota exceeded",
			Detail: fmt.Sprintf("The server reported more than %d events in 24 hours. The ones over the quota still raise alerts but are not kept for the timeline: an intact sensor on a normal server does not report that many.", store.MaxEventsPerDay),
		}, now)
	}

	history := func(path string, since time.Time) []watch.Event {
		past, err := s.Store.PathEvents(ctx, host, path, since)
		if err != nil {
			return nil
		}
		out := make([]watch.Event, 0, len(past))
		for _, p := range past {
			var ev watch.Event
			if json.Unmarshal(p.Data, &ev) == nil {
				ev.At = p.At
				out = append(out, ev)
			}
		}
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
		s.raise(ctx, store.Alert{HostID: host, Fingerprint: "events:lost", Severity: "high", Kind: "sensor",
			Title:  "Real-time events lost",
			Detail: fmt.Sprintf("The sensor lost %d events: they came faster than it could read or send them. Flooding the watched directories is a way to hide one change among many; the next snapshot still shows the state they left.", b.Dropped),
		}, now)
	}
	if b.Skipped > 0 {
		s.raise(ctx, store.Alert{HostID: host, Fingerprint: "events:skipped", Severity: "medium", Kind: "sensor",
			Title:  "Process starts not inspected",
			Detail: fmt.Sprintf("More processes started than the sensor inspects in a second: %d were not looked at. A build or a busy cron job does this; so does an attempt to slip a process past the sensor.", b.Skipped),
		}, now)
	}
}
