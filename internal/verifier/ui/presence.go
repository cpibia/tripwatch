package ui

import (
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// Gap is a stretch without heartbeats longer than the silence threshold.
type Gap struct {
	From    time.Time
	To      time.Time
	Ongoing bool
}

func (g Gap) Duration() time.Duration { return g.To.Sub(g.From) }

// silences finds the gaps between heartbeats, within the window ending at until, longer than
// limit. A gap runs from the last heartbeat, as the "silent since" of the host does.
func silences(marks []store.Mark, enrolled, until time.Time, window, limit time.Duration) []Gap {
	since := until.Add(-window)
	last := enrolled
	if last.Before(since) {
		last = since
	}
	var out []Gap
	for _, m := range marks {
		if m.Kind != protocol.KindHeartbeat || m.At.Before(since) {
			continue
		}
		if m.At.Sub(last) > limit {
			out = append(out, Gap{From: last, To: m.At})
		}
		last = m.At
	}
	if until.Sub(last) > limit {
		out = append(out, Gap{From: last, To: until, Ongoing: true})
	}
	// Newest first, like every other list in the interface.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	}
	return 3
}

// mostUrgent is the alert to look at first: the most severe one nobody has taken yet, and among
// those the oldest; failing that, the most severe one in progress.
func mostUrgent(alerts []store.Alert) *store.Alert {
	var best *store.Alert
	better := func(a, b *store.Alert) bool {
		if (a.Status == store.StatusOpen) != (b.Status == store.StatusOpen) {
			return a.Status == store.StatusOpen
		}
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra < rb
		}
		if ka, kb := kindRank(a.Kind), kindRank(b.Kind); ka != kb {
			return ka < kb
		}
		return a.CreatedAt.Before(b.CreatedAt)
	}
	for i := range alerts {
		a := &alerts[i]
		if a.Status == store.StatusResolved {
			continue
		}
		if best == nil || better(a, best) {
			best = a
		}
	}
	return best
}

// kindRank orders alerts of the same severity by what usually needs eyes first: a silent sensor,
// then code planted in the web applications, then the rest.
func kindRank(kind string) int {
	switch kind {
	case "silence":
		return 0
	case "web":
		return 1
	}
	return 2
}
