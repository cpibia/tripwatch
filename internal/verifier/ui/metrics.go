package ui

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// metrics serves the verifier's state in Prometheus' text format, to a bearer token like the
// API: a token limited to some servers counts only theirs. The queue, the database and the
// envelopes are the verifier's own and hold nothing of any server.
func (s *server) metrics(w http.ResponseWriter, r *http.Request, _ apiCaller) {
	ctx := r.Context()
	var b strings.Builder
	metric := func(name, kind, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
	}
	fail := func(err error) {
		s.Log.Error("metrics", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}

	hosts, err := s.Store.Hosts(ctx)
	if err != nil {
		fail(err)
		return
	}
	states := map[string]int{"reporting": 0, "silent": 0, "waiting": 0, "revoked": 0}
	now := s.Now()
	for _, h := range hosts {
		switch {
		case h.Revoked:
			states["revoked"]++
		case h.LastHeartbeat.IsZero() && now.Sub(h.EnrolledAt) <= s.SilenceAfter:
			states["waiting"]++
		case h.LastHeartbeat.IsZero() || now.Sub(h.LastHeartbeat) > s.SilenceAfter:
			states["silent"]++
		default:
			states["reporting"]++
		}
	}
	metric("tripwatch_hosts", "gauge", "Servers by state: reporting, silent past the silence threshold, waiting for a first heartbeat, revoked.")
	for _, st := range []string{"reporting", "silent", "waiting", "revoked"} {
		fmt.Fprintf(&b, "tripwatch_hosts{state=%q} %d\n", st, states[st])
	}

	metric("tripwatch_alerts", "gauge", "Alerts not resolved, by status and severity.")
	for _, status := range []string{store.StatusOpen, store.StatusAcked} {
		for _, sev := range allSeverities {
			n, err := s.Store.CountAlerts(ctx, store.AlertFilter{Statuses: []string{status}, Severities: []string{sev}, Current: true})
			if err != nil {
				fail(err)
				return
			}
			fmt.Fprintf(&b, "tripwatch_alerts{status=%q,severity=%q} %d\n", status, sev, n)
		}
	}

	backlog, err := s.Store.AnalysisBacklog(ctx)
	if err != nil {
		fail(err)
		return
	}
	metric("tripwatch_analysis_pending", "gauge", "Snapshots stored and waiting to be analysed.")
	fmt.Fprintf(&b, "tripwatch_analysis_pending %d\n", backlog.Pending)
	metric("tripwatch_analysis_oldest_seconds", "gauge", "How long the oldest snapshot waiting to be analysed has waited.")
	wait := 0.0
	if !backlog.Oldest.IsZero() {
		wait = max(now.Sub(backlog.Oldest).Seconds(), 0)
	}
	fmt.Fprintf(&b, "tripwatch_analysis_oldest_seconds %s\n", strconv.FormatFloat(wait, 'f', 0, 64))

	size, err := s.Store.Size(ctx)
	if err != nil {
		fail(err)
		return
	}
	metric("tripwatch_database_bytes", "gauge", "Bytes the database takes on disk.")
	fmt.Fprintf(&b, "tripwatch_database_bytes %d\n", size)

	if s.Envelopes != nil {
		metric("tripwatch_envelopes_total", "counter", "Requests of the sensors since the verifier started, by kind and HTTP answer.")
		for _, c := range s.Envelopes() {
			code := strconv.Itoa(c.Status)
			if c.Status == 0 {
				code = "none"
			}
			fmt.Fprintf(&b, "tripwatch_envelopes_total{kind=%q,code=%q} %d\n", c.Kind, code, c.N)
		}
	}
	metric("tripwatch_build_info", "gauge", "The verifier's release.")
	fmt.Fprintf(&b, "tripwatch_build_info{version=%q} 1\n", s.release())

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(b.String()))
}
