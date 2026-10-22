// Package analyze turns snapshots into alerts: conditions that are dangerous in themselves, and
// changes from the host's previous snapshot.
package analyze

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/apps"
	"github.com/cpibia/tripwatch/internal/collector/logs"
	"github.com/cpibia/tripwatch/internal/collector/system"
	"github.com/cpibia/tripwatch/internal/collector/web"
	"github.com/cpibia/tripwatch/internal/discovery"
	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// Limits on a decompressed snapshot, which comes from a host that may be compromised. Real
// snapshots are a few hundred KB with tens of thousands of values; the decoded structure weighs
// several times the text, so both the size and the number of values are bounded before
// decoding, and so is the nesting.
const (
	maxSnapshotSize   = 32 << 20
	maxSnapshotValues = 500_000
	maxSnapshotDepth  = 32
)

// maxFindings bounds the alerts one snapshot can raise.
const maxFindings = 200

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

// Report is what the sensor sends: the environment and the snapshot of every collector.
type Report struct {
	Environment discovery.Environment `json:"environment"`
	Snapshot    collector.Snapshot    `json:"snapshot"`
}

// State is a snapshot decoded into the collectors' result types. A collector missing from the
// snapshot (failed, disabled) leaves its field nil, and rules on it do not run.
type State struct {
	TakenAt    time.Time
	Errors     map[string]string
	Warnings   []string
	Accounts   *system.AccountsResult
	SSH        *system.SSHResult
	Sudoers    *system.SudoersResult
	Scheduled  *system.ScheduledResult
	Services   *system.ServicesResult
	Hooks      *system.HooksResult
	Processes  *system.ProcessesResult
	Sockets    *system.SocketsResult
	Packages   *system.PackagesResult
	Privileged *system.PrivilegedResult
	Web        *web.Result
	Weblog     *logs.Result
	Apps       *apps.Result
}

// Decode reads a payload as sent by the sensor: gzip-compressed JSON.
func Decode(payload []byte) (State, error) {
	zr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return State{}, fmt.Errorf("snapshot not compressed: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(zr, maxSnapshotSize+1))
	if err != nil {
		return State{}, err
	}
	if len(data) > maxSnapshotSize {
		return State{}, errors.New("snapshot too large")
	}
	if err := checkShape(data); err != nil {
		return State{}, err
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return State{}, err
	}

	st := State{TakenAt: r.Snapshot.TakenAt, Errors: r.Snapshot.Errors, Warnings: r.Snapshot.Warnings}
	targets := map[string]any{
		"accounts": &st.Accounts, "ssh": &st.SSH, "sudoers": &st.Sudoers, "scheduled": &st.Scheduled,
		"services": &st.Services, "hooks": &st.Hooks, "processes": &st.Processes, "sockets": &st.Sockets,
		"packages": &st.Packages, "privileged": &st.Privileged, "web": &st.Web, "weblog": &st.Weblog, "apps": &st.Apps,
	}
	for name, raw := range r.Snapshot.Results {
		target, ok := targets[name]
		if !ok {
			continue
		}
		if err := json.Unmarshal(raw, target); err != nil {
			if st.Errors == nil {
				st.Errors = map[string]string{}
			}
			st.Errors[name] = "undecodable result: " + err.Error()
		}
	}
	return st, nil
}

// checkShape walks the JSON tokens without building anything and refuses documents with too
// many values or too deep a nesting.
func checkShape(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	values, depth := 0, 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("malformed snapshot: %w", err)
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if depth++; depth > maxSnapshotDepth {
					return errors.New("snapshot nested too deeply")
				}
			default:
				depth--
			}
		}
		if values++; values > maxSnapshotValues {
			return errors.New("snapshot has too many values")
		}
	}
}

// Analyzer raises the alerts of a host's newest snapshot.
type Analyzer struct {
	Store *store.Store
	Now   func() time.Time
	Log   *slog.Logger
}

// Worker analyses pending snapshots, oldest first, until ctx ends. wake signals new ones; a
// periodic pass also picks up what was stored before a restart.
func (a *Analyzer) Worker(ctx context.Context, wake <-chan struct{}) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		ids, err := a.Store.PendingSnapshots(ctx, 100)
		if err != nil && ctx.Err() == nil {
			a.Log.Error("load pending snapshots", "err", err)
		}
		for _, id := range ids {
			if ctx.Err() != nil {
				return
			}
			a.RunSnapshot(ctx, id)
			if err := a.Store.MarkAnalyzed(ctx, id); err != nil {
				a.Log.Error("mark analysed", "snapshot", id, "err", err)
			}
		}
		if len(ids) == 100 {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-tick.C:
		}
	}
}

// RunSnapshot raises the alerts of one snapshot against the one before it. Each snapshot is
// analysed on its own, so a hostile one only costs its own host.
func (a *Analyzer) RunSnapshot(ctx context.Context, id int64) {
	cur, prevSnap, err := a.Store.SnapshotPair(ctx, id)
	if err != nil {
		a.Log.Error("load snapshot", "snapshot", id, "err", err)
		return
	}
	host := cur.HostID
	state, err := Decode(cur.Payload)
	if err != nil {
		a.raise(ctx, store.Alert{HostID: host, Fingerprint: "snapshot:undecodable", Severity: "high", Kind: "sensor",
			Title: "Snapshot rifiutato", Detail: err.Error() + ". Un sensore integro non produce snapshot così: il server può essere compromesso."})
		return
	}
	var prev *State
	if prevSnap != nil {
		if p, err := Decode(prevSnap.Payload); err == nil {
			prev = &p
		}
	}

	findings := Evaluate(prev, state)
	current := map[string][]string{}
	for _, f := range findings {
		if f.State {
			current[f.Kind] = append(current[f.Kind], f.Fingerprint)
		}
	}
	// A snapshot raises at most maxFindings alerts, the most severe first; the rest are
	// summarised in one, so a hostile snapshot cannot flood the table and the mailbox.
	if len(findings) > maxFindings {
		slices.SortStableFunc(findings, func(x, y Finding) int { return severityRank(x.Severity) - severityRank(y.Severity) })
		dropped := len(findings) - maxFindings
		findings = append(findings[:maxFindings], Finding{Kind: "sensor", Fingerprint: "snapshot:too-many-findings", Severity: "high",
			Title:  "Troppe anomalie in un solo snapshot",
			Detail: fmt.Sprintf("Lo snapshot ne contiene %d: registrate le %d più gravi, le altre %d no. Un cambiamento così esteso va esaminato sul server.", maxFindings+dropped, maxFindings, dropped)})
	}
	var evidenceOf []string
	for _, f := range findings {
		// Evidence is the snapshot where an alert starts (or comes back), not every later one
		// that shows it again: a repeated log request would otherwise keep every snapshot.
		if a.raise(ctx, store.Alert{HostID: host, Fingerprint: f.Fingerprint, Severity: f.Severity, Kind: f.Kind, Title: f.Title, Detail: f.Detail}) {
			evidenceOf = append(evidenceOf, f.Fingerprint)
		}
	}

	// A snapshot that raises a new alert is evidence, and so is the one before it, which shows the
	// host as it was: both are kept beyond the thinning.
	// One proof a day per alert: an alert made to reopen at every snapshot (two files swapped
	// back and forth) would otherwise keep them all.
	var alertIDs []int64
	day := a.Now().Truncate(24 * time.Hour)
	for _, fp := range evidenceOf {
		alertID, err := a.Store.AlertID(ctx, host, fp)
		if err != nil {
			continue
		}
		if seen, err := a.Store.HasEvidenceSince(ctx, alertID, day); err == nil && !seen {
			alertIDs = append(alertIDs, alertID)
		}
	}
	if len(alertIDs) > 0 {
		keep := []int64{id}
		if prevSnap != nil {
			keep = append(keep, prevSnap.ID)
		}
		// Linked to every alert it shows, the snapshot outlives the retention while any of them
		// stays open.
		for _, k := range keep {
			if err := a.Store.Keep(ctx, k, alertIDs...); err != nil {
				a.Log.Error("keep snapshot", "snapshot", k, "err", err)
			}
		}
	}
	for _, kind := range StateKinds {
		if err := a.Store.ResolveMissing(ctx, host, kind, current[kind], a.Now()); err != nil {
			a.Log.Error("resolve alerts", "host", host, "kind", kind, "err", err)
		}
	}
}

// raise records an alert and reports whether it is new or reopened.
func (a *Analyzer) raise(ctx context.Context, al store.Alert) bool {
	fresh, err := a.Store.Raise(ctx, al, a.Now())
	if err != nil {
		a.Log.Error("raise alert", "host", al.HostID, "err", err)
	}
	return fresh
}

// Silent raises an alert for every enrolled host whose last heartbeat is older than limit, or
// whose snapshots stopped while heartbeats still arrive (a sensor tampered with to send only
// "I am alive"), and resolves them once the host reports again.
func (a *Analyzer) Silent(ctx context.Context, limit, snapshotLimit time.Duration) {
	hosts, err := a.Store.Hosts(ctx)
	if err != nil {
		a.Log.Error("list hosts", "err", err)
		return
	}
	now := a.Now()
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		var current []string
		last := h.LastHeartbeat
		if last.IsZero() {
			last = h.EnrolledAt
		}
		if now.Sub(last) > limit {
			fp := "sensor:silent"
			current = append(current, fp)
			a.raise(ctx, store.Alert{HostID: h.ID, Fingerprint: fp, Severity: "critical", Kind: "silence",
				Title:  "Il sensore non risponde",
				Detail: fmt.Sprintf("Nessun battito da %s (ultimo: %s). Il sensore è fermo, il server è irraggiungibile, oppure qualcuno lo ha spento.", span(now.Sub(last)), formatTime(last))})
		}
		lastSnap := h.LastSnapshot
		if lastSnap.IsZero() {
			lastSnap = h.EnrolledAt
		}
		if now.Sub(last) <= limit && now.Sub(lastSnap) > snapshotLimit {
			fp := "sensor:no-snapshots"
			current = append(current, fp)
			a.raise(ctx, store.Alert{HostID: h.ID, Fingerprint: fp, Severity: "high", Kind: "silence",
				Title:  "Il sensore risponde ma non invia snapshot",
				Detail: fmt.Sprintf("Battiti regolari, ma nessuno snapshot da %s (ultimo: %s). La raccolta è bloccata, oppure il sensore è stato manomesso per mandare solo segnali di vita.", span(now.Sub(lastSnap)), formatTime(lastSnap))})
		}
		if err := a.Store.ResolveGone(ctx, h.ID, "silence", current, now); err != nil {
			a.Log.Error("resolve silence", "host", h.ID, "err", err)
		}
	}
}

// span writes a duration for the alert text, in minutes, hours or days.
func span(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h %d min", int(d/time.Hour), int(d%time.Hour/time.Minute))
	}
	return fmt.Sprintf("%d giorni", int(d/(24*time.Hour)))
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "mai"
	}
	return t.Format("2006-01-02 15:04 MST")
}
