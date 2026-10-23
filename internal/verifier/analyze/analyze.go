// Package analyze turns snapshots into alerts: conditions that are dangerous in themselves, and
// changes from the host's previous snapshot.
package analyze

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"strings"
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

// maxEvidencePerDay bounds the snapshots a host keeps as evidence each day for one kind of
// alert: one an hour on average, while the daily thinning keeps the last of each day anyway.
const maxEvidencePerDay = 24

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

// maxBaseWalk bounds how many earlier snapshots are read to find a collector's last result.
const maxBaseWalk = 50

// base is what a snapshot is compared with: for each collector, its result in the last
// snapshot where it succeeded. A collector made to fail once would otherwise let a change made
// in that window become the reference with no alert.
// It also names the collectors cur has that no snapshot within maxBaseWalk has: their changes
// cannot be compared.
func (a *Analyzer) base(ctx context.Context, cur State, prevSnap *store.Snapshot) (*State, []string) {
	var out *State
	walked := 0
	for ; prevSnap != nil && walked < maxBaseWalk; walked++ {
		if p, err := Decode(prevSnap.Payload); err == nil {
			if out == nil {
				out = &p
			} else {
				fillMissing(out, p)
			}
		}
		if out != nil && !missing(*out, cur) {
			break
		}
		older, err := a.Store.SnapshotBefore(ctx, prevSnap.HostID, prevSnap.ID)
		if err != nil {
			break
		}
		prevSnap = &older
	}
	if out == nil || walked < maxBaseWalk {
		return out, nil
	}
	var lost []string
	b, c := collectorResults(out), collectorResults(&cur)
	names := reflect.TypeFor[State]()
	for i, j := 0, 0; i < names.NumField(); i++ {
		if names.Field(i).Type.Kind() != reflect.Pointer {
			continue
		}
		if b[j].IsNil() && !c[j].IsNil() {
			lost = append(lost, strings.ToLower(names.Field(i).Name))
		}
		j++
	}
	return out, lost
}

// failingSnapshots is how many snapshots in a row a collector may fail before it is an alert
// that stays open: a collector kept failing is a part of the host nobody compares.
const failingSnapshots = 3

// persistentErrors returns the collectors that failed in cur and in the snapshots just before it.
func (a *Analyzer) persistentErrors(ctx context.Context, cur State, prevSnap *store.Snapshot) map[string]string {
	failing := maps.Clone(cur.Errors)
	for range failingSnapshots - 1 {
		if len(failing) == 0 || prevSnap == nil {
			return nil
		}
		p, err := Decode(prevSnap.Payload)
		if err != nil {
			return nil
		}
		for name := range failing {
			if _, ok := p.Errors[name]; !ok {
				delete(failing, name)
			}
		}
		older, err := a.Store.SnapshotBefore(ctx, prevSnap.HostID, prevSnap.ID)
		if err != nil {
			prevSnap = nil
		} else {
			prevSnap = &older
		}
	}
	return failing
}

// collectorResults are the State fields holding a collector's result.
func collectorResults(s *State) []reflect.Value {
	v := reflect.ValueOf(s).Elem()
	var out []reflect.Value
	for i := range v.NumField() {
		if v.Field(i).Kind() == reflect.Pointer {
			out = append(out, v.Field(i))
		}
	}
	return out
}

// missing reports whether base lacks a result that cur has.
func missing(base, cur State) bool {
	b, c := collectorResults(&base), collectorResults(&cur)
	for i := range b {
		if b[i].IsNil() && !c[i].IsNil() {
			return true
		}
	}
	return false
}

// fillMissing copies into base the results it lacks from an older snapshot.
func fillMissing(base *State, older State) {
	b, o := collectorResults(base), collectorResults(&older)
	for i := range b {
		if b[i].IsNil() {
			b[i].Set(o[i])
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
			Title: "Snapshot refused", Detail: err.Error() + ". A sound sensor does not produce snapshots like this: the server may be compromised."})
		return
	}
	prev, lost := a.base(ctx, state, prevSnap)

	findings := Evaluate(prev, state)
	for _, name := range lost {
		findings = append(findings, Finding{Kind: "sensor", Fingerprint: "sensor:baseline-lost:" + name, Severity: "high",
			Title:  "Collector " + name + " has nothing to compare with",
			Detail: fmt.Sprintf("None of the %d previous snapshots holds the result of %s: changes made while it did not answer are not reported. Check the server directly.", maxBaseWalk, name)})
	}
	for name, msg := range a.persistentErrors(ctx, state, prevSnap) {
		findings = append(findings, Finding{Kind: "sensor", Fingerprint: "sensor:error-persistent:" + name, Severity: "high", State: true,
			Title:  fmt.Sprintf("Collector %s did not complete for %d snapshots in a row", name, failingSnapshots),
			Detail: msg + "\nUntil it answers, changes to what it reads are not compared. The alert stays open after it recovers."})
	}
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
			Title:  "Too many findings in one snapshot",
			Detail: fmt.Sprintf("The snapshot holds %d: the %d most severe were recorded, the other %d were not. A change this wide must be examined on the server.", maxFindings+dropped, maxFindings, dropped)})
	}
	var evidenceOf []Finding
	for _, f := range findings {
		// Evidence is the snapshot where an alert starts (or comes back), not every later one
		// that shows it again: a repeated log request would otherwise keep every snapshot.
		if a.raise(ctx, store.Alert{HostID: host, Fingerprint: f.Fingerprint, Severity: f.Severity, Kind: f.Kind, Title: f.Title, Detail: f.Detail}) {
			evidenceOf = append(evidenceOf, f)
		}
		if f.Diff != nil {
			a.keepDiff(ctx, host, f)
		}
	}

	// A snapshot that raises a new alert is evidence, and so is the one before it, which shows the
	// host as it was: both are kept beyond the thinning. One proof a day per alert and content,
	// so an alert made to reopen at every snapshot keeps one, while a decoy raised early in the
	// day does not take the place of different content raised later; and at most
	// maxEvidencePerDay a day per host and kind of alert, whatever the number of files swapped
	// back and forth.
	var links []store.Evidence
	day := a.Now().Truncate(24 * time.Hour)
	kept, err := a.Store.EvidenceSnapshotsSince(ctx, host, day)
	if err != nil {
		a.Log.Error("count evidence", "host", host, "err", err)
		kept = map[string]int{}
	}
	for _, f := range evidenceOf {
		// The daily bound is per kind and severity of alert, so noise of one kind (files in the
		// uploads) cannot use up another's, and medium noise cannot use up the critical budget. What only root can cause is always kept; web and log
		// alerts, critical ones included, and other users' keys, crontabs and setuid files
		// can be produced without root and stay bounded.
		if !f.owned() && kept[f.Kind+"|"+f.Severity] >= maxEvidencePerDay {
			continue
		}
		alertID, err := a.Store.AlertID(ctx, host, f.Fingerprint)
		if err != nil {
			continue
		}
		sum := sha256.Sum256([]byte(f.Severity + "\x00" + f.Detail))
		digest := hex.EncodeToString(sum[:8])
		if seen, err := a.Store.HasEvidenceSince(ctx, alertID, digest, day); err == nil && !seen {
			links = append(links, store.Evidence{AlertID: alertID, Digest: digest})
		}
	}
	if len(links) > 0 {
		keep := []int64{id}
		if prevSnap != nil {
			keep = append(keep, prevSnap.ID)
		}
		// Linked to every alert it shows, the snapshot outlives the retention while any of them
		// stays open.
		for _, k := range keep {
			if err := a.Store.Keep(ctx, k, links...); err != nil {
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
// maxStoredDiff bounds the complete diff kept with a policy alert.
const maxStoredDiff = 256 << 10

// keepDiff stores the complete diff of a policy alert, computed once here: rebuilding it later
// from snapshots would depend on which of them retention kept.
func (a *Analyzer) keepDiff(ctx context.Context, host string, f Finding) {
	id, err := a.Store.AlertID(ctx, host, f.Fingerprint)
	if err != nil {
		a.Log.Error("alert diff", "host", host, "err", err)
		return
	}
	var b strings.Builder
	for i, l := range f.Diff {
		if b.Len()+len(l) > maxStoredDiff {
			fmt.Fprintf(&b, "(%d more lines beyond %d KB not kept)\n", len(f.Diff)-i, maxStoredDiff>>10)
			break
		}
		b.WriteString(l + "\n")
	}
	if err := a.Store.SetAlertDiff(ctx, id, strings.TrimSuffix(b.String(), "\n"), a.Now()); err != nil {
		a.Log.Error("alert diff", "host", host, "err", err)
	}
}

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
				Title:  "The sensor is silent",
				Detail: fmt.Sprintf("No heartbeat for %s (last: %s). The sensor is stopped, the server is unreachable, or someone turned it off.", span(now.Sub(last)), formatTime(last))})
		}
		lastSnap := h.LastSnapshot
		if lastSnap.IsZero() {
			lastSnap = h.EnrolledAt
		}
		if now.Sub(last) <= limit && now.Sub(lastSnap) > snapshotLimit {
			fp := "sensor:no-snapshots"
			current = append(current, fp)
			a.raise(ctx, store.Alert{HostID: h.ID, Fingerprint: fp, Severity: "high", Kind: "silence",
				Title:  "The sensor answers but sends no snapshots",
				Detail: fmt.Sprintf("Regular heartbeats, but no snapshot for %s (last: %s). Collection is stuck, or the sensor was tampered with to send only signs of life.", span(now.Sub(lastSnap)), formatTime(lastSnap))})
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
	return fmt.Sprintf("%d days", int(d/(24*time.Hour)))
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format("2006-01-02 15:04 MST")
}
