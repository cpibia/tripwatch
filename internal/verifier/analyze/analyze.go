// Package analyze turns snapshots into alerts: conditions that are dangerous in themselves, and
// changes from the host's previous snapshot.
package analyze

import (
	"bytes"
	"cmp"
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
	"github.com/cpibia/tripwatch/internal/verifier/refs"
	"github.com/cpibia/tripwatch/internal/verifier/store"
	"github.com/cpibia/tripwatch/internal/watch"
)

// Limits on a decompressed snapshot, which comes from a host that may be compromised. Real
// snapshots are a few hundred KB with tens of thousands of values; the decoded structure weighs
// several times the text, so both the size and the number of values are bounded before
// decoding, and so is the nesting. The values are bounded per collector result too: what an
// unprivileged user can inflate (files in a home, processes) then costs that result alone,
// named in the snapshot's errors, and never the whole snapshot.
const (
	maxSnapshotSize   = 32 << 20
	maxSnapshotValues = 4_000_000
	maxSnapshotDepth  = 32
	maxResultValues   = 500_000
	maxDecodedValues  = 1_000_000
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
	Realtime    *watch.Status         `json:"realtime,omitempty"`
}

// State is a snapshot decoded into the collectors' result types. A collector missing from the
// snapshot (failed, disabled) leaves its field nil, and rules on it do not run.
type State struct {
	TakenAt     time.Time
	Environment discovery.Environment
	Errors      map[string]string
	Warnings    []string
	Accounts    *system.AccountsResult
	SSH         *system.SSHResult
	Sudoers     *system.SudoersResult
	Scheduled   *system.ScheduledResult
	Services    *system.ServicesResult
	Hooks       *system.HooksResult
	Processes   *system.ProcessesResult
	Sockets     *system.SocketsResult
	Packages    *system.PackagesResult
	Privileged  *system.PrivilegedResult
	Web         *web.Result
	Weblog      *logs.Result
	Apps        *apps.Result
	Kernel      *system.KernelResult
	Containers  *system.ContainersResult
	// Realtime is nil for sensors that predate the real-time watchers.
	Realtime *watch.Status
	// Issues are what each collector said it could not do, by collector, at most
	// maxCollectorIssues of them each; IssueCounts counts them all.
	Issues      map[string][]string
	IssueCounts map[string]int
	// Published judges the changed files of packages whose public release is known, by path; it
	// is filled by the analyzer from content references, never by the sensor.
	Published map[string]Published
	// KnownReleases are the releases the verifier remembers for the host, by package root,
	// whatever snapshot named them last; empty for a host it has none for yet.
	KnownReleases map[string]store.HostRelease
}

// Published is what a changed file of a package is next to its public release: Release names the
// release, Matches says its SHA-256 is one the release lists for its path, Listed that the
// release has a file at that path at all.
type Published struct {
	Release         string
	Matches, Listed bool
}

// maxCollectorIssues bounds the issues kept of one collector.
const maxCollectorIssues = 20

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
	if _, err := checkShape(data, maxSnapshotValues); err != nil {
		return State{}, err
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return State{}, err
	}

	st := State{TakenAt: r.Snapshot.TakenAt, Environment: r.Environment, Errors: r.Snapshot.Errors, Warnings: r.Snapshot.Warnings, Realtime: r.Realtime}
	targets := map[string]any{
		"accounts": &st.Accounts, "ssh": &st.SSH, "sudoers": &st.Sudoers, "scheduled": &st.Scheduled,
		"services": &st.Services, "hooks": &st.Hooks, "processes": &st.Processes, "sockets": &st.Sockets,
		"packages": &st.Packages, "privileged": &st.Privileged, "web": &st.Web, "weblog": &st.Weblog, "apps": &st.Apps, "kernel": &st.Kernel,
		"containers": &st.Containers,
	}
	fail := func(name, msg string) {
		if st.Errors == nil {
			st.Errors = map[string]string{}
		}
		st.Errors[name] = msg
	}
	type sized struct {
		name   string
		values int
	}
	var results []sized
	for name, raw := range r.Snapshot.Results {
		if _, ok := targets[name]; !ok {
			continue
		}
		n, err := checkShape(raw, maxResultValues)
		if err != nil {
			fail(name, "result refused: "+err.Error())
			continue
		}
		results = append(results, sized{name, n})
	}
	// The smallest first: a result inflated to take the decoding budget is the one left out.
	slices.SortFunc(results, func(a, b sized) int { return a.values - b.values })
	decoded := 0
	for _, res := range results {
		if decoded += res.values; decoded > maxDecodedValues {
			fail(res.name, fmt.Sprintf("result refused: %d values, past what the snapshot's results may hold together", res.values))
			continue
		}
		if err := json.Unmarshal(r.Snapshot.Results[res.name], targets[res.name]); err != nil {
			fail(res.name, "undecodable result: "+err.Error())
			continue
		}
		var withIssues struct{ Issues []string }
		if json.Unmarshal(r.Snapshot.Results[res.name], &withIssues) == nil && len(withIssues.Issues) > 0 {
			if st.Issues == nil {
				st.Issues, st.IssueCounts = map[string][]string{}, map[string]int{}
			}
			// The most serious work left undone first, so that a flood of minor issues cannot push
			// a skimmer search left unfinished out of the twenty kept.
			slices.SortStableFunc(withIssues.Issues, func(a, b string) int { return cmp.Compare(issueOrder(a), issueOrder(b)) })
			st.Issues[res.name] = withIssues.Issues[:min(len(withIssues.Issues), maxCollectorIssues)]
			st.IssueCounts[res.name] = len(withIssues.Issues)
		}
	}
	CleanHostText(&st)
	return st, nil
}

// checkShape walks the JSON tokens without building anything, refuses documents with more than
// limit values or too deep a nesting, and returns how many values it found.
func checkShape(data []byte, limit int) (int, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	values, depth := 0, 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return values, nil
		}
		if err != nil {
			return values, fmt.Errorf("malformed snapshot: %w", err)
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if depth++; depth > maxSnapshotDepth {
					return values, errors.New("snapshot nested too deeply")
				}
			default:
				depth--
			}
		}
		if values++; values > limit {
			return values, fmt.Errorf("more than %d values", limit)
		}
	}
}

// Analyzer raises the alerts of a host's newest snapshot.
type Analyzer struct {
	Store *store.Store
	Now   func() time.Time
	Log   *slog.Logger
	// Refs gives the published content of public components; nil leaves changes unjudged
	// against their releases.
	Refs *refs.Resolver
}

// Worker analyses pending snapshots, oldest first, until ctx ends. wake signals new ones; a
// periodic pass also picks up what was stored before a restart.
func (a *Analyzer) Worker(ctx context.Context, wake <-chan struct{}) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		// One pass of the queue is one round of the references' fetches.
		if a.Refs != nil {
			a.Refs.NewRound()
		}
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
func sensorVersion(s State) string {
	if s.Environment.System == nil {
		return ""
	}
	return s.Environment.System.SensorVersion
}

func (a *Analyzer) base(ctx context.Context, cur State, prevSnap *store.Snapshot) (*State, []string) {
	var out *State
	walked := 0
	// A collector a newer sensor brings has nothing to compare with in snapshots of the older
	// one: that is not a loss.
	upgraded := false
	for ; prevSnap != nil && walked < maxBaseWalk; walked++ {
		if p, err := Decode(prevSnap.Payload); err == nil {
			upgraded = upgraded || sensorVersion(p) != sensorVersion(cur)
			if out == nil {
				out = &p
			} else {
				fillMissing(out, p)
				fillObjects(out, p)
			}
		}
		if out != nil && !missing(*out, cur) && !missingObjects(*out, cur) {
			break
		}
		older, err := a.Store.SnapshotBefore(ctx, prevSnap.HostID, prevSnap.ID)
		if err != nil {
			break
		}
		prevSnap = &older
	}
	if out == nil || walked < maxBaseWalk || upgraded {
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
	maps.DeleteFunc(failing, func(_, msg string) bool { return stoppedMidway(msg) })
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

// missingObjects reports whether an application of cur read a kind of database objects that the
// same application in base did not: a query that failed or timed out, as a table locked by
// whoever is adding a row to it can make it. Comparing that kind with the last snapshot that
// read it keeps such a row from becoming part of the baseline unseen.
func missingObjects(base, cur State) bool {
	if base.Apps == nil || cur.Apps == nil {
		return false
	}
	for _, app := range cur.Apps.Apps {
		i := slices.IndexFunc(base.Apps.Apps, func(b apps.Profile) bool { return b.Path == app.Path })
		if i >= 0 && slices.ContainsFunc(app.ObjectsRead, func(k string) bool { return !slices.Contains(base.Apps.Apps[i].ObjectsRead, k) }) {
			return true
		}
	}
	return false
}

// fillObjects copies into base, for each application, the database objects of the kinds it did
// not read and an older snapshot did.
func fillObjects(base *State, older State) {
	if base.Apps == nil || older.Apps == nil {
		return
	}
	for i := range base.Apps.Apps {
		b := &base.Apps.Apps[i]
		j := slices.IndexFunc(older.Apps.Apps, func(o apps.Profile) bool { return o.Path == b.Path })
		if j < 0 {
			continue
		}
		o := older.Apps.Apps[j]
		for _, kind := range o.ObjectsRead {
			if slices.Contains(b.ObjectsRead, kind) {
				continue
			}
			b.ObjectsRead = append(b.ObjectsRead, kind)
			for _, obj := range o.Objects {
				if obj.Kind == kind {
					b.Objects = append(b.Objects, obj)
				}
			}
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
	if err := a.Store.SetFacts(ctx, host, Facts(state)); err != nil {
		a.Log.Error("keep host facts", "host", host, "err", err)
	}
	prev, lost := a.base(ctx, state, prevSnap)

	since := a.Now().Add(-a.Store.Retention().Events)
	if prev != nil && prev.TakenAt.After(since) {
		since = prev.TakenAt
	}
	state.Published = a.published(ctx, host, state)
	known, err := a.Store.HostReleases(ctx, host)
	if err != nil {
		a.Log.Error("load host releases", "host", host, "err", err)
	}
	state.KnownReleases = known
	findings := a.dropReported(ctx, host, since, Evaluate(prev, state))
	if state.Web != nil {
		var seen []store.HostRelease
		for _, app := range state.Web.Apps {
			for _, r := range app.Releases {
				seen = append(seen, store.HostRelease{Root: r.Root, Ecosystem: r.Ecosystem, Slug: r.Slug, Version: r.Version})
			}
		}
		if err := a.Store.SetHostReleases(ctx, host, seen, a.Now()); err != nil {
			a.Log.Error("keep host releases", "host", host, "err", err)
		}
	}
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

// published compares the changed files of each package with a public release to that release as
// published, when references are on and the release's reference can be had within the bounds.
func (a *Analyzer) published(ctx context.Context, host string, st State) map[string]Published {
	if a.Refs == nil || st.Web == nil {
		return nil
	}
	var out map[string]Published
	for _, app := range st.Web.Apps {
		for _, rel := range app.Releases {
			ref, ok := a.Refs.Lookup(ctx, host, refs.Key{Ecosystem: rel.Ecosystem, Slug: rel.Slug, Version: rel.Version})
			if !ok {
				continue
			}
			name := rel.Slug + " " + rel.Version
			if rel.Ecosystem == web.EcosystemWordPressCore {
				name = "WordPress " + rel.Version + " (" + rel.Slug + ")"
			}
			for _, c := range app.Changes {
				p, inside := strings.CutPrefix(c.Path, rel.Root+"/")
				// The core's wp-content holds the plugins and themes, judged by their own releases.
				if !inside || c.Change == web.ChangeRemoved || rel.Ecosystem == web.EcosystemWordPressCore && strings.HasPrefix(p, "wp-content/") {
					continue
				}
				if out == nil {
					out = map[string]Published{}
				}
				sums := ref.Files[p]
				out[c.Path] = Published{Release: name, Listed: len(sums) > 0,
					Matches: c.SHA256 != "" && slices.Contains(sums, c.SHA256)}
			}
		}
	}
	return out
}

// maxReportedChecks bounds the event lookups of one snapshot: past it, findings are kept, and
// the bound on findings per snapshot does the rest.
const maxReportedChecks = 64

// dropReported removes the findings about file content a real-time event reported since the
// previous snapshot: the event raised its own alert when it happened. An older event with the
// same content says nothing of this change.
func (a *Analyzer) dropReported(ctx context.Context, host string, since time.Time, findings []Finding) []Finding {
	checks := 0
	return slices.DeleteFunc(findings, func(f Finding) bool {
		if f.Path == "" || f.SHA256 == "" || checks == maxReportedChecks {
			return false
		}
		checks++
		events, err := a.Store.PathEvents(ctx, host, f.Path, since)
		if err != nil {
			return false
		}
		return slices.ContainsFunc(events, func(e store.Event) bool {
			var data struct {
				SHA256 string `json:"sha256"`
			}
			return json.Unmarshal(e.Data, &data) == nil && data.SHA256 == f.SHA256
		})
	})
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

// cleanStopGrace is how long a silence after a clean stop stays medium.
const cleanStopGrace = 24 * time.Hour

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
			al := store.Alert{HostID: h.ID, Fingerprint: fp, Severity: "critical", Kind: "silence",
				Title:  "The sensor is silent",
				Detail: fmt.Sprintf("No heartbeat for %s (last: %s). The sensor is stopped, the server is unreachable, or someone turned it off.", span(now.Sub(last)), formatTime(last))}
			// A sensor that signed, after its last heartbeat, that it stopped because systemd was
			// shutting the system down went away with the server. That silence is medium for a
			// day, the length of a server switched off at night; a stop on a running system stays
			// critical, since root can stop the sensor and work before rebooting.
			if run, err := a.Store.Run(ctx, h.ID); err == nil && run.Shutdown && !run.StoppedAt.IsZero() && !run.StoppedAt.Before(last.Add(-2*time.Minute)) {
				al.Severity, al.Title = "medium", "The server was shut down"
				al.Detail = fmt.Sprintf("The sensor reported at %s that it was stopping while the system was shutting down, and has been silent for %s since: the server is off. Past a day this becomes high.", formatTime(run.StoppedAt), span(now.Sub(run.StoppedAt)))
				if now.Sub(run.StoppedAt) > cleanStopGrace {
					al.Severity = "high"
				}
			}
			a.raise(ctx, al)
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

// maxAppFacts bounds the applications listed among a host's facts, maxRealtimeIssues the
// problems of its real-time watchers.
const (
	maxAppFacts       = 50
	maxAppSites       = 8
	maxRealtimeIssues = 5
)

// Facts sums up a snapshot for the fleet page: the sensor's system block, the environment, and
// what the collectors counted.
func Facts(st State) store.HostFacts {
	f := store.HostFacts{SeenAt: st.TakenAt, Environment: string(st.Environment.Kind), ContainerRuntimes: st.Environment.ContainerRuntimes}
	if sys := st.Environment.System; sys != nil {
		f.OS, f.OSID, f.OSVersion, f.Kernel, f.Arch, f.Hostname = sys.OS, sys.OSID, sys.OSVersion, sys.Kernel, sys.Arch, sys.Hostname
		f.BootedAt, f.CPUs, f.MemoryBytes, f.Addresses, f.SensorVersion = sys.BootedAt, sys.CPUs, sys.MemoryBytes, sys.Addresses, sys.SensorVersion
	}
	if rt := st.Realtime; rt != nil {
		f.Realtime = &store.RealtimeFact{Files: rt.Files, Processes: rt.Processes, Watches: rt.Watches}
		for i, issue := range rt.Issues {
			if i == maxRealtimeIssues {
				break
			}
			if len(issue) > 300 {
				issue = strings.ToValidUTF8(issue[:300], "")
			}
			f.Realtime.Issues = append(f.Realtime.Issues, issue)
		}
	}
	if p := st.Packages; p != nil {
		f.PackageManager, f.Packages = p.Manager, p.Packages
	}
	for _, name := range slices.Sorted(maps.Keys(st.Issues)) {
		l := store.LimitFact{Collector: name, More: st.IssueCounts[name] - len(st.Issues[name])}
		for _, issue := range st.Issues[name] {
			note := issueNote(issue)
			if len(issue) > 300 {
				issue = strings.ToValidUTF8(issue[:300], "")
			}
			if note {
				l.Notes = append(l.Notes, issue)
			} else {
				l.Incomplete = append(l.Incomplete, issue)
			}
		}
		f.Limits = append(f.Limits, l)
	}

	if w := st.Web; w != nil {
		// Served applications first: those on disk alone cannot push them past the bound.
		for _, served := range []bool{true, false} {
			for _, app := range w.Apps {
				if len(f.Apps) == maxAppFacts || (len(app.Sites) > 0) != served {
					continue
				}
				f.Apps = append(f.Apps, store.AppFact{Path: app.Path, Framework: app.Framework, Version: app.Version,
					Sites: app.Sites[:min(len(app.Sites), maxAppSites)]})
			}
		}
	}
	if so := st.Sockets; so != nil {
		seen := map[string]bool{}
		for _, s := range so.Sockets {
			if s.State == "listen" && !seen[s.Proto+" "+s.Local] {
				seen[s.Proto+" "+s.Local] = true
				f.Listening++
			}
		}
	}
	return f
}
