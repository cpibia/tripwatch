package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Alert statuses.
const (
	StatusOpen     = "open"
	StatusAcked    = "acknowledged"
	StatusResolved = "resolved"
)

type Alert struct {
	ID          int64
	HostID      string
	Fingerprint string
	Severity    string
	Kind        string
	Title       string
	Detail      string
	Status      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Occurrences int
	AckedBy     string
	NotifiedAt  time.Time
}

// Bounds on what one host can put in the alert table. Titles and details come in part from the
// host, which may be compromised, and some findings (requests in the web logs) can be produced
// by anyone. Alerts of one rule and severity beyond MaxOpenPerGroup become one aggregate alert
// of that rule and severity, so noise from one rule never mutes another: a new rule at any
// severity is a new group and is raised and notified on its own. MaxOpenPerHost bounds the
// medium and low alerts of a host; high and critical ones are bounded per group only.
const (
	MaxTitle        = 300
	MaxDetail       = 8 << 10
	MaxFingerprint  = 512
	MaxOpenPerGroup = 100
	MaxOpenPerHost  = 2000
)

// FloodFingerprint marks the alert that stands for the medium and low findings of a host
// beyond MaxOpenPerHost; aggregate alerts of one group start with floodPrefix.
const (
	FloodFingerprint = "alerts:flood"
	floodPrefix      = "flood:"
)

// group is the part of a fingerprint that aggregation counts by, with the bounds of the range of
// fingerprints in it. A fingerprint may name its group explicitly up to a "|" (the web log
// rules put the script there, so noise sent to one script does not share a group with another);
// otherwise the group is "kind:rule".
func group(fingerprint string) (g, lo, hi string) {
	if i := strings.IndexByte(fingerprint, '|'); i >= 0 {
		g = fingerprint[:i]
		return g, g + "|", g + "}"
	}
	parts := strings.SplitN(fingerprint, ":", 3)
	if len(parts) < 3 {
		return fingerprint, fingerprint + ":", fingerprint + ";"
	}
	g = parts[0] + ":" + parts[1]
	return g, g + ":", g + ";"
}

// storedFingerprint bounds a fingerprint as it is stored: a long one keeps its start and a hash.
func storedFingerprint(fp string) string {
	if len(fp) <= MaxFingerprint {
		return fp
	}
	sum := sha256.Sum256([]byte(fp))
	return fp[:64] + ":" + hex.EncodeToString(sum[:])
}

// AlertID returns the id of a host's alert with the given fingerprint, as passed to Raise.
func (s *Store) AlertID(ctx context.Context, host, fingerprint string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM alerts WHERE host_id = ? AND fingerprint = ?`, host, storedFingerprint(fingerprint)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

// renotifyAfter is how often an aggregate of serious alerts that keeps growing is mailed again.
const renotifyAfter = time.Hour

// visible shows as escapes the characters of a text that would change how the rest reads:
// control characters, line and paragraph separators, and the invisible format characters
// (bidirectional overrides and isolates, zero-width marks). Names of files, processes and
// requests come from the monitored host: a newline in one would forge a line of the alert email,
// a right-to-left override would show x\u202egnp.php as xphp.png. Line breaks stay in a
// detail, where the verifier writes them. Invalid UTF-8 becomes U+FFFD.
func visible(s string, lines bool) string {
	clean := true
	for _, r := range s {
		if hidden(r, lines) || r == utf8.RuneError {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(s, "\uFFFD") {
		switch {
		case !hidden(r, lines):
			b.WriteRune(r)
		case r < 0x80:
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			fmt.Fprintf(&b, "\\u%04x", r)
		}
	}
	return b.String()
}

func hidden(r rune, lines bool) bool {
	if lines && r == '\n' {
		return false
	}
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary so the text stays valid UTF-8.
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// Raise records an alert. The same fingerprint on the same host updates the existing alert
// instead of adding one, and reopens it if it had been resolved: a condition that comes back
// is news again, unless someone accepted it with the same evidence. It reports whether the
// alert is new or reopened.
func (s *Store) Raise(ctx context.Context, a Alert, now time.Time) (bool, error) {
	a.Title, a.Detail, a.Kind = clip(visible(a.Title, false), MaxTitle), clip(visible(a.Detail, true), MaxDetail), clip(a.Kind, 64)
	a.Fingerprint = storedFingerprint(a.Fingerprint)
	if ok, err := s.accepted(ctx, a); ok || err != nil {
		return false, err
	}
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM alerts WHERE host_id = ? AND fingerprint = ?`, a.HostID, a.Fingerprint).Scan(&status)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if a.Fingerprint != FloodFingerprint && !strings.HasPrefix(a.Fingerprint, floodPrefix) {
			g, lo, hi := group(a.Fingerprint)
			var inGroup int
			// The range on the fingerprint uses the (host_id, fingerprint) index.
			if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE host_id = ? AND fingerprint >= ? AND fingerprint < ?
				AND severity = ? AND status != 'resolved'`, a.HostID, lo, hi, a.Severity).Scan(&inGroup); err != nil {
				return false, err
			}
			if inGroup >= MaxOpenPerGroup {
				flood := floodPrefix + a.Severity + ":" + g
				fresh, err := s.Raise(ctx, Alert{HostID: a.HostID, Fingerprint: flood, Severity: a.Severity, Kind: a.Kind,
					Title:  clip("Many alerts of the same rule: "+a.Title, MaxTitle),
					Detail: "The server already has " + strconv.Itoa(inGroup) + " open alerts of this rule and severity: the next ones are gathered here. Latest:\n" + a.Detail,
				}, now)
				// A serious aggregate that keeps growing is mailed again, at most once an hour,
				// so what arrives after the first email is not silent.
				if err == nil && (a.Severity == "critical" || a.Severity == "high") {
					_, err = s.db.ExecContext(ctx, `UPDATE alerts SET notified_at = 0 WHERE host_id = ? AND fingerprint = ? AND notified_at > 0 AND notified_at < ?`,
						a.HostID, flood, now.Add(-renotifyAfter).Unix())
				}
				return fresh, err
			}
			if a.Severity != "critical" && a.Severity != "high" {
				var open int
				if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE host_id = ? AND status != 'resolved'`, a.HostID).Scan(&open); err != nil {
					return false, err
				}
				if open >= MaxOpenPerHost {
					return s.Raise(ctx, Alert{HostID: a.HostID, Fingerprint: FloodFingerprint, Severity: "high", Kind: "verifier",
						Title:  "Too many alerts open on this server",
						Detail: "The server already has " + strconv.Itoa(open) + " open alerts: new medium and low ones are not recorded until some are closed (high and critical ones are). A server producing this many anomalies needs a direct look. Latest dropped: " + a.Title,
					}, now)
				}
			}
		}
		_, err = s.db.ExecContext(ctx, `INSERT INTO alerts (host_id, fingerprint, severity, kind, title, detail, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, a.HostID, a.Fingerprint, a.Severity, a.Kind, a.Title, a.Detail, now.Unix(), now.Unix())
		return true, err
	case err != nil:
		return false, err
	}
	reopened := status == StatusResolved
	_, err = s.db.ExecContext(ctx, `UPDATE alerts SET severity = ?, title = ?, detail = ?, updated_at = ?, occurrences = occurrences + 1,
		status = CASE WHEN status = 'resolved' THEN 'open' ELSE status END,
		notified_at = CASE WHEN status = 'resolved' THEN 0 ELSE notified_at END
		WHERE host_id = ? AND fingerprint = ?`, a.Severity, a.Title, a.Detail, now.Unix(), a.HostID, a.Fingerprint)
	return reopened, err
}

// ResolveMissing marks as resolved the open alerts of a host and kind whose fingerprints are
// not in current: conditions that a newer snapshot no longer shows. High and critical alerts
// are left alone: a compromised host could otherwise clean up and close its own alerts, so a
// person has to look at them.
func (s *Store) ResolveMissing(ctx context.Context, host, kind string, current []string, now time.Time) error {
	return s.resolveMissing(ctx, host, kind, current, now, false)
}

// ResolveGone is ResolveMissing for conditions whose end is itself trustworthy, such as a
// silent sensor reporting again, and which may close at any severity.
func (s *Store) ResolveGone(ctx context.Context, host, kind string, current []string, now time.Time) error {
	return s.resolveMissing(ctx, host, kind, current, now, true)
}

func (s *Store) resolveMissing(ctx context.Context, host, kind string, current []string, now time.Time, anySeverity bool) error {
	q := `SELECT fingerprint FROM alerts WHERE host_id = ? AND kind = ? AND status != 'resolved'`
	if !anySeverity {
		q += ` AND severity NOT IN ('critical', 'high')`
	}
	rows, err := s.db.QueryContext(ctx, q, host, kind)
	if err != nil {
		return err
	}
	var stale []string
	keep := map[string]bool{}
	for _, f := range current {
		keep[f] = true
	}
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			_ = rows.Close()
			return err
		}
		if !keep[f] {
			stale = append(stale, f)
		}
	}
	_ = rows.Close()
	for _, f := range stale {
		if _, err := s.db.ExecContext(ctx, `UPDATE alerts SET status = 'resolved', updated_at = ? WHERE host_id = ? AND fingerprint = ?`, now.Unix(), host, f); err != nil {
			return err
		}
	}
	return nil
}

// PruneResolved deletes resolved alerts past their retention.
func (s *Store) PruneResolved(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM alerts WHERE status = 'resolved' AND (updated_at < ?
		OR (severity NOT IN ('critical', 'high') AND updated_at < ?))`, now.Add(-s.retain.Resolved).Unix(), now.Add(-s.retain.MinorResolved).Unix())
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM alert_diffs WHERE alert_id NOT IN (SELECT id FROM alerts)`)
	return err
}

// SetAlertDiff keeps the complete diff of a policy alert, replacing the one before.
func (s *Store) SetAlertDiff(ctx context.Context, id int64, lines string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO alert_diffs (alert_id, lines, computed_at) VALUES (?, ?, ?)
		ON CONFLICT (alert_id) DO UPDATE SET lines = excluded.lines, computed_at = excluded.computed_at`, id, lines, now.Unix())
	return err
}

// AlertDiff returns the complete diff kept with an alert and when it was computed.
func (s *Store) AlertDiff(ctx context.Context, id int64) (string, time.Time, error) {
	var lines string
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT lines, computed_at FROM alert_diffs WHERE alert_id = ?`, id).Scan(&lines, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, ErrNotFound
	}
	return lines, unix(at), err
}

// Resolve closes an alert by hand.
func (s *Store) Resolve(ctx context.Context, id int64, by string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE alerts SET status = 'resolved', acked_by = ?, updated_at = ? WHERE id = ? AND status != 'resolved'`, by, now.Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Ack marks an alert as acknowledged by a user.
func (s *Store) Ack(ctx context.Context, id int64, by string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE alerts SET status = 'acknowledged', acked_by = ?, updated_at = ? WHERE id = ? AND status = 'open'`, by, now.Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AlertFilter selects alerts; zero values mean no restriction.
type AlertFilter struct {
	ID         int64
	HostID     string
	Statuses   []string
	Severities []string
	Unnotified bool
	// Since keeps the alerts updated since a time, CreatedSince those raised since a time.
	Since        time.Time
	CreatedSince time.Time
	Limit        int
	// Oldest orders by creation, oldest first, within each severity instead of newest update.
	Oldest bool
	// Current leaves out the alerts of revoked hosts, which no longer report: their alerts stay
	// as a record, but they no longer describe the fleet.
	Current bool
	// Kinds keeps the alerts of these kinds only.
	Kinds []string
	// Query keeps the alerts whose host, title or detail contain it, ignoring case.
	Query string
	// Sort orders the alerts another way than the most severe and recently updated first.
	Sort string
	// Offset skips that many alerts of the order, for the pages after the first.
	Offset int
	// AfterID keeps the alerts with a higher ID: a cursor for programs that read every alert
	// once, in the order they were raised (Sort SortID).
	AfterID int64
}

// Orders of an alert list besides the default.
const (
	SortOldest      = "oldest"
	SortNewest      = "newest"
	SortOccurrences = "occurrences"
	SortHost        = "host"
	// SortID is the order alerts were raised in, the one AfterID pages through.
	SortID = "id"
)

// maxQueryLen bounds the text searched in alerts.
const maxQueryLen = 200

// likePattern makes text a LIKE pattern that matches it literally anywhere.
func likePattern(text string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(text) + "%"
}

// currentHosts is the condition that keeps alerts of hosts still enrolled.
const currentHosts = `host_id NOT IN (SELECT id FROM hosts WHERE revoked = 1)`

// Alert returns one alert by id.
func (s *Store) Alert(ctx context.Context, id int64) (Alert, error) {
	if id <= 0 {
		// Zero means "no restriction" to the filter, not an alert.
		return Alert{}, ErrNotFound
	}
	out, err := s.Alerts(ctx, AlertFilter{ID: id})
	if err != nil {
		return Alert{}, err
	}
	if len(out) == 0 {
		return Alert{}, ErrNotFound
	}
	return out[0], nil
}

// CountAlerts counts the alerts a filter matches, whatever its limit: a list cut short says of
// how many.
func (s *Store) CountAlerts(ctx context.Context, f AlertFilter) (int, error) {
	where, args := alertWhere(ctx, f)
	ctx, cancel := searchContext(ctx, f)
	defer cancel()
	var n int
	err := s.read.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts`+where, args...).Scan(&n) //nolint:gosec // alertWhere builds constant clauses; values are bound
	return n, err
}

// searchContext bounds a list that searches text in time, like a search of events.
func searchContext(ctx context.Context, f AlertFilter) (context.Context, context.CancelFunc) {
	if strings.TrimSpace(f.Query) == "" {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, searchTimeout)
}

// alertWhere is the WHERE clause of a filter, with its arguments, the request's scope included.
func alertWhere(ctx context.Context, f AlertFilter) (string, []any) {
	q := ` WHERE 1 = 1`
	var args []any
	if f.ID != 0 {
		q += ` AND id = ?`
		args = append(args, f.ID)
	}
	if !f.Since.IsZero() {
		q += ` AND updated_at >= ?`
		args = append(args, f.Since.Unix())
	}
	if !f.CreatedSince.IsZero() {
		q += ` AND created_at >= ?`
		args = append(args, f.CreatedSince.Unix())
	}
	if f.HostID != "" {
		q += ` AND host_id = ?`
		args = append(args, f.HostID)
	}
	if f.AfterID > 0 {
		q += ` AND id > ?`
		args = append(args, f.AfterID)
	}
	if len(f.Severities) > 0 {
		q += ` AND severity IN (?` + repeat(",?", len(f.Severities)-1) + `)` //nolint:gosec // placeholders only; values are bound
		for _, sev := range f.Severities {
			args = append(args, sev)
		}
	}
	if f.Unnotified {
		q += ` AND notified_at = 0`
	}
	if f.Current {
		q += ` AND ` + currentHosts
	}
	if clause, more := scopeClause(ctx, "host_id"); clause != "" {
		q += clause
		args = append(args, more...)
	}
	if len(f.Statuses) > 0 {
		q += ` AND status IN (?` + repeat(",?", len(f.Statuses)-1) + `)` //nolint:gosec // placeholders only; values are bound
		for _, st := range f.Statuses {
			args = append(args, st)
		}
	}
	if len(f.Kinds) > 0 {
		q += ` AND kind IN (?` + repeat(",?", len(f.Kinds)-1) + `)` //nolint:gosec // placeholders only; values are bound
		for _, k := range f.Kinds {
			args = append(args, k)
		}
	}
	if text := strings.TrimSpace(f.Query); text != "" {
		like := likePattern(strings.ToValidUTF8(text[:min(len(text), maxQueryLen)], ""))
		q += ` AND (host_id LIKE ? ESCAPE '\' OR title LIKE ? ESCAPE '\' OR detail LIKE ? ESCAPE '\')`
		args = append(args, like, like, like)
	}
	return q, args
}

func (s *Store) Alerts(ctx context.Context, f AlertFilter) ([]Alert, error) {
	where, args := alertWhere(ctx, f)
	//nolint:gosec // alertWhere builds constant clauses; values are bound
	q := `SELECT id, host_id, fingerprint, severity, kind, title, detail, status, created_at, updated_at, occurrences,
		COALESCE(acked_by, ''), notified_at FROM alerts` + where
	switch {
	case f.Sort == SortID:
		q += ` ORDER BY id`
	case f.Sort == SortNewest:
		q += ` ORDER BY created_at DESC, id DESC`
	case f.Sort == SortOldest:
		q += ` ORDER BY created_at, id`
	case f.Sort == SortOccurrences:
		q += ` ORDER BY occurrences DESC, ` + severityOrder + `, id DESC`
	case f.Sort == SortHost:
		q += ` ORDER BY host_id, ` + severityOrder + `, updated_at DESC, id DESC`
	case f.Oldest:
		q += ` ORDER BY ` + severityOrder + `, created_at, id`
	default:
		q += ` ORDER BY ` + severityOrder + `, updated_at DESC, id DESC`
	}
	if f.Limit > 0 {
		q += ` LIMIT ? OFFSET ?`
		args = append(args, f.Limit, max(f.Offset, 0))
	}
	ctx, cancel := searchContext(ctx, f)
	defer cancel()
	rows, err := s.read.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Alert
	for rows.Next() {
		var a Alert
		var created, updated, notified int64
		if err := rows.Scan(&a.ID, &a.HostID, &a.Fingerprint, &a.Severity, &a.Kind, &a.Title, &a.Detail, &a.Status,
			&created, &updated, &a.Occurrences, &a.AckedBy, &notified); err != nil {
			return nil, err
		}
		a.CreatedAt, a.UpdatedAt, a.NotifiedAt = unix(created), unix(updated), unix(notified)
		out = append(out, a)
	}
	return out, rows.Err()
}

// Unnotified returns up to limit alerts of the given severities not yet sent by email, the most
// severe and oldest first, whatever their status: an alert that resolved itself before the
// next round must still be sent.
func (s *Store) Unnotified(ctx context.Context, severities []string, limit int) ([]Alert, error) {
	if len(severities) == 0 {
		return nil, nil
	}
	return s.Alerts(ctx, AlertFilter{Severities: severities, Unnotified: true, Limit: limit, Oldest: true})
}

func (s *Store) MarkNotified(ctx context.Context, ids []int64, now time.Time) error {
	for _, id := range ids {
		if _, err := s.db.ExecContext(ctx, `UPDATE alerts SET notified_at = ? WHERE id = ?`, now.Unix(), id); err != nil {
			return err
		}
	}
	return nil
}

const severityOrder = `CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END`

// HostSummary is what the overview needs of a host's unresolved alerts: how many, and the one
// to show, the most severe untaken one and the oldest among equals.
type HostSummary struct {
	Open  int
	Worst Alert
}

// Summaries returns the summary of every host with unresolved alerts, computed in the database
// so that one host's thousands of alerts cannot hide the others.
func (s *Store) Summaries(ctx context.Context) (map[string]HostSummary, error) {
	scope, args := scopeClause(ctx, "host_id")
	//nolint:gosec // the scope is a constant clause of this package; its label is bound
	rows, err := s.read.QueryContext(ctx, `SELECT id, host_id, fingerprint, severity, kind, title, detail, status, created_at, updated_at,
		occurrences, COALESCE(acked_by, ''), notified_at, n FROM (
			SELECT *, ROW_NUMBER() OVER (PARTITION BY host_id ORDER BY status = 'open' DESC, `+severityOrder+`, created_at, id) AS rn,
				COUNT(*) OVER (PARTITION BY host_id) AS n
			FROM alerts WHERE status != 'resolved' AND `+currentHosts+scope+`
		) WHERE rn = 1`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]HostSummary{}
	for rows.Next() {
		var a Alert
		var created, updated, notified int64
		var n int
		if err := rows.Scan(&a.ID, &a.HostID, &a.Fingerprint, &a.Severity, &a.Kind, &a.Title, &a.Detail, &a.Status,
			&created, &updated, &a.Occurrences, &a.AckedBy, &notified, &n); err != nil {
			return nil, err
		}
		a.CreatedAt, a.UpdatedAt, a.NotifiedAt = unix(created), unix(updated), unix(notified)
		out[a.HostID] = HostSummary{Open: n, Worst: a}
	}
	return out, rows.Err()
}

// Tally counts unresolved alerts by kind of counter for the overview, with the oldest of each.
type Tally struct {
	N      int
	Oldest time.Time
}

// Tallies counts unresolved alerts of enrolled hosts: "acknowledged" for those someone took, and
// otherwise by severity; silence alerts are left out, the overview counts silent hosts itself.
func (s *Store) Tallies(ctx context.Context) (map[string]Tally, error) {
	scope, args := scopeClause(ctx, "host_id")
	//nolint:gosec // the scope is a constant clause of this package; its label is bound
	rows, err := s.read.QueryContext(ctx, `SELECT CASE WHEN status = 'acknowledged' THEN 'acknowledged' ELSE severity END AS k,
		COUNT(*), MIN(created_at) FROM alerts WHERE status != 'resolved' AND kind != 'silence' AND `+currentHosts+scope+` GROUP BY k`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]Tally{}
	for rows.Next() {
		var k string
		var t Tally
		var oldest int64
		if err := rows.Scan(&k, &t.N, &oldest); err != nil {
			return nil, err
		}
		t.Oldest = unix(oldest)
		out[k] = t
	}
	return out, rows.Err()
}

func repeat(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}

// Alarming reports whether a critical alert is open, silences included: what turns the console's
// tab icon red.
func (s *Store) Alarming(ctx context.Context) (bool, error) {
	var n int
	scope, args := scopeClause(ctx, "host_id")
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM alerts WHERE status = 'open' AND severity = 'critical' AND `+currentHosts+scope+`)`, args...).Scan(&n)
	return n == 1, err
}

// Raised is an alert as the overview's charts need it: when it was raised, how severe, by which
// rule, on which host, and how often it was seen.
type Raised struct {
	ID          int64
	HostID      string
	Fingerprint string
	Severity    string
	Kind        string
	Title       string
	Detail      string
	Status      string
	CreatedAt   time.Time
	Occurrences int
}

// RaisedSince lists the alerts raised since a time, whatever their status. Resolved medium and
// low alerts are pruned after the retention of resolved minor alerts, so periods longer than
// that undercount them.
func (s *Store) RaisedSince(ctx context.Context, since time.Time) ([]Raised, error) {
	scope, args := scopeClause(ctx, "host_id")
	//nolint:gosec // the scope is a constant clause of this package; its label is bound
	rows, err := s.db.QueryContext(ctx, `SELECT id, host_id, fingerprint, severity, kind, title,
		CASE WHEN kind = 'weblog' THEN detail ELSE '' END, status, created_at, occurrences
		FROM alerts WHERE created_at >= ? AND `+currentHosts+scope+` ORDER BY created_at`, append([]any{since.Unix()}, args...)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Raised
	for rows.Next() {
		var r Raised
		var created int64
		if err := rows.Scan(&r.ID, &r.HostID, &r.Fingerprint, &r.Severity, &r.Kind, &r.Title, &r.Detail, &r.Status, &created, &r.Occurrences); err != nil {
			return nil, err
		}
		r.CreatedAt = unix(created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// OpenBySeverity counts the unresolved alerts of every host by severity, silences included.
func (s *Store) OpenBySeverity(ctx context.Context) (map[string]map[string]int, error) {
	scope, args := scopeClause(ctx, "host_id")
	//nolint:gosec // the scope is a constant clause of this package; its label is bound
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, severity, COUNT(*) FROM alerts WHERE status != 'resolved' AND `+currentHosts+scope+` GROUP BY host_id, severity`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]map[string]int{}
	for rows.Next() {
		var host, sev string
		var n int
		if err := rows.Scan(&host, &sev, &n); err != nil {
			return nil, err
		}
		if out[host] == nil {
			out[host] = map[string]int{}
		}
		out[host][sev] = n
	}
	return out, rows.Err()
}
