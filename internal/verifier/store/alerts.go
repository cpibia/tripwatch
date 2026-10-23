package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
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
// is news again. It reports whether the alert is new or reopened.
func (s *Store) Raise(ctx context.Context, a Alert, now time.Time) (bool, error) {
	a.Title, a.Detail, a.Kind = clip(a.Title, MaxTitle), clip(a.Detail, MaxDetail), clip(a.Kind, 64)
	a.Fingerprint = storedFingerprint(a.Fingerprint)
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
					Title:  clip("Molti allarmi della stessa regola: "+a.Title, MaxTitle),
					Detail: "Il server ha già " + strconv.Itoa(inGroup) + " allarmi aperti di questa regola e gravità: i successivi sono raccolti qui. Ultimo arrivato:\n" + a.Detail,
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
						Title:  "Troppi allarmi aperti su questo server",
						Detail: "Il server ha già " + strconv.Itoa(open) + " allarmi aperti: i nuovi di gravità media e bassa non vengono registrati finché non se ne chiudono (quelli alti e critici sì). Un server che produce così tante anomalie va esaminato direttamente. Ultimo scartato: " + a.Title,
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

// Resolved alerts stay for reference: high and critical ones for ResolvedRetention, medium and
// low ones, which are most of the noise, for MinorResolvedRetention. A condition that comes back
// after that is raised as new.
const (
	ResolvedRetention      = 90 * 24 * time.Hour
	MinorResolvedRetention = 7 * 24 * time.Hour
)

// PruneResolved deletes resolved alerts past their retention.
func (s *Store) PruneResolved(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM alerts WHERE status = 'resolved' AND (updated_at < ?
		OR (severity NOT IN ('critical', 'high') AND updated_at < ?))`, now.Add(-ResolvedRetention).Unix(), now.Add(-MinorResolvedRetention).Unix())
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
	Since      time.Time
	Limit      int
	// Oldest orders by creation, oldest first, within each severity instead of newest update.
	Oldest bool
}

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

func (s *Store) Alerts(ctx context.Context, f AlertFilter) ([]Alert, error) {
	q := `SELECT id, host_id, fingerprint, severity, kind, title, detail, status, created_at, updated_at, occurrences,
		COALESCE(acked_by, ''), notified_at FROM alerts WHERE 1 = 1`
	var args []any
	if f.ID != 0 {
		q += ` AND id = ?`
		args = append(args, f.ID)
	}
	if !f.Since.IsZero() {
		q += ` AND updated_at >= ?`
		args = append(args, f.Since.Unix())
	}
	if f.HostID != "" {
		q += ` AND host_id = ?`
		args = append(args, f.HostID)
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
	if len(f.Statuses) > 0 {
		q += ` AND status IN (?` + repeat(",?", len(f.Statuses)-1) + `)` //nolint:gosec // placeholders only; values are bound
		for _, st := range f.Statuses {
			args = append(args, st)
		}
	}
	q += ` ORDER BY ` + severityOrder
	if f.Oldest {
		q += `, created_at, id`
	} else {
		q += `, updated_at DESC, id DESC`
	}
	if f.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, f.Limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
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
	rows, err := s.db.QueryContext(ctx, `SELECT id, host_id, fingerprint, severity, kind, title, detail, status, created_at, updated_at,
		occurrences, COALESCE(acked_by, ''), notified_at, n FROM (
			SELECT *, ROW_NUMBER() OVER (PARTITION BY host_id ORDER BY status = 'open' DESC, `+severityOrder+`, created_at, id) AS rn,
				COUNT(*) OVER (PARTITION BY host_id) AS n
			FROM alerts WHERE status != 'resolved'
		) WHERE rn = 1`)
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

// Tallies counts unresolved alerts: "acknowledged" for those someone took, and otherwise by
// severity; silence alerts are left out, the overview counts silent hosts itself.
func (s *Store) Tallies(ctx context.Context) (map[string]Tally, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT CASE WHEN status = 'acknowledged' THEN 'acknowledged' ELSE severity END AS k,
		COUNT(*), MIN(created_at) FROM alerts WHERE status != 'resolved' AND kind != 'silence' GROUP BY k`)
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
