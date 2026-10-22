package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
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

// Raise records an alert. The same fingerprint on the same host updates the existing alert
// instead of adding one, and reopens it if it had been resolved: a condition that comes back
// is news again. It reports whether the alert is new or reopened.
func (s *Store) Raise(ctx context.Context, a Alert, now time.Time) (bool, error) {
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM alerts WHERE host_id = ? AND fingerprint = ?`, a.HostID, a.Fingerprint).Scan(&status)
	switch {
	case errors.Is(err, sql.ErrNoRows):
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
	ID       int64
	HostID   string
	Statuses []string
	Since    time.Time
	Limit    int
}

// Alert returns one alert by id.
func (s *Store) Alert(ctx context.Context, id int64) (Alert, error) {
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
	if len(f.Statuses) > 0 {
		q += ` AND status IN (?` + repeat(",?", len(f.Statuses)-1) + `)` //nolint:gosec // placeholders only; values are bound
		for _, st := range f.Statuses {
			args = append(args, st)
		}
	}
	q += ` ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, updated_at DESC`
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

// Unnotified returns alerts of the given severities not yet sent by email, whatever their
// status: an alert that resolved itself before the next round must still be sent.
func (s *Store) Unnotified(ctx context.Context, severities []string) ([]Alert, error) {
	all, err := s.Alerts(ctx, AlertFilter{})
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, a := range all {
		for _, sev := range severities {
			if a.Severity == sev && a.NotifiedAt.IsZero() {
				out = append(out, a)
				break
			}
		}
	}
	return out, nil
}

func (s *Store) MarkNotified(ctx context.Context, ids []int64, now time.Time) error {
	for _, id := range ids {
		if _, err := s.db.ExecContext(ctx, `UPDATE alerts SET notified_at = ? WHERE id = ?`, now.Unix(), id); err != nil {
			return err
		}
	}
	return nil
}

func repeat(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}
