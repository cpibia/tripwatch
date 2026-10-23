package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
)

// Acceptance is a finding someone declared legitimate on a host, such as a file a library ships.
// It holds only while the evidence is the same: the alert's detail names the file with its size
// and hash, so a changed file, or anything new, is raised again.
type Acceptance struct {
	HostID      string
	Fingerprint string
	Title       string
	AcceptedBy  string
	AcceptedAt  time.Time
}

// processID matches the process numbers in a detail: a restarted process keeps its executable
// and hash, which the fingerprint already names, but not its PID.
var processID = regexp.MustCompile(`\bPID \d+`)

// evidence is what an acceptance is bound to: the detail of the alert as stored, without process
// numbers.
func evidence(detail string) string {
	sum := sha256.Sum256([]byte(processID.ReplaceAllString(detail, "PID")))
	return hex.EncodeToString(sum[:])
}

// accepted reports whether alert a, as it would be stored, matches an acceptance. An acceptance
// whose evidence changed no longer applies and is dropped, so the change is raised.
func (s *Store) accepted(ctx context.Context, a Alert) (bool, error) {
	var ev string
	err := s.db.QueryRowContext(ctx, `SELECT evidence FROM accepted WHERE host_id = ? AND fingerprint = ?`, a.HostID, a.Fingerprint).Scan(&ev)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, err
	case ev == evidence(a.Detail):
		return true, nil
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM accepted WHERE host_id = ? AND fingerprint = ?`, a.HostID, a.Fingerprint)
	return false, err
}

// AcceptAlert declares the condition behind an alert legitimate and closes the alert: the same
// evidence is not raised again on that host until the acceptance is withdrawn.
func (s *Store) AcceptAlert(ctx context.Context, id int64, by string, now time.Time) error {
	a, err := s.Alert(ctx, id)
	if err != nil {
		return err
	}
	if !Acceptable(a) {
		return ErrNotFound
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO accepted (host_id, fingerprint, evidence, title, accepted_by, accepted_at) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (host_id, fingerprint) DO UPDATE SET evidence = excluded.evidence, title = excluded.title,
			accepted_by = excluded.accepted_by, accepted_at = excluded.accepted_at`,
		a.HostID, a.Fingerprint, evidence(a.Detail), a.Title, by, now.Unix()); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE alerts SET status = 'resolved', acked_by = ?, updated_at = ? WHERE id = ?`, by, now.Unix(), id)
	return err
}

// Acceptable reports whether an alert can be accepted: findings about the host's state can,
// while what the verifier and the sensor's lifecycle report (silences, broken chains, sensor
// starts and failures, aggregates, quotas) must stay visible every time it happens.
func Acceptable(a Alert) bool {
	switch a.Kind {
	case "verifier", "silence", "chain", "sensor", "sensor-event":
		return false
	}
	return a.Fingerprint != FloodFingerprint && !strings.HasPrefix(a.Fingerprint, floodPrefix)
}

// Acceptances lists what was accepted on a host, the most recent first.
func (s *Store) Acceptances(ctx context.Context, host string) ([]Acceptance, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, fingerprint, title, accepted_by, accepted_at FROM accepted
		WHERE host_id = ? ORDER BY accepted_at DESC, title`, host)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Acceptance
	for rows.Next() {
		var a Acceptance
		var at int64
		if err := rows.Scan(&a.HostID, &a.Fingerprint, &a.Title, &a.AcceptedBy, &at); err != nil {
			return nil, err
		}
		a.AcceptedAt = unix(at)
		out = append(out, a)
	}
	return out, rows.Err()
}

// Withdraw puts an accepted finding back under watch: the next snapshot that shows it raises it.
func (s *Store) Withdraw(ctx context.Context, host, fingerprint string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM accepted WHERE host_id = ? AND fingerprint = ?`, host, fingerprint)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
