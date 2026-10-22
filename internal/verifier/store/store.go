// Package store keeps the verifier's state in SQLite: enrolled hosts and their chain
// positions, recent snapshots, alerts, and the users of the web interface.
package store

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure Go driver: the verifier image needs no C toolchain

	"github.com/cpibia/tripwatch/internal/protocol"
)

// Snapshot retention, by age and never by count, so that a compromised host flooding snapshots
// cannot push the evidence out: every snapshot of the last DenseRetention, then the last one of
// each day and every snapshot that raised an alert until Retention, and a host's first snapshot
// for good as its baseline. Hourly snapshots of a stable host are nearly identical; thinning
// them keeps the database at a few days' worth per host instead of a month.
const (
	DenseRetention = 48 * time.Hour
	Retention      = 30 * 24 * time.Hour
)

// ActivityRetention bounds the per-minute record of heartbeats and snapshots behind the traces
// of the web interface.
const ActivityRetention = 7 * 24 * time.Hour

var ErrNotFound = errors.New("store: not found")

const schema = `
CREATE TABLE IF NOT EXISTS hosts (
	id             TEXT PRIMARY KEY,
	public_key     BLOB NOT NULL,
	enrolled_at    INTEGER NOT NULL,
	revoked        INTEGER NOT NULL DEFAULT 0,
	last_seq       INTEGER NOT NULL DEFAULT 0,
	last_digest    BLOB,
	last_seen      INTEGER NOT NULL DEFAULT 0,
	last_heartbeat INTEGER NOT NULL DEFAULT 0,
	last_snapshot  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS snapshots (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	host_id     TEXT NOT NULL REFERENCES hosts(id),
	seq         INTEGER NOT NULL,
	taken_at    INTEGER NOT NULL,
	received_at INTEGER NOT NULL,
	analyzed    INTEGER NOT NULL DEFAULT 0,
	keep        INTEGER NOT NULL DEFAULT 0,
	payload     BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS snapshots_pending ON snapshots(analyzed, id);
CREATE INDEX IF NOT EXISTS snapshots_host ON snapshots(host_id, id);
CREATE TABLE IF NOT EXISTS alerts (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	host_id     TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	severity    TEXT NOT NULL,
	kind        TEXT NOT NULL,
	title       TEXT NOT NULL,
	detail      TEXT NOT NULL,
	status      TEXT NOT NULL DEFAULT 'open',
	created_at  INTEGER NOT NULL,
	updated_at  INTEGER NOT NULL,
	occurrences INTEGER NOT NULL DEFAULT 1,
	acked_by    TEXT,
	notified_at INTEGER NOT NULL DEFAULT 0,
	UNIQUE(host_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS alerts_status ON alerts(status, severity, updated_at);
CREATE TABLE IF NOT EXISTS activity (
	host_id TEXT NOT NULL,
	minute  INTEGER NOT NULL,
	kind    TEXT NOT NULL,
	PRIMARY KEY (host_id, minute, kind)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS users (
	email         TEXT PRIMARY KEY,
	password_hash BLOB NOT NULL,
	created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash BLOB PRIMARY KEY,
	email      TEXT NOT NULL REFERENCES users(email),
	expires_at INTEGER NOT NULL
);
`

type Store struct {
	db *sql.DB
}

// Open opens or creates the database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer: a single connection serialises writes instead of failing them.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: migration: %w", err)
	}
	return &Store{db: db}, nil
}

// migrate adds the columns that databases created by earlier versions lack.
func migrate(db *sql.DB) error {
	var n int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM pragma_table_info('snapshots') WHERE name = 'keep'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		_, err := db.ExecContext(context.Background(), `ALTER TABLE snapshots ADD COLUMN keep INTEGER NOT NULL DEFAULT 0`)
		return err
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

type Host struct {
	ID            string
	PublicKey     ed25519.PublicKey
	EnrolledAt    time.Time
	Revoked       bool
	Chain         protocol.ChainState
	LastSeen      time.Time
	LastHeartbeat time.Time
	LastSnapshot  time.Time
}

// Enroll registers a host and its signing key, or replaces the key of an existing host and
// restarts its chain: re-enrollment is how a reinstalled sensor is brought back.
func (s *Store) Enroll(ctx context.Context, id string, pub ed25519.PublicKey, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO hosts (id, public_key, enrolled_at) VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET public_key = excluded.public_key, enrolled_at = excluded.enrolled_at,
		revoked = 0, last_seq = 0, last_digest = NULL`, id, []byte(pub), now.Unix())
	return err
}

func (s *Store) Revoke(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE hosts SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Host(ctx context.Context, id string) (Host, error) {
	rows, err := s.hosts(ctx, `WHERE id = ?`, id)
	if err != nil {
		return Host{}, err
	}
	if len(rows) == 0 {
		return Host{}, ErrNotFound
	}
	return rows[0], nil
}

func (s *Store) Hosts(ctx context.Context) ([]Host, error) {
	return s.hosts(ctx, `ORDER BY id`)
}

func (s *Store) hosts(ctx context.Context, where string, args ...any) ([]Host, error) {
	//nolint:gosec // where is a constant clause from this package; values are bound
	rows, err := s.db.QueryContext(ctx, `SELECT id, public_key, enrolled_at, revoked, last_seq, last_digest,
		last_seen, last_heartbeat, last_snapshot FROM hosts `+where, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Host
	for rows.Next() {
		var h Host
		var pub, digest []byte
		var enrolled, seen, heartbeat, snapshot int64
		if err := rows.Scan(&h.ID, &pub, &enrolled, &h.Revoked, &h.Chain.Sequence, &digest, &seen, &heartbeat, &snapshot); err != nil {
			return nil, err
		}
		h.PublicKey, h.Chain.LastDigest = pub, digest
		h.EnrolledAt, h.LastSeen, h.LastHeartbeat, h.LastSnapshot = unix(enrolled), unix(seen), unix(heartbeat), unix(snapshot)
		out = append(out, h)
	}
	return out, rows.Err()
}

// ErrChainMoved is returned when the host's chain changed between verification and storage:
// another envelope of the same host was accepted in the meantime.
var ErrChainMoved = errors.New("store: chain position changed concurrently")

// Accept records a verified envelope: the new chain position and, for snapshots, the payload.
// It runs in one transaction, and only if the chain is still where it was when the envelope was
// verified (prev), so two envelopes can never both extend the same position.
func (s *Store) Accept(ctx context.Context, e protocol.Envelope, prev, state protocol.ChainState, now time.Time) error {
	return s.accept(ctx, e, prev, state, now, true)
}

// AcceptDropped records a verified snapshot envelope without its payload: the chain moves and
// the host counts as alive, but nothing is stored or analysed. It is for snapshots over the
// host's storage quota, so that a host flooding the disk does not also lose its liveness.
func (s *Store) AcceptDropped(ctx context.Context, e protocol.Envelope, prev, state protocol.ChainState, now time.Time) error {
	return s.accept(ctx, e, prev, state, now, false)
}

func (s *Store) accept(ctx context.Context, e protocol.Envelope, prev, state protocol.ChainState, now time.Time, keepPayload bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	kind := e.Kind
	if kind == protocol.KindSnapshot && !keepPayload {
		kind = protocol.KindHeartbeat
	}
	field := map[protocol.Kind]string{protocol.KindHeartbeat: "last_heartbeat", protocol.KindSnapshot: "last_snapshot"}[kind]
	set := "last_seq = ?, last_digest = ?, last_seen = ?"
	args := []any{state.Sequence, state.LastDigest, now.Unix()}
	if field != "" {
		set += ", " + field + " = ?"
		args = append(args, now.Unix())
	}
	res, err := tx.ExecContext(ctx, `UPDATE hosts SET `+set+` WHERE id = ? AND last_seq = ?`, append(args, e.HostID, prev.Sequence)...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrChainMoved
	}
	if field != "" {
		minute := now.Unix() / 60
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO activity (host_id, minute, kind) VALUES (?, ?, ?)`, e.HostID, minute, string(kind)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM activity WHERE host_id = ? AND minute < ?`, e.HostID, minute-int64(ActivityRetention/time.Minute)); err != nil {
			return err
		}
	}
	if kind == protocol.KindSnapshot {
		if _, err := tx.ExecContext(ctx, `INSERT INTO snapshots (host_id, seq, taken_at, received_at, payload) VALUES (?, ?, ?, ?, ?)`,
			e.HostID, e.Sequence, e.SentAt.Unix(), now.Unix(), e.Payload); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM snapshots WHERE host_id = ? AND analyzed = 1 AND received_at < ?
			AND id != (SELECT MIN(id) FROM snapshots WHERE host_id = ?)`, e.HostID, now.Add(-Retention).Unix(), e.HostID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM snapshots WHERE host_id = ? AND analyzed = 1 AND keep = 0 AND received_at < ?
			AND id != (SELECT MIN(id) FROM snapshots WHERE host_id = ?)
			AND id NOT IN (SELECT MAX(id) FROM snapshots WHERE host_id = ? GROUP BY received_at / 86400)`,
			e.HostID, now.Add(-DenseRetention).Unix(), e.HostID, e.HostID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PendingSnapshots returns the ids of snapshots not analysed yet, oldest first. The queue lives
// in the database, so nothing is lost on a restart and nothing is dropped when busy.
func (s *Store) PendingSnapshots(ctx context.Context, limit int) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM snapshots WHERE analyzed = 0 ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Keep marks a snapshot as evidence of an alert, exempt from thinning until Retention.
func (s *Store) Keep(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE snapshots SET keep = 1 WHERE id = ?`, id)
	return err
}

func (s *Store) MarkAnalyzed(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE snapshots SET analyzed = 1 WHERE id = ?`, id)
	return err
}

// SnapshotPair returns a snapshot and the one before it from the same host, if any.
func (s *Store) SnapshotPair(ctx context.Context, id int64) (Snapshot, *Snapshot, error) {
	cur, err := s.snapshot(ctx, `WHERE id = ?`, id)
	if err != nil {
		return Snapshot{}, nil, err
	}
	prev, err := s.snapshot(ctx, `WHERE host_id = ? AND id < ? ORDER BY id DESC LIMIT 1`, cur.HostID, id)
	if errors.Is(err, ErrNotFound) {
		return cur, nil, nil
	}
	if err != nil {
		return Snapshot{}, nil, err
	}
	return cur, &prev, nil
}

func (s *Store) snapshot(ctx context.Context, where string, args ...any) (Snapshot, error) {
	var sn Snapshot
	var taken, received int64
	err := s.db.QueryRowContext(ctx, `SELECT id, host_id, seq, taken_at, received_at, payload FROM snapshots `+where, args...).
		Scan(&sn.ID, &sn.HostID, &sn.Sequence, &taken, &received, &sn.Payload)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrNotFound
	}
	sn.TakenAt, sn.ReceivedAt = unix(taken), unix(received)
	return sn, err
}

type Snapshot struct {
	ID         int64
	HostID     string
	Sequence   uint64
	TakenAt    time.Time
	ReceivedAt time.Time
	Payload    []byte
}

// LatestSnapshots returns up to n most recent snapshots of a host, newest first.
func (s *Store) LatestSnapshots(ctx context.Context, host string, n int) ([]Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, host_id, seq, taken_at, received_at, payload FROM snapshots
		WHERE host_id = ? ORDER BY id DESC LIMIT ?`, host, n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Snapshot
	for rows.Next() {
		var sn Snapshot
		var taken, received int64
		if err := rows.Scan(&sn.ID, &sn.HostID, &sn.Sequence, &taken, &received, &sn.Payload); err != nil {
			return nil, err
		}
		sn.TakenAt, sn.ReceivedAt = unix(taken), unix(received)
		out = append(out, sn)
	}
	return out, rows.Err()
}

// Mark is a minute in which a host delivered an envelope of the given kind.
type Mark struct {
	At   time.Time
	Kind protocol.Kind
}

// Activity returns the minutes since the given time in which the host delivered heartbeats or
// snapshots, oldest first.
func (s *Store) Activity(ctx context.Context, host string, since time.Time) ([]Mark, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT minute, kind FROM activity WHERE host_id = ? AND minute >= ? ORDER BY minute`, host, since.Unix()/60)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Mark
	for rows.Next() {
		var minute int64
		var kind string
		if err := rows.Scan(&minute, &kind); err != nil {
			return nil, err
		}
		out = append(out, Mark{At: unix(minute * 60), Kind: protocol.Kind(kind)})
	}
	return out, rows.Err()
}

// CountSnapshots returns how many snapshots of a host arrived since the given time.
func (s *Store) CountSnapshots(ctx context.Context, host string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM snapshots WHERE host_id = ? AND received_at >= ?`, host, since.Unix()).Scan(&n)
	return n, err
}

// SnapshotBytes returns the size of the snapshots of a host received since the given time.
func (s *Store) SnapshotBytes(ctx context.Context, host string, since time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(length(payload)), 0) FROM snapshots WHERE host_id = ? AND received_at >= ?`, host, since.Unix()).Scan(&n)
	return n, err
}

// SnapshotHead describes a stored snapshot without its payload.
type SnapshotHead struct {
	ID         int64
	Sequence   uint64
	TakenAt    time.Time
	ReceivedAt time.Time
	Size       int
	Analyzed   bool
}

// SnapshotHeads returns up to n most recent snapshots of a host, newest first, without payloads.
func (s *Store) SnapshotHeads(ctx context.Context, host string, n int) ([]SnapshotHead, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, seq, taken_at, received_at, length(payload), analyzed FROM snapshots
		WHERE host_id = ? ORDER BY id DESC LIMIT ?`, host, n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SnapshotHead
	for rows.Next() {
		var h SnapshotHead
		var taken, received int64
		if err := rows.Scan(&h.ID, &h.Sequence, &taken, &received, &h.Size, &h.Analyzed); err != nil {
			return nil, err
		}
		h.TakenAt, h.ReceivedAt = unix(taken), unix(received)
		out = append(out, h)
	}
	return out, rows.Err()
}

func unix(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}
