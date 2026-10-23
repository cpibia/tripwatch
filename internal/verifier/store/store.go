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
	last_snapshot  INTEGER NOT NULL DEFAULT 0,
	cert_serial    TEXT NOT NULL DEFAULT '',
	prev_serial    TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS snapshots (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	host_id     TEXT NOT NULL REFERENCES hosts(id),
	seq         INTEGER NOT NULL,
	taken_at    INTEGER NOT NULL,
	received_at INTEGER NOT NULL,
	analyzed    INTEGER NOT NULL DEFAULT 0,
	keep        INTEGER NOT NULL DEFAULT 0,
	evidence    INTEGER NOT NULL DEFAULT 0,
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
-- Replaced by alerts_open_host, which leaves the resolved alerts out.
DROP INDEX IF EXISTS alerts_host_status;
-- Partial indexes over unresolved alerts only: the counts that bound a host's alerts must not
-- walk the resolved ones, which a noisy host accumulates by the million.
CREATE INDEX IF NOT EXISTS alerts_open_host ON alerts(host_id) WHERE status != 'resolved';
CREATE INDEX IF NOT EXISTS alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS alerts_open_group ON alerts(host_id, severity, fingerprint) WHERE status != 'resolved';
CREATE TABLE IF NOT EXISTS activity (
	host_id TEXT NOT NULL,
	minute  INTEGER NOT NULL,
	kind    TEXT NOT NULL,
	PRIMARY KEY (host_id, minute, kind)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS events (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	host_id         TEXT NOT NULL,
	seq             INTEGER NOT NULL,
	at              INTEGER NOT NULL,
	received_at     INTEGER NOT NULL,
	class           TEXT NOT NULL,
	op              TEXT NOT NULL,
	path            TEXT NOT NULL,
	package_manager INTEGER NOT NULL DEFAULT 0,
	data            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_host ON events(host_id, received_at);
CREATE INDEX IF NOT EXISTS events_path ON events(host_id, path, at);
CREATE TABLE IF NOT EXISTS sensor_runs (
	host_id    TEXT PRIMARY KEY,
	boot_id    TEXT NOT NULL DEFAULT '',
	version    TEXT NOT NULL DEFAULT '',
	stopped_at INTEGER NOT NULL DEFAULT 0,
	stop_reason TEXT NOT NULL DEFAULT '',
	shutdown   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS enroll_tokens (
	host_id    TEXT PRIMARY KEY,
	token_hash BLOB NOT NULL UNIQUE,
	created_by TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	used_at    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS snapshot_evidence (
	snapshot_id INTEGER NOT NULL,
	alert_id    INTEGER NOT NULL,
	digest      TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (snapshot_id, alert_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS snapshot_evidence_alert ON snapshot_evidence(alert_id);
CREATE TABLE IF NOT EXISTS alert_diffs (
	alert_id    INTEGER PRIMARY KEY,
	lines       TEXT NOT NULL,
	computed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS host_facts (
	host_id    TEXT PRIMARY KEY,
	facts      TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS accepted (
	host_id     TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	evidence    TEXT NOT NULL,
	title       TEXT NOT NULL,
	accepted_by TEXT NOT NULL,
	accepted_at INTEGER NOT NULL,
	PRIMARY KEY (host_id, fingerprint)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS login_links (
	token_hash BLOB PRIMARY KEY,
	email      TEXT NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
	token_hash BLOB PRIMARY KEY,
	email      TEXT NOT NULL,
	expires_at INTEGER NOT NULL
);
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
	var evidence int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM pragma_table_info('snapshots') WHERE name = 'evidence'`).Scan(&evidence); err != nil {
		return err
	}
	if evidence == 0 {
		if _, err := db.ExecContext(context.Background(), `ALTER TABLE snapshots ADD COLUMN evidence INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	var digest int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM pragma_table_info('snapshot_evidence') WHERE name = 'digest'`).Scan(&digest); err != nil {
		return err
	}
	if digest == 0 {
		if _, err := db.ExecContext(context.Background(), `ALTER TABLE snapshot_evidence ADD COLUMN digest TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	// Links made before the evidence table: one alert per snapshot, kept in a column.
	if _, err := db.ExecContext(context.Background(), `INSERT OR IGNORE INTO snapshot_evidence (snapshot_id, alert_id)
		SELECT id, evidence FROM snapshots WHERE evidence != 0`); err != nil {
		return err
	}
	var used int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM pragma_table_info('enroll_tokens') WHERE name = 'used_at'`).Scan(&used); err != nil {
		return err
	}
	if used == 0 {
		if _, err := db.ExecContext(context.Background(), `ALTER TABLE enroll_tokens ADD COLUMN used_at INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	for _, col := range []string{"cert_serial", "prev_serial"} {
		var n int
		if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM pragma_table_info('hosts') WHERE name = ?`, col).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := db.ExecContext(context.Background(), `ALTER TABLE hosts ADD COLUMN `+col+` TEXT NOT NULL DEFAULT ''`); err != nil { //nolint:gosec // column names from the list above
				return err
			}
		}
	}
	// sensor_runs as created by 0.1.10 lacks how the sensor said it stopped.
	for col, def := range map[string]string{"stop_reason": "TEXT NOT NULL DEFAULT ''", "shutdown": "INTEGER NOT NULL DEFAULT 0"} {
		var have int
		if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM pragma_table_info('sensor_runs') WHERE name = ?`, col).Scan(&have); err != nil {
			return err
		}
		if have == 0 {
			if _, err := db.ExecContext(context.Background(), `ALTER TABLE sensor_runs ADD COLUMN `+col+` `+def); err != nil { //nolint:gosec // names and definitions from the map above
				return err
			}
		}
	}
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
	// CertSerial is the serial of the host's current client certificate; PrevSerial the one it
	// replaced, still accepted until the new one is first used. Empty means not recorded.
	CertSerial string
	PrevSerial string
}

// Enroll registers a host and its signing key, or replaces the key of an existing host and
// restarts its chain: re-enrollment is how a reinstalled sensor is brought back.
func (s *Store) Enroll(ctx context.Context, id string, pub ed25519.PublicKey, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO hosts (id, public_key, enrolled_at) VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET public_key = excluded.public_key, enrolled_at = excluded.enrolled_at,
		revoked = 0, last_seq = 0, last_digest = NULL, cert_serial = '', prev_serial = ''`, id, []byte(pub), now.Unix())
	return err
}

// EnrollWithCertificate is Enroll and the recording of the host's first client certificate in
// one statement: between the two, no other certificate of the host can be taken for its own.
func (s *Store) EnrollWithCertificate(ctx context.Context, id string, pub ed25519.PublicKey, serial string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO hosts (id, public_key, enrolled_at, cert_serial) VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET public_key = excluded.public_key, enrolled_at = excluded.enrolled_at,
		revoked = 0, last_seq = 0, last_digest = NULL, cert_serial = excluded.cert_serial, prev_serial = ''`, id, []byte(pub), now.Unix(), serial)
	return err
}

// SetCertificate records a newly issued client certificate of a host. On renewal the previous
// one stays accepted until the new one is used, so a lost answer does not lock the sensor out;
// on enrollment (renewal false) every earlier certificate stops working at once.
func (s *Store) SetCertificate(ctx context.Context, id, serial string, renewal bool) error {
	q := `UPDATE hosts SET prev_serial = '', cert_serial = ? WHERE id = ?`
	if renewal {
		q = `UPDATE hosts SET prev_serial = cert_serial, cert_serial = ? WHERE id = ?`
	}
	_, err := s.db.ExecContext(ctx, q, serial, id)
	return err
}

// RenewCertificate records a renewed certificate. The one the renewal was asked with stays
// valid until the new one is used: if the answer is lost, the sensor still holds a certificate
// that works, however many renewals were lost in a row.
func (s *Store) RenewCertificate(ctx context.Context, id, serial, presented string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET prev_serial = ?, cert_serial = ? WHERE id = ?`, presented, serial, id)
	return err
}

// CertificateUsed forgets the previous certificate once the current one has been presented.
func (s *Store) CertificateUsed(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET prev_serial = '' WHERE id = ? AND prev_serial != ''`, id)
	return err
}

func (s *Store) Revoke(ctx context.Context, id string) error {
	// A token made for the host must not bring it back.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM enroll_tokens WHERE host_id = ? AND used_at = 0`, id); err != nil {
		return err
	}
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
		last_seen, last_heartbeat, last_snapshot, cert_serial, prev_serial FROM hosts `+where, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Host
	for rows.Next() {
		var h Host
		var pub, digest []byte
		var enrolled, seen, heartbeat, snapshot int64
		if err := rows.Scan(&h.ID, &pub, &enrolled, &h.Revoked, &h.Chain.Sequence, &digest, &seen, &heartbeat, &snapshot, &h.CertSerial, &h.PrevSerial); err != nil {
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
		// Evidence of an alert still open stays past the retention, within the host's quota.
		var gone []int64
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`DELETE FROM snapshots WHERE host_id = ? AND analyzed = 1 AND received_at < ?
				AND id != (SELECT MIN(id) FROM snapshots WHERE host_id = ?)
				AND NOT EXISTS (SELECT 1 FROM snapshot_evidence ev JOIN alerts a ON a.id = ev.alert_id
					WHERE ev.snapshot_id = snapshots.id AND a.status != 'resolved') RETURNING id`,
				[]any{e.HostID, now.Add(-Retention).Unix(), e.HostID}},
			{`DELETE FROM snapshots WHERE host_id = ? AND analyzed = 1 AND keep = 0 AND received_at < ?
				AND id != (SELECT MIN(id) FROM snapshots WHERE host_id = ?)
				AND id NOT IN (SELECT MAX(id) FROM snapshots WHERE host_id = ? GROUP BY received_at / 86400) RETURNING id`,
				[]any{e.HostID, now.Add(-DenseRetention).Unix(), e.HostID, e.HostID}},
		} {
			rows, err := tx.QueryContext(ctx, q.sql, q.args...)
			if err != nil {
				return err
			}
			for rows.Next() {
				var id int64
				if err := rows.Scan(&id); err != nil {
					_ = rows.Close()
					return err
				}
				gone = append(gone, id)
			}
			if err := rows.Close(); err != nil {
				return err
			}
		}
		// Only the links of the snapshots just deleted, through the primary key.
		for _, id := range gone {
			if _, err := tx.ExecContext(ctx, `DELETE FROM snapshot_evidence WHERE snapshot_id = ?`, id); err != nil {
				return err
			}
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

// Keep marks a snapshot as evidence, exempt from thinning until Retention, and past it while
// any of the alerts it is evidence of stays open. Every alert is recorded, so noise raised in
// the same snapshot cannot take the evidence away from the change that matters.
func (s *Store) Keep(ctx context.Context, id int64, links ...Evidence) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE snapshots SET keep = 1 WHERE id = ?`, id); err != nil {
		return err
	}
	for _, l := range links {
		if l.AlertID == 0 {
			continue
		}
		if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO snapshot_evidence (snapshot_id, alert_id, digest) VALUES (?, ?, ?)`, id, l.AlertID, l.Digest); err != nil {
			return err
		}
	}
	return nil
}

// Evidence links a snapshot to an alert it shows; Digest identifies what the alert said then,
// so a later, different content of the same alert is evidence of its own.
type Evidence struct {
	AlertID int64
	Digest  string
}

// HasEvidenceSince reports whether an alert, with the same content, already has a snapshot kept
// as its evidence among those received since the given time.
func (s *Store) HasEvidenceSince(ctx context.Context, alertID int64, digest string, since time.Time) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM snapshot_evidence ev JOIN snapshots sn ON sn.id = ev.snapshot_id
		WHERE ev.alert_id = ? AND ev.digest = ? AND sn.received_at >= ?`, alertID, digest, since.Unix()).Scan(&n)
	return n > 0, err
}

// EvidenceSnapshotsSince counts, by alert kind and severity ("kind|severity"), a host's
// snapshots kept as evidence among those received since the given time.
func (s *Store) EvidenceSnapshotsSince(ctx context.Context, host string, since time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.kind || '|' || a.severity, COUNT(DISTINCT sn.id) FROM snapshot_evidence ev
		JOIN snapshots sn ON sn.id = ev.snapshot_id JOIN alerts a ON a.id = ev.alert_id
		WHERE sn.host_id = ? AND sn.received_at >= ? GROUP BY a.kind, a.severity`, host, since.Unix())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			return nil, err
		}
		out[kind] = n
	}
	return out, rows.Err()
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

// SnapshotBefore returns the snapshot of a host that precedes id.
func (s *Store) SnapshotBefore(ctx context.Context, host string, id int64) (Snapshot, error) {
	return s.snapshot(ctx, `WHERE host_id = ? AND id < ? ORDER BY id DESC LIMIT 1`, host, id)
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

// Alive records that a host reached the verifier over mutual TLS with its certificate, even if
// its envelope could not be taken yet (snapshot over the rate, verifier busy): the sensor is
// running, and must not look silent while its pending snapshot waits.
func (s *Store) Alive(ctx context.Context, host string, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE hosts SET last_seen = ?, last_heartbeat = ? WHERE id = ?`, now.Unix(), now.Unix(), host); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO activity (host_id, minute, kind) VALUES (?, ?, ?)`, host, now.Unix()/60, string(protocol.KindHeartbeat))
	return err
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
