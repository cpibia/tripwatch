package store

import (
	"context"
	"encoding/json"
	"time"
)

// Events reported in real time are kept for EventRetention, and at most MaxEventsPerDay of one
// host in 24 hours: beyond that they are counted, not stored, so a host flooding events cannot
// fill the disk, and what it stored first, the start of an intrusion, is never pushed out.
const (
	EventRetention  = 7 * 24 * time.Hour
	MaxEventsPerDay = 20000
	maxEventData    = 4 << 10
)

// Event is one change a sensor reported as it happened. Data is the event as the sensor sent it,
// bounded; everything in it comes from the host.
type Event struct {
	ID             int64
	HostID         string
	Seq            uint64
	At             time.Time
	ReceivedAt     time.Time
	Class          string
	Op             string
	Path           string
	PackageManager bool
	Data           json.RawMessage
}

// AddEvents stores the events of one envelope and drops those of the host past their retention.
// It returns how many it stored: fewer than given once the host is over its daily quota.
func (s *Store) AddEvents(ctx context.Context, events []Event, now time.Time) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	host := events[0].HostID
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE host_id = ? AND received_at < ?`, host, now.Add(-EventRetention).Unix()); err != nil {
		return 0, err
	}
	var today int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE host_id = ? AND received_at >= ?`, host, now.Add(-24*time.Hour).Unix()).Scan(&today); err != nil {
		return 0, err
	}
	stored := 0
	for _, e := range events {
		if today+stored >= MaxEventsPerDay {
			break
		}
		data := e.Data
		if len(data) > maxEventData {
			data = json.RawMessage(`{"truncated":true}`)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO events (host_id, seq, at, received_at, class, op, path, package_manager, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			host, e.Seq, e.At.Unix(), now.Unix(), clip(e.Class, 32), clip(e.Op, 32), clip(e.Path, 4096), e.PackageManager, string(data)); err != nil {
			return 0, err
		}
		stored++
	}
	return stored, tx.Commit()
}

// PathEvents returns the events of a host on path since a time, oldest first.
func (s *Store) PathEvents(ctx context.Context, host, path string, since time.Time) ([]Event, error) {
	return s.events(ctx, `SELECT id, host_id, seq, at, received_at, class, op, path, package_manager, data FROM events
		WHERE host_id = ? AND path = ? AND at >= ? ORDER BY at, id LIMIT 200`, host, path, since.Unix())
}

// HostEvents returns the latest events of a host, newest first.
func (s *Store) HostEvents(ctx context.Context, host string, limit int) ([]Event, error) {
	return s.events(ctx, `SELECT id, host_id, seq, at, received_at, class, op, path, package_manager, data FROM events
		WHERE host_id = ? ORDER BY id DESC LIMIT ?`, host, limit)
}

func (s *Store) events(ctx context.Context, q string, args ...any) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Event
	for rows.Next() {
		var e Event
		var at, received int64
		var data string
		if err := rows.Scan(&e.ID, &e.HostID, &e.Seq, &at, &received, &e.Class, &e.Op, &e.Path, &e.PackageManager, &data); err != nil {
			return nil, err
		}
		e.At, e.ReceivedAt, e.Data = unix(at), unix(received), json.RawMessage(data)
		out = append(out, e)
	}
	return out, rows.Err()
}
