package store

import (
	"context"
	"encoding/json"
	"time"
)

// Events reported in real time are kept for EventRetention, and at most MaxEventsPerDay of one
// host in 24 hours in each of three budgets: one for what the web server's user can produce at
// will (uploads and process starts), one for the homes and crontabs of accounts other than root,
// MaxOwnerEventsPerDay of them for each account, and one for system paths only root can change.
// Beyond that they are counted, not stored, so a host flooding events cannot fill the disk, what
// it stored first is never pushed out, and no account but root can use up the budget of root's
// changes.
const (
	EventRetention       = 7 * 24 * time.Hour
	MaxEventsPerDay      = 20000
	MaxOwnerEventsPerDay = 2000
	maxEventData         = 4 << 10
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
	// Owner is the account other than root whose home or crontab the path is in, as the sensor
	// says.
	Owner string
	Data  json.RawMessage
}

// noisyClasses are the event classes the web server's user can produce; they have a budget of
// their own.
const noisyClasses = `'upload', 'exec', 'scratch'`

func noisy(class string) bool { return class == "upload" || class == "exec" || class == "scratch" }

// AddEvents stores the events of one envelope and drops those of the host past their retention.
// It returns which events it stored: not those over the host's daily quota for their kind.
func (s *Store) AddEvents(ctx context.Context, events []Event, now time.Time) ([]bool, error) {
	kept := make([]bool, len(events))
	if len(events) == 0 {
		return kept, nil
	}
	host := events[0].HostID
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE host_id = ? AND received_at < ?`, host, now.Add(-EventRetention).Unix()); err != nil {
		return nil, err
	}
	since := now.Add(-24 * time.Hour).Unix()
	var noise, users, system int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(class IN (`+noisyClasses+`)), 0),
		COALESCE(SUM(class NOT IN (`+noisyClasses+`) AND owner != ''), 0), COALESCE(SUM(class NOT IN (`+noisyClasses+`) AND owner = ''), 0)
		FROM events WHERE host_id = ? AND received_at >= ?`, host, since).Scan(&noise, &users, &system); err != nil {
		return nil, err
	}
	owners := map[string]int{}
	for i, e := range events {
		e.Owner = clip(e.Owner, 64)
		count := &system
		switch {
		case noisy(e.Class):
			count = &noise
		case e.Owner != "":
			count = &users
			n, ok := owners[e.Owner]
			if !ok {
				if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE host_id = ? AND owner = ? AND received_at >= ? AND class NOT IN (`+noisyClasses+`)`,
					host, e.Owner, since).Scan(&n); err != nil {
					return nil, err
				}
			}
			if n >= MaxOwnerEventsPerDay {
				owners[e.Owner] = n
				continue
			}
			owners[e.Owner] = n + 1
		}
		if *count >= MaxEventsPerDay {
			continue
		}
		data := e.Data
		if len(data) > maxEventData {
			data = json.RawMessage(`{"truncated":true}`)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO events (host_id, seq, at, received_at, class, op, path, package_manager, owner, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			host, e.Seq, e.At.Unix(), now.Unix(), clip(e.Class, 32), clip(e.Op, 32), clip(e.Path, 4096), e.PackageManager, e.Owner, string(data)); err != nil {
			return nil, err
		}
		*count++
		kept[i] = true
	}
	return kept, tx.Commit()
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
