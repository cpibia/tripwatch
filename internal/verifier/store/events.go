package store

import (
	"context"
	"encoding/json"
	"strings"
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
	maxBatchOwners       = 64
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
	// One pass over the host's day, whatever the number of accounts in the batch: a count per
	// account would let a sensor naming a thousand of them hold the database for seconds.
	inBatch := map[string]bool{}
	for i := range events {
		events[i].Owner = clip(events[i].Owner, 64)
		if !noisy(events[i].Class) && events[i].Owner != "" {
			inBatch[events[i].Owner] = true
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT class IN (`+noisyClasses+`), owner, COUNT(*) FROM events
		WHERE host_id = ? AND received_at >= ? GROUP BY 1, 2`, host, now.Add(-24*time.Hour).Unix())
	if err != nil {
		return nil, err
	}
	var noise, users, system int
	owners := map[string]int{}
	for rows.Next() {
		var isNoise bool
		var owner string
		var n int
		if err := rows.Scan(&isNoise, &owner, &n); err != nil {
			_ = rows.Close()
			return nil, err
		}
		switch {
		case isNoise:
			noise += n
		case owner == "":
			system += n
		default:
			users += n
			if inBatch[owner] {
				owners[owner] = n
			}
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	fresh := 0
	for i, e := range events {
		count := &system
		switch {
		case noisy(e.Class):
			count = &noise
		case e.Owner != "":
			count = &users
			n, ok := owners[e.Owner]
			if !ok {
				// A sensor sends the few accounts of its host; one naming more in a batch is not
				// an intact sensor, and its extra accounts are not kept.
				if fresh >= maxBatchOwners {
					continue
				}
				fresh++
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

// HostEventsBetween returns a host's events in a time interval, oldest first, at most limit.
func (s *Store) HostEventsBetween(ctx context.Context, host string, from, to time.Time, limit int) ([]Event, error) {
	return s.events(ctx, `SELECT id, host_id, seq, at, received_at, class, op, path, package_manager, data FROM events
		WHERE host_id = ? AND at >= ? AND at <= ? ORDER BY at, id LIMIT ?`, host, from.Unix(), to.Unix(), limit)
}

// SearchEvents returns the latest events, of every host, whose path or report contains text,
// ignoring the case of ASCII letters: what the console's search finds among the changes seen as
// they happened.
func (s *Store) SearchEvents(ctx context.Context, text string, limit int) ([]Event, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}
	like := likePattern(strings.ToValidUTF8(text[:min(len(text), maxQueryLen)], ""))
	scope, args := scopeClause(ctx, "host_id")
	return s.events(ctx, `SELECT id, host_id, seq, at, received_at, class, op, path, package_manager, data FROM events
		WHERE (path LIKE ? ESCAPE '\' OR data LIKE ? ESCAPE '\')`+scope+` ORDER BY id DESC LIMIT ?`, append(append([]any{like, like}, args...), limit)...)
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
