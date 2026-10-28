package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// UpdateOrder is the signed order for the sensors to install a release, as the verifier gives it
// to each sensor in its answers. There is one at most: a newer order replaces it.
type UpdateOrder struct {
	Version   string
	Payload   string
	Signature string
	OrderedBy string
	OrderedAt time.Time
}

// SetUpdateOrder records the order the sensors are given from now on.
func (s *Store) SetUpdateOrder(ctx context.Context, o UpdateOrder) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO update_order (id, version, payload, signature, ordered_by, ordered_at) VALUES (1, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET version = excluded.version, payload = excluded.payload, signature = excluded.signature,
		ordered_by = excluded.ordered_by, ordered_at = excluded.ordered_at`, o.Version, o.Payload, o.Signature, o.OrderedBy, o.OrderedAt.Unix())
	return err
}

// CurrentUpdateOrder returns the order in force, or ok false when none was given.
func (s *Store) CurrentUpdateOrder(ctx context.Context) (o UpdateOrder, ok bool, err error) {
	var at int64
	err = s.db.QueryRowContext(ctx, `SELECT version, payload, signature, ordered_by, ordered_at FROM update_order WHERE id = 1`).
		Scan(&o.Version, &o.Payload, &o.Signature, &o.OrderedBy, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return o, false, nil
	}
	if err != nil {
		return o, false, err
	}
	o.OrderedAt = unix(at)
	return o, true, nil
}
