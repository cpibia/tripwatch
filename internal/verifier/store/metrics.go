package store

import (
	"context"
	"database/sql"
	"time"
)

// Backlog is the analysis queue: snapshots stored and not yet analysed, and since when the
// oldest of them waits.
type Backlog struct {
	Pending int
	Oldest  time.Time
}

// AnalysisBacklog returns the snapshots waiting for analysis, through the pending index.
func (s *Store) AnalysisBacklog(ctx context.Context) (Backlog, error) {
	var b Backlog
	var oldest sql.NullInt64
	err := s.read.QueryRowContext(ctx, `SELECT COUNT(*), MIN(received_at) FROM snapshots WHERE analyzed = 0`).Scan(&b.Pending, &oldest)
	if oldest.Valid {
		b.Oldest = unix(oldest.Int64)
	}
	return b, err
}

// Size returns the bytes the database takes, free pages included: what the disk holds.
func (s *Store) Size(ctx context.Context) (int64, error) {
	var pages, size int64
	if err := s.read.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pages); err != nil {
		return 0, err
	}
	if err := s.read.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&size); err != nil {
		return 0, err
	}
	return pages * size, nil
}
