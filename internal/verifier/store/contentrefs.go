package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// ContentRef is the published content of one release of a public component: for each path
// under the component's root, the SHA-256 of its files. Missing says the source has no such
// release, remembered so that it is not asked again at every snapshot.
type ContentRef struct {
	Ecosystem, Slug, Version string
	Missing                  bool
	Files                    map[string][]string
	FetchedAt                time.Time
}

// MaxContentRefBytes bounds the references kept, compressed: past it the least recently used
// releases go first. A variable for the tests.
var MaxContentRefBytes int64 = 2 << 30

// maxContentRefFiles bounds what one stored reference decompresses to.
const maxContentRefFiles = 64 << 20

// ContentRef returns the reference of a release, and ok false when none is kept.
func (s *Store) ContentRef(ctx context.Context, ecosystem, slug, version string, now time.Time) (ContentRef, bool, error) {
	ref := ContentRef{Ecosystem: ecosystem, Slug: slug, Version: version}
	var missing int
	var files []byte
	var fetched int64
	err := s.db.QueryRowContext(ctx, `SELECT missing, files, fetched_at FROM content_refs WHERE ecosystem = ? AND slug = ? AND version = ?`,
		ecosystem, slug, version).Scan(&missing, &files, &fetched)
	if errors.Is(err, sql.ErrNoRows) {
		return ref, false, nil
	}
	if err != nil {
		return ref, false, err
	}
	ref.Missing, ref.FetchedAt = missing != 0, unix(fetched)
	if !ref.Missing {
		zr, err := gzip.NewReader(bytes.NewReader(files))
		if err != nil {
			return ref, false, err
		}
		raw, err := io.ReadAll(io.LimitReader(zr, maxContentRefFiles+1))
		if err != nil {
			return ref, false, err
		}
		if len(raw) > maxContentRefFiles {
			return ref, false, errors.New("content reference larger than its bound")
		}
		if err := json.Unmarshal(raw, &ref.Files); err != nil {
			return ref, false, err
		}
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE content_refs SET used_at = ? WHERE ecosystem = ? AND slug = ? AND version = ?`,
		now.Unix(), ecosystem, slug, version); err != nil {
		return ref, false, err
	}
	return ref, true, nil
}

// PutContentRef keeps a reference, then drops the least recently used ones past
// MaxContentRefBytes.
func (s *Store) PutContentRef(ctx context.Context, ref ContentRef, now time.Time) error {
	var buf bytes.Buffer
	if !ref.Missing {
		raw, err := json.Marshal(ref.Files)
		if err != nil {
			return err
		}
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(raw); err != nil {
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
	}
	missing := 0
	if ref.Missing {
		missing = 1
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO content_refs (ecosystem, slug, version, missing, files, size, fetched_at, used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (ecosystem, slug, version) DO UPDATE SET missing = excluded.missing, files = excluded.files, size = excluded.size,
		fetched_at = excluded.fetched_at, used_at = excluded.used_at`,
		ref.Ecosystem, ref.Slug, ref.Version, missing, append([]byte{}, buf.Bytes()...), buf.Len(), now.Unix(), now.Unix()); err != nil {
		return err
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(size), 0) FROM content_refs`).Scan(&total); err != nil {
		return err
	}
	for total > MaxContentRefBytes {
		var eco, slug, version string
		var size int64
		err := s.db.QueryRowContext(ctx, `SELECT ecosystem, slug, version, size FROM content_refs ORDER BY used_at, fetched_at LIMIT 1`).Scan(&eco, &slug, &version, &size)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM content_refs WHERE ecosystem = ? AND slug = ? AND version = ?`, eco, slug, version); err != nil {
			return err
		}
		total -= max(size, 1)
	}
	return nil
}
