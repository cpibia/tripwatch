package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"
)

// EnrollTokenLifetime bounds how long a token waits to be used.
const EnrollTokenLifetime = time.Hour

// CreateEnrollToken returns a one-time secret that enrolls host. Only its hash is stored, and a
// new token for the same host replaces the previous one.
func (s *Store) CreateEnrollToken(ctx context.Context, host, by string, now time.Time) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))
	expires := now.Add(EnrollTokenLifetime)
	_, err := s.db.ExecContext(ctx, `INSERT INTO enroll_tokens (host_id, token_hash, created_by, expires_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(host_id) DO UPDATE SET token_hash = excluded.token_hash, created_by = excluded.created_by, expires_at = excluded.expires_at`,
		host, sum[:], by, expires.Unix())
	return secret, expires, err
}

// ConsumeEnrollToken checks a secret and deletes it in the same step, so it works once. It
// returns the host the token was made for and who made it.
func (s *Store) ConsumeEnrollToken(ctx context.Context, secret string, now time.Time) (string, string, error) {
	sum := sha256.Sum256([]byte(secret))
	var host, by string
	err := s.db.QueryRowContext(ctx, `DELETE FROM enroll_tokens WHERE token_hash = ? AND expires_at > ? RETURNING host_id, created_by`,
		sum[:], now.Unix()).Scan(&host, &by)
	if err != nil {
		return "", "", ErrNotFound
	}
	return host, by, nil
}
