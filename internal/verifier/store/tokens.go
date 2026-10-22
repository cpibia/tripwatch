package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
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
		ON CONFLICT(host_id) DO UPDATE SET token_hash = excluded.token_hash, created_by = excluded.created_by, expires_at = excluded.expires_at, used_at = 0`,
		host, sum[:], by, expires.Unix())
	return secret, expires, err
}

// ErrTokenReused is returned for a token that was already used: someone else holds a copy.
var ErrTokenReused = errors.New("store: enrollment token already used")

// ConsumeEnrollToken checks a secret and marks it used in the same step, so it works once. It
// returns the host the token was made for and who made it. A used token is kept, until the
// host gets a new one, so that presenting it again names the host it was for.
func (s *Store) ConsumeEnrollToken(ctx context.Context, secret string, now time.Time) (string, string, error) {
	sum := sha256.Sum256([]byte(secret))
	var host, by string
	err := s.db.QueryRowContext(ctx, `UPDATE enroll_tokens SET used_at = ? WHERE token_hash = ? AND used_at = 0 AND expires_at > ?
		RETURNING host_id, created_by`, now.Unix(), sum[:], now.Unix()).Scan(&host, &by)
	if err == nil {
		return host, by, nil
	}
	if err := s.db.QueryRowContext(ctx, `SELECT host_id, created_by FROM enroll_tokens WHERE token_hash = ? AND used_at > 0`, sum[:]).Scan(&host, &by); err == nil {
		return host, by, ErrTokenReused
	}
	return "", "", ErrNotFound
}
