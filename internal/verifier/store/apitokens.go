package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// APITokenPrefix starts every API token, so a leaked one is easy to recognise and to search for.
const APITokenPrefix = "twk_"

// maxAPITokens bounds the tokens kept.
const maxAPITokens = 50

// APIToken is a token programs use to read the console's data, and with Write to handle
// alerts. It acts as its owner: their role and the servers they may see.
type APIToken struct {
	ID        int64
	Name      string
	Owner     string
	Write     bool
	CreatedAt time.Time
	ExpiresAt time.Time
	LastUsed  time.Time
}

// CreateAPIToken makes a token; it is returned once, only its hash is stored.
func (s *Store) CreateAPIToken(ctx context.Context, name, owner string, write bool, lifetime time.Duration, now time.Time) (string, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_tokens`).Scan(&n); err != nil {
		return "", err
	}
	if n >= maxAPITokens {
		return "", errors.New("store: too many API tokens")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := APITokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	_, err := s.db.ExecContext(ctx, `INSERT INTO api_tokens (token_hash, name, owner, write, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		sum[:], name, normalEmail(owner), write, now.Unix(), now.Add(lifetime).Unix())
	return token, err
}

// APITokens lists the tokens, newest first.
func (s *Store) APITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, owner, write, created_at, expires_at, last_used FROM api_tokens ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		var created, expires, used int64
		if err := rows.Scan(&t.ID, &t.Name, &t.Owner, &t.Write, &created, &expires, &used); err != nil {
			return nil, err
		}
		t.CreatedAt, t.ExpiresAt, t.LastUsed = unix(created), unix(expires), unix(used)
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken deletes a token.
func (s *Store) RevokeAPIToken(ctx context.Context, id int64) error {
	return s.one(ctx, `DELETE FROM api_tokens WHERE id = ?`, id)
}

// UseAPIToken checks a token and records its use. Tokens of users since removed stop working.
func (s *Store) UseAPIToken(ctx context.Context, token string, now time.Time) (APIToken, error) {
	if !strings.HasPrefix(token, APITokenPrefix) {
		return APIToken{}, ErrNotFound
	}
	sum := sha256.Sum256([]byte(token))
	var t APIToken
	err := s.db.QueryRowContext(ctx, `SELECT t.id, t.name, t.owner, t.write FROM api_tokens t JOIN users u ON u.email = t.owner
		WHERE t.token_hash = ? AND t.expires_at > ?`, sum[:], now.Unix()).Scan(&t.ID, &t.Name, &t.Owner, &t.Write)
	if errors.Is(err, sql.ErrNoRows) {
		return APIToken{}, ErrNotFound
	}
	if err != nil {
		return APIToken{}, err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used = ? WHERE id = ? AND last_used < ?`, now.Unix(), t.ID, now.Add(-time.Minute).Unix())
	return t, err
}
