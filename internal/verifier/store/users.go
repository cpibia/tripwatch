package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// SessionLifetime bounds how long a login lasts.
const SessionLifetime = 12 * time.Hour

var ErrBadCredentials = errors.New("store: wrong email or password")

// dummyHash is compared against when the email is unknown, so that a login takes as long
// whether or not the user exists.
var dummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("tripwatch-timing-equaliser"), bcrypt.DefaultCost)
	return h
})

// SetUser creates a user or replaces their password.
func (s *Store) SetUser(ctx context.Context, email, password string, now time.Time) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)
		ON CONFLICT(email) DO UPDATE SET password_hash = excluded.password_hash`, email, hash, now.Unix())
	if err == nil {
		// A new password ends every existing session of that user, and forgets its devices.
		_, err = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE email = ?`, email)
	}
	if err == nil {
		_, err = s.db.ExecContext(ctx, `DELETE FROM devices WHERE email = ?`, email)
	}
	return err
}

// UserExists reports whether an email belongs to a user.
func (s *Store) UserExists(ctx context.Context, email string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE email = ?`, email).Scan(&n)
	return n > 0, err
}

// DeviceLifetime is how long a browser that signed in stays known.
const DeviceLifetime = 365 * 24 * time.Hour

// CreateDevice remembers a browser a user signed in from. The token is returned once; only its
// hash is stored.
func (s *Store) CreateDevice(ctx context.Context, email string, now time.Time) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	_, err := s.db.ExecContext(ctx, `INSERT INTO devices (token_hash, email, expires_at) VALUES (?, ?, ?)`, sum[:], email, now.Add(DeviceLifetime).Unix())
	return token, err
}

// DeviceEmail returns the user a device token belongs to.
func (s *Store) DeviceEmail(ctx context.Context, token string, now time.Time) (string, error) {
	sum := sha256.Sum256([]byte(token))
	var email string
	err := s.db.QueryRowContext(ctx, `SELECT email FROM devices WHERE token_hash = ? AND expires_at > ?`, sum[:], now.Unix()).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return email, err
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// Login checks the password and opens a session. The token is returned once; only its hash is
// stored, so a copy of the database does not hand out live sessions.
func (s *Store) Login(ctx context.Context, email, password string, now time.Time) (string, error) {
	var hash []byte
	err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE email = ?`, email).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		// Compare anyway, so that timing does not tell which emails exist.
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(password))
		return "", ErrBadCredentials
	}
	if err != nil {
		return "", err
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil {
		return "", ErrBadCredentials
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, email, expires_at) VALUES (?, ?, ?)`, sum[:], email, now.Add(SessionLifetime).Unix())
	return token, err
}

// Session returns the user of a valid session token.
func (s *Store) Session(ctx context.Context, token string, now time.Time) (string, error) {
	sum := sha256.Sum256([]byte(token))
	var email string
	err := s.db.QueryRowContext(ctx, `SELECT email FROM sessions WHERE token_hash = ? AND expires_at > ?`, sum[:], now.Unix()).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return email, err
}

func (s *Store) Logout(ctx context.Context, token string) error {
	sum := sha256.Sum256([]byte(token))
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, sum[:])
	return err
}
