package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/webauthn"
)

const (
	// ChallengeLifetime bounds how long a security key prompt may stay open.
	ChallengeLifetime = 5 * time.Minute
	// MaxSecurityKeys bounds the keys of a user: each is a row and a sign-in option.
	MaxSecurityKeys = 10
	// Challenge purposes: one of each may wait per session.
	PurposeRegister = "register"
	PurposeAssert   = "assert"
)

var (
	// ErrClonedKey is returned when a key's signature counter did not move forward: another
	// copy of the key signed in since, or this is the copy.
	ErrClonedKey = errors.New("store: the security key's counter went back")
	// ErrTooManyKeys is returned past MaxSecurityKeys.
	ErrTooManyKeys = errors.New("store: too many security keys")
	// ErrKeyExists is returned for a credential registered already.
	ErrKeyExists = errors.New("store: security key registered already")
	// ErrNoChallenge is returned when the prompt expired, was used, or was never given.
	ErrNoChallenge = errors.New("store: no security key prompt waiting")
	// ErrKeyRefused wraps the reason the webauthn checks refused a browser's answer, so callers
	// tell a refused answer from a failing database.
	ErrKeyRefused = errors.New("store: security key answer refused")
)

// SecurityKey is one of a user's WebAuthn credentials, as listed to them.
type SecurityKey struct {
	// ID is the credential ID, base64url, as browsers name it.
	ID           string
	Name         string
	Alg          int
	UserVerified bool
	CreatedAt    time.Time
	LastUsed     time.Time
}

// NewChallenge makes the random challenge of a security key prompt for a session, replacing
// one left from an earlier page: each is single use and bound to the session it was given to.
func (s *Store) NewChallenge(ctx context.Context, token, purpose string, now time.Time) ([]byte, error) {
	c := make([]byte, webauthn.ChallengeSize)
	if _, err := rand.Read(c); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(token))
	_, err := s.db.ExecContext(ctx, `INSERT INTO webauthn_challenges (token_hash, purpose, challenge, expires_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (token_hash, purpose) DO UPDATE SET challenge = excluded.challenge, expires_at = excluded.expires_at`,
		sum[:], purpose, c, now.Add(ChallengeLifetime).Unix())
	return c, err
}

// takeChallenge spends a session's challenge, so a response is checked against it once.
func (s *Store) takeChallenge(ctx context.Context, token, purpose string, now time.Time) ([]byte, error) {
	sum := sha256.Sum256([]byte(token))
	var c []byte
	var fresh bool
	err := s.db.QueryRowContext(ctx, `DELETE FROM webauthn_challenges WHERE token_hash = ? AND purpose = ? RETURNING challenge, expires_at > ?`,
		sum[:], purpose, now.Unix()).Scan(&c, &fresh)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !fresh) {
		return nil, ErrNoChallenge
	}
	return c, err
}

// SecurityKeys lists a user's keys, the oldest first.
func (s *Store) SecurityKeys(ctx context.Context, email string) ([]SecurityKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, alg, user_verified, created_at, last_used FROM webauthn_credentials
		WHERE email = ? ORDER BY created_at, rowid`, normalEmail(email))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SecurityKey
	for rows.Next() {
		var id []byte
		var created, used int64
		var k SecurityKey
		if err := rows.Scan(&id, &k.Name, &k.Alg, &k.UserVerified, &created, &used); err != nil {
			return nil, err
		}
		k.ID, k.CreatedAt, k.LastUsed = base64.RawURLEncoding.EncodeToString(id), unix(created), unix(used)
		out = append(out, k)
	}
	return out, rows.Err()
}

// KeyRef names a key to the browser: its credential ID, base64url, and how it is reached.
type KeyRef struct {
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

// SecurityKeyRefs returns a user's keys as the browser is asked for one of them at sign-in.
func (s *Store) SecurityKeyRefs(ctx context.Context, email string) ([]KeyRef, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, transports FROM webauthn_credentials WHERE email = ? ORDER BY created_at, rowid`, normalEmail(email))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []KeyRef
	for rows.Next() {
		var id []byte
		var transports string
		if err := rows.Scan(&id, &transports); err != nil {
			return nil, err
		}
		ref := KeyRef{ID: base64.RawURLEncoding.EncodeToString(id)}
		if transports != "" {
			ref.Transports = strings.Split(transports, ",")
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}

// AddSecurityKey checks a browser's answer to the registration prompt of a session and stores
// the new key. For a user with no second factor yet it returns the recovery codes, shown once.
func (s *Store) AddSecurityKey(ctx context.Context, rp webauthn.RelyingParty, email, token, name, transports string, clientData, attestation []byte, now time.Time) ([]string, error) {
	email = normalEmail(email)
	challenge, err := s.takeChallenge(ctx, token, PurposeRegister, now)
	if err != nil {
		return nil, err
	}
	reg, err := rp.VerifyRegistration(challenge, clientData, attestation)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyRefused, err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var have int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM webauthn_credentials WHERE email = ?`, email).Scan(&have); err != nil {
		return nil, err
	}
	if have >= MaxSecurityKeys {
		return nil, ErrTooManyKeys
	}
	first, err := noSecondFactor(ctx, tx, email)
	if err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO webauthn_credentials (id, email, name, public_key, alg, sign_count, transports, user_verified, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING`,
		reg.CredentialID, email, KeyName(name), reg.PublicKey, reg.Alg, reg.SignCount, keyTransports(transports), reg.UserVerified, now.Unix())
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrKeyExists
	}
	var codes []string
	if first {
		if codes, err = issueRecoveryCodes(ctx, tx, email); err != nil {
			return nil, err
		}
	}
	return codes, tx.Commit()
}

// KeyName is the name a key is stored under: trimmed, bounded, and never empty.
func KeyName(name string) string {
	name = strings.Join(strings.Fields(name), " ")
	if len(name) > 60 {
		name = strings.ToValidUTF8(name[:60], "")
	}
	if name == "" {
		return "Security key"
	}
	return name
}

// keyTransports keeps the transports a browser reported that the specification names, so the
// list handed back to browsers at sign-in holds nothing else.
func keyTransports(reported string) string {
	var out []string
	for _, t := range strings.Split(reported, ",") {
		switch t = strings.TrimSpace(t); t {
		case "usb", "nfc", "ble", "internal", "hybrid", "smart-card":
			if !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
	}
	return strings.Join(out, ",")
}

// RemoveSecurityKey deletes one of a user's keys. When it was their last second factor, the
// recovery codes and any lock go with it.
func (s *Store) RemoveSecurityKey(ctx context.Context, email, id string) (string, error) {
	email = normalEmail(email)
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(raw) == 0 || len(raw) > webauthn.MaxCredentialID {
		return "", ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	var name string
	err = tx.QueryRowContext(ctx, `DELETE FROM webauthn_credentials WHERE id = ? AND email = ? RETURNING name`, raw, email).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if err := dropCodesIfNoFactor(ctx, tx, email); err != nil {
		return "", err
	}
	return name, tx.Commit()
}

// CheckSecurityKey checks a browser's answer to the sign-in prompt of a session: the challenge
// given to that session, a key of this user, its signature, and a counter that moved forward.
// It spends one of the user's attempts as a code does, so keys and codes share one limit, and
// returns the key's name.
func (s *Store) CheckSecurityKey(ctx context.Context, rp webauthn.RelyingParty, email, token string, credentialID, clientData, authData, signature []byte, now time.Time) (string, error) {
	email = normalEmail(email)
	if _, _, err := s.takeAttempt(ctx, email, now); err != nil {
		return "", err
	}
	challenge, err := s.takeChallenge(ctx, token, PurposeAssert, now)
	if err != nil {
		return "", err
	}
	if len(credentialID) == 0 || len(credentialID) > webauthn.MaxCredentialID {
		return "", ErrBadCode
	}
	var key []byte
	var stored int64
	var name string
	err = s.db.QueryRowContext(ctx, `SELECT public_key, sign_count, name FROM webauthn_credentials WHERE id = ? AND email = ?`,
		credentialID, email).Scan(&key, &stored, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrBadCode
	}
	if err != nil {
		return "", err
	}
	got, err := rp.VerifyAssertion(challenge, key, clientData, authData, signature)
	if err != nil {
		return name, fmt.Errorf("%w: %w", ErrKeyRefused, err)
	}
	// Keys that keep no counter send zero every time; any other must go up. A key that counted
	// once and now answers zero is refused too: a copy would otherwise skip the check by
	// claiming it keeps no counter. The condition is in the statement, so two answers racing
	// cannot both pass with the same count.
	res, err := s.db.ExecContext(ctx, `UPDATE webauthn_credentials SET sign_count = ?, last_used = ?, user_verified = ?
		WHERE id = ? AND email = ? AND ((sign_count = 0 AND ? = 0) OR sign_count < ?)`,
		got.SignCount, now.Unix(), got.UserVerified, credentialID, email, got.SignCount, got.SignCount)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return name, ErrClonedKey
	}
	return name, s.clearAttempts(ctx, email)
}
