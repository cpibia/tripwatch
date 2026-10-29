package store

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP is HMAC-SHA1, what every authenticator app computes
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TOTP as authenticator apps compute it (RFC 6238): six digits, a new code every 30 seconds.
const (
	totpStep   = 30
	totpDigits = 1000000
	// totpSkew accepts the code of the step before and after, for clocks a little apart.
	totpSkew = 1
	// recoveryCodes is how many single-use codes a user gets when turning the second factor on.
	recoveryCodes = 10
	// MaxSecondFactorFailures ends a half-open session after this many wrong codes: the password
	// must be given again. The same count, kept per user, locks the codes for SecondFactorLock.
	MaxSecondFactorFailures = 5
	// SecondFactorLock is how long a user's codes are refused once MaxSecondFactorFailures were
	// wrong in a row; every wrong code after that locks them again.
	SecondFactorLock = 15 * time.Minute
)

var (
	// ErrBadCode is returned for a wrong, reused or expired code.
	ErrBadCode = errors.New("store: wrong code")
	// ErrSecondFactorLocked is returned, without looking at the code, while a user's codes are
	// locked after too many wrong ones.
	ErrSecondFactorLocked = errors.New("store: too many wrong codes, try again later")
	// ErrSecondFactorRequired is returned for a session that still waits for its code.
	ErrSecondFactorRequired = errors.New("store: the session waits for its second factor")
	b32                     = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// totp is the code of a secret for a time step.
func totp(secret []byte, step int64) int {
	mac := hmac.New(sha1.New, secret)
	_ = binary.Write(mac, binary.BigEndian, step)
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return int(binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff) % totpDigits
}

// matchTOTP returns the step a code belongs to, within the skew, or -1.
func matchTOTP(secret, code string, now time.Time) int64 {
	key, err := b32.DecodeString(secret)
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if err != nil || len(code) != 6 {
		return -1
	}
	step := now.Unix() / totpStep
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		want := fmt.Sprintf("%06d", totp(key, step+d))
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step + d
		}
	}
	return -1
}

// BeginTOTP makes a new secret for a user, kept apart until a code from it is confirmed, so a
// setup left half way never locks anyone out.
func (s *Store) BeginTOTP(ctx context.Context, email string) (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	secret := b32.EncodeToString(raw)
	return secret, s.one(ctx, `UPDATE users SET totp_pending = ? WHERE email = ?`, secret, normalEmail(email))
}

// PendingTOTP returns the secret a user is setting up, for the code to scan.
func (s *Store) PendingTOTP(ctx context.Context, email string) (string, error) {
	var pending string
	err := s.db.QueryRowContext(ctx, `SELECT totp_pending FROM users WHERE email = ?`, normalEmail(email)).Scan(&pending)
	if err != nil || pending == "" {
		return "", ErrNotFound
	}
	return pending, nil
}

// ConfirmTOTP turns the second factor on once a code from the new secret checks out, and returns
// the single-use recovery codes, shown once: only their hashes are stored.
func (s *Store) ConfirmTOTP(ctx context.Context, email, code string, now time.Time) ([]string, error) {
	email = normalEmail(email)
	var pending string
	if err := s.db.QueryRowContext(ctx, `SELECT totp_pending FROM users WHERE email = ?`, email).Scan(&pending); err != nil {
		return nil, ErrNotFound
	}
	step := matchTOTP(pending, code, now)
	if pending == "" || step < 0 {
		return nil, ErrBadCode
	}
	codes := make([]string, recoveryCodes)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret = totp_pending, totp_pending = '', totp_last = ? WHERE email = ?`, step, email); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE email = ?`, email); err != nil {
		return nil, err
	}
	for i := range codes {
		raw := make([]byte, 6)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		h := hex.EncodeToString(raw)
		codes[i] = h[:4] + "-" + h[4:8] + "-" + h[8:]
		sum := sha256.Sum256([]byte(codes[i]))
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes (code_hash, email) VALUES (?, ?)`, sum[:], email); err != nil {
			return nil, err
		}
	}
	return codes, tx.Commit()
}

// TOTPEnabled reports whether a user signs in with a second factor.
func (s *Store) TOTPEnabled(ctx context.Context, email string) (bool, error) {
	var secret string
	err := s.db.QueryRowContext(ctx, `SELECT totp_secret FROM users WHERE email = ?`, normalEmail(email)).Scan(&secret)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	return secret != "", err
}

// RecoveryCodesLeft counts a user's unused recovery codes.
func (s *Store) RecoveryCodesLeft(ctx context.Context, email string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE email = ?`, normalEmail(email)).Scan(&n)
	return n, err
}

// DisableTOTP turns a user's second factor off, with their recovery codes and any lock.
func (s *Store) DisableTOTP(ctx context.Context, email string) error {
	email = normalEmail(email)
	if err := s.one(ctx, `UPDATE users SET totp_secret = '', totp_pending = '', totp_last = 0, mfa_failures = 0, mfa_locked_until = 0 WHERE email = ?`, email); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM recovery_codes WHERE email = ?`, email)
	return err
}

// CheckSecondFactor accepts a code from the user's app, once (a code seen before, or one older
// than the last used, is refused), or one of their recovery codes, which is then spent.
//
// Each check first takes one of the user's attempts, in a single statement, so parallel requests
// cannot check more codes than the limit allows; the count belongs to the user, not to a session,
// so signing in again with a stolen password does not start it over. Only a right code resets it.
func (s *Store) CheckSecondFactor(ctx context.Context, email, code string, now time.Time) error {
	email = normalEmail(email)
	var secret string
	var last int64
	err := s.db.QueryRowContext(ctx, `UPDATE users SET mfa_failures = mfa_failures + 1,
		mfa_locked_until = CASE WHEN mfa_failures + 1 >= ? THEN ? ELSE mfa_locked_until END
		WHERE email = ? AND mfa_locked_until <= ? RETURNING totp_secret, totp_last`,
		MaxSecondFactorFailures, now.Add(SecondFactorLock).Unix(), email, now.Unix()).Scan(&secret, &last)
	if errors.Is(err, sql.ErrNoRows) {
		if exists, _ := s.UserExists(ctx, email); exists {
			return ErrSecondFactorLocked
		}
		return ErrBadCode
	}
	if err != nil {
		return err
	}
	ok, err := s.matchSecondFactor(ctx, email, secret, last, code, now)
	if err != nil || !ok {
		if err == nil {
			err = ErrBadCode
		}
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET mfa_failures = 0, mfa_locked_until = 0 WHERE email = ?`, email)
	return err
}

func (s *Store) matchSecondFactor(ctx context.Context, email, secret string, last int64, code string, now time.Time) (bool, error) {
	if step := matchTOTP(secret, code, now); secret != "" && step > last {
		res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_last = ? WHERE email = ? AND totp_last < ?`, step, email, step)
		if err != nil {
			return false, err
		}
		n, _ := res.RowsAffected()
		return n == 1, nil
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(code))))
	res, err := s.db.ExecContext(ctx, `DELETE FROM recovery_codes WHERE code_hash = ? AND email = ?`, sum[:], email)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// CompleteSecondFactor lets a half-open session through once its code checked out.
func (s *Store) CompleteSecondFactor(ctx context.Context, token string) error {
	sum := sha256.Sum256([]byte(token))
	return s.one(ctx, `UPDATE sessions SET mfa_pending = 0, mfa_failures = 0 WHERE token_hash = ?`, sum[:])
}

// FailSecondFactor counts a wrong code for a half-open session and ends it past the limit. It
// reports whether the session is still there.
func (s *Store) FailSecondFactor(ctx context.Context, token string) (bool, error) {
	sum := sha256.Sum256([]byte(token))
	if _, err := s.db.ExecContext(ctx, `UPDATE sessions SET mfa_failures = mfa_failures + 1 WHERE token_hash = ?`, sum[:]); err != nil {
		return false, err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ? AND mfa_failures >= ?`, sum[:], MaxSecondFactorFailures)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 0, nil
}

// SessionInfo describes one of a user's sessions, for them to recognise and end.
type SessionInfo struct {
	// ID is the hash of the session's token: it names the session without being able to open it.
	ID        string
	CreatedAt time.Time
	LastSeen  time.Time
	Agent     string
	Current   bool
}

// UserSessions lists a user's open sessions, the most recently used first.
func (s *Store) UserSessions(ctx context.Context, email, currentToken string, now time.Time) ([]SessionInfo, error) {
	current := sha256.Sum256([]byte(currentToken))
	rows, err := s.db.QueryContext(ctx, `SELECT token_hash, created_at, last_seen, agent FROM sessions
		WHERE email = ? AND expires_at > ? AND mfa_pending = 0 ORDER BY last_seen DESC`, normalEmail(email), now.Unix())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SessionInfo
	for rows.Next() {
		var hash []byte
		var created, seen int64
		var si SessionInfo
		if err := rows.Scan(&hash, &created, &seen, &si.Agent); err != nil {
			return nil, err
		}
		si.ID, si.CreatedAt, si.LastSeen, si.Current = hex.EncodeToString(hash), unix(created), unix(seen), subtle.ConstantTimeCompare(hash, current[:]) == 1
		out = append(out, si)
	}
	return out, rows.Err()
}

// EndSession closes one of a user's sessions, named by its ID.
func (s *Store) EndSession(ctx context.Context, email, id string) error {
	hash, err := hex.DecodeString(id)
	if err != nil {
		return ErrNotFound
	}
	return s.one(ctx, `DELETE FROM sessions WHERE token_hash = ? AND email = ?`, hash, normalEmail(email))
}

// EndOtherSessions closes every session of a user but the one of keepToken (all of them for an
// empty one): after the second factor changes, a session opened without it must not stay.
func (s *Store) EndOtherSessions(ctx context.Context, email, keepToken string) error {
	keep := sha256.Sum256([]byte(keepToken))
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE email = ? AND token_hash != ?`, normalEmail(email), keep[:])
	return err
}

// touchEvery bounds how often a session's last use is written.
const touchEvery = time.Minute

// TouchSession records that a session was used, and from which browser.
func (s *Store) TouchSession(ctx context.Context, token, agent string, now time.Time) error {
	sum := sha256.Sum256([]byte(token))
	if len(agent) > 200 {
		agent = strings.ToValidUTF8(agent[:200], "")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen = ?, agent = ? WHERE token_hash = ? AND last_seen < ?`,
		now.Unix(), agent, sum[:], now.Add(-touchEvery).Unix())
	return err
}
