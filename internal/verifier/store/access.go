package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"slices"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Roles, from the one that can do least: a viewer reads, an operator also handles alerts, an
// administrator also changes how the verifier works (servers, notifications, users).
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// Roles lists the roles in order of what they can do.
var Roles = []string{RoleViewer, RoleOperator, RoleAdmin}

// RoleAtLeast reports whether role can do what least can.
func RoleAtLeast(role, least string) bool {
	return slices.Index(Roles, role) >= slices.Index(Roles, least) && slices.Contains(Roles, role)
}

// ErrLastAdmin is returned by a change that would leave no administrator.
var ErrLastAdmin = errors.New("store: the last administrator cannot be removed or demoted")

// User is a person who signs in to the console.
type User struct {
	Email     string
	Role      string
	CreatedAt time.Time
	// Scope is the label a user's servers carry: they see only those. Empty sees every server,
	// and administrators always do.
	Scope string
}

// SetScope limits what a user sees to the servers carrying a label; empty lifts the limit.
func (s *Store) SetScope(ctx context.Context, email, label string) error {
	return s.one(ctx, `UPDATE users SET scope = ? WHERE email = ?`, label, normalEmail(email))
}

// UserAccess returns a user's role and scope; an administrator's scope is always empty.
func (s *Store) UserAccess(ctx context.Context, email string) (role, scope string, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT role, scope FROM users WHERE email = ?`, normalEmail(email)).Scan(&role, &scope)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if role == RoleAdmin {
		scope = ""
	}
	return role, scope, err
}

// Users lists the users, administrators first.
func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT email, role, created_at, scope FROM users
		ORDER BY CASE role WHEN 'admin' THEN 0 WHEN 'operator' THEN 1 ELSE 2 END, email`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []User
	for rows.Next() {
		var u User
		var created int64
		if err := rows.Scan(&u.Email, &u.Role, &created, &u.Scope); err != nil {
			return nil, err
		}
		u.CreatedAt = unix(created)
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserRole returns a user's role.
func (s *Store) UserRole(ctx context.Context, email string) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx, `SELECT role FROM users WHERE email = ?`, normalEmail(email)).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return role, err
}

// SetRole changes a user's role, keeping at least one administrator.
func (s *Store) SetRole(ctx context.Context, email, role string) error {
	if !slices.Contains(Roles, role) {
		return errors.New("store: unknown role")
	}
	email = normalEmail(email)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if role != RoleAdmin {
		if err := lastAdmin(ctx, tx, email); err != nil {
			return err
		}
	}
	res, err := tx.ExecContext(ctx, `UPDATE users SET role = ? WHERE email = ?`, role, email)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// DeleteUser removes a user with their sessions, known browsers and sign-in links, keeping at
// least one administrator.
func (s *Store) DeleteUser(ctx context.Context, email string) error {
	email = normalEmail(email)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lastAdmin(ctx, tx, email); err != nil {
		return err
	}
	for _, q := range []string{`DELETE FROM sessions WHERE email = ?`, `DELETE FROM devices WHERE email = ?`, `DELETE FROM login_links WHERE email = ?`} {
		if _, err := tx.ExecContext(ctx, q, email); err != nil {
			return err
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE email = ?`, email)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// lastAdmin refuses to take away the role of the only administrator.
func lastAdmin(ctx context.Context, tx *sql.Tx, email string) error {
	var others int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND email != ?`, email).Scan(&others); err != nil {
		return err
	}
	var role string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE email = ?`, email).Scan(&role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if role == RoleAdmin && others == 0 {
		return ErrLastAdmin
	}
	return nil
}

// InviteLifetime is how long an invitation link stays valid.
const InviteLifetime = 72 * time.Hour

// MinPassword is the shortest password a new user may choose.
const MinPassword = 12

// ErrUserExists is returned when inviting someone who already has an account.
var ErrUserExists = errors.New("store: this email already has an account")

// CreateInvite makes a one-time link for a new user with a role; only its hash is stored.
// Inviting the same email again replaces the earlier link.
func (s *Store) CreateInvite(ctx context.Context, email, role, by string, now time.Time) (string, time.Time, error) {
	email = normalEmail(email)
	if !slices.Contains(Roles, role) {
		return "", time.Time{}, errors.New("store: unknown role")
	}
	if exists, err := s.UserExists(ctx, email); err != nil {
		return "", time.Time{}, err
	} else if exists {
		return "", time.Time{}, ErrUserExists
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	expires := now.Add(InviteLifetime)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM invites WHERE email = ? OR expires_at <= ?`, email, now.Unix()); err != nil {
		return "", time.Time{}, err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO invites (token_hash, email, role, invited_by, expires_at) VALUES (?, ?, ?, ?, ?)`, sum[:], email, role, by, expires.Unix())
	return token, expires, err
}

// Invite returns the email and role an invitation is for, without using it.
func (s *Store) Invite(ctx context.Context, token string, now time.Time) (email, role string, err error) {
	sum := sha256.Sum256([]byte(token))
	err = s.db.QueryRowContext(ctx, `SELECT email, role FROM invites WHERE token_hash = ? AND expires_at > ?`, sum[:], now.Unix()).Scan(&email, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return email, role, err
}

// AcceptInvite uses an invitation: it creates the user with the password they chose and opens
// their first session.
func (s *Store) AcceptInvite(ctx context.Context, token, password string, now time.Time) (email, session string, err error) {
	if len(password) < MinPassword {
		return "", "", errors.New("store: password too short")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(token))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback() }()
	var role string
	if err := tx.QueryRowContext(ctx, `DELETE FROM invites WHERE token_hash = ? AND expires_at > ? RETURNING email, role`, sum[:], now.Unix()).Scan(&email, &role); err != nil {
		return "", "", ErrNotFound
	}
	// An account made for the same email since the invitation keeps its password.
	if _, err := tx.ExecContext(ctx, `INSERT INTO users (email, password_hash, created_at, role) VALUES (?, ?, ?, ?)`, email, hash, now.Unix(), role); err != nil {
		return "", "", ErrUserExists
	}
	if err := tx.Commit(); err != nil {
		return "", "", err
	}
	session, err = s.openSession(ctx, email, now)
	return email, session, err
}

// AuditEntry is one action recorded in the audit log.
type AuditEntry struct {
	At     time.Time
	Actor  string
	Action string
	Target string
	Detail string
}

// maxAudit bounds the audit log: the oldest entries go first.
const maxAudit = 100000

// Audit records an action. The log is only appended to and trimmed from its oldest end.
func (s *Store) Audit(ctx context.Context, actor, action, target, detail string, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `INSERT INTO audit (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)`,
		now.Unix(), actor, action, target, detail); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM audit WHERE id <= (SELECT MAX(id) FROM audit) - ?`, maxAudit)
	return err
}

// AuditLog returns the latest entries, newest first.
func (s *Store) AuditLog(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT at, actor, action, target, detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&at, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		e.At = unix(at)
		out = append(out, e)
	}
	return out, rows.Err()
}
