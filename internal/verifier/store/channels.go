package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Kinds of notification channel.
const (
	ChannelEmail    = "email"
	ChannelTelegram = "telegram"
	ChannelWebhook  = "webhook"
)

// Channel is where alerts are sent: its settings, secrets included, stay in the database, which
// only the verifier reads. MinSeverity is the least severe alert it receives.
type Channel struct {
	ID          int64
	Kind        string
	Name        string
	Settings    ChannelSettings
	MinSeverity string
	Enabled     bool
	CreatedAt   time.Time
	// LastOK and LastError are the outcome of its latest send, test included.
	LastOK    time.Time
	LastError string
	LastTry   time.Time
}

// ChannelSettings are a channel's settings: the fields of its kind only.
type ChannelSettings struct {
	// Email.
	SMTPHost string   `json:"smtp_host,omitempty"`
	SMTPPort string   `json:"smtp_port,omitempty"`
	SMTPUser string   `json:"smtp_user,omitempty"`
	Password string   `json:"password,omitempty"`
	From     string   `json:"from,omitempty"`
	To       []string `json:"to,omitempty"`
	// Telegram.
	BotToken string `json:"bot_token,omitempty"`
	ChatID   string `json:"chat_id,omitempty"`
	// Webhook: the payload is signed with Secret, HMAC-SHA256.
	URL    string `json:"url,omitempty"`
	Secret string `json:"secret,omitempty"`
}

// maxChannels bounds the channels kept: each one is a send at every round.
const maxChannels = 32

// ErrTooManyChannels is returned when adding a channel past maxChannels.
var ErrTooManyChannels = errors.New("store: too many notification channels")

// AddChannel records a new channel, enabled.
func (s *Store) AddChannel(ctx context.Context, c Channel, now time.Time) (int64, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM channels`).Scan(&n); err != nil {
		return 0, err
	}
	if n >= maxChannels {
		return 0, ErrTooManyChannels
	}
	settings, err := json.Marshal(c.Settings) //nolint:gosec // a channel's credentials are kept in the verifier's database, which only it reads
	if err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO channels (kind, name, settings, min_severity, enabled, created_at) VALUES (?, ?, ?, ?, 1, ?)`,
		c.Kind, c.Name, string(settings), c.MinSeverity, now.Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Channels returns every channel, oldest first.
func (s *Store) Channels(ctx context.Context) ([]Channel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, name, settings, min_severity, enabled, created_at, last_ok, last_error, last_try FROM channels ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Channel
	for rows.Next() {
		var c Channel
		var settings string
		var created, ok, try int64
		if err := rows.Scan(&c.ID, &c.Kind, &c.Name, &settings, &c.MinSeverity, &c.Enabled, &created, &ok, &c.LastError, &try); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(settings), &c.Settings); err != nil {
			return nil, err
		}
		c.CreatedAt, c.LastOK, c.LastTry = unix(created), unix(ok), unix(try)
		out = append(out, c)
	}
	return out, rows.Err()
}

// Channel returns one channel.
func (s *Store) Channel(ctx context.Context, id int64) (Channel, error) {
	all, err := s.Channels(ctx)
	if err != nil {
		return Channel{}, err
	}
	for _, c := range all {
		if c.ID == id {
			return c, nil
		}
	}
	return Channel{}, ErrNotFound
}

// SetChannelEnabled turns a channel on or off.
func (s *Store) SetChannelEnabled(ctx context.Context, id int64, enabled bool) error {
	return s.one(ctx, `UPDATE channels SET enabled = ? WHERE id = ?`, enabled, id)
}

// DeleteChannel removes a channel.
func (s *Store) DeleteChannel(ctx context.Context, id int64) error {
	return s.one(ctx, `DELETE FROM channels WHERE id = ?`, id)
}

// ChannelResult records the outcome of a send: an empty failure is a success.
func (s *Store) ChannelResult(ctx context.Context, id int64, failure string, now time.Time) error {
	if failure == "" {
		_, err := s.db.ExecContext(ctx, `UPDATE channels SET last_ok = ?, last_error = '', last_try = ? WHERE id = ?`, now.Unix(), now.Unix(), id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE channels SET last_error = ?, last_try = ? WHERE id = ?`, failure, now.Unix(), id)
	return err
}

// one runs a statement that must change exactly one row.
func (s *Store) one(ctx context.Context, q string, args ...any) error {
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}
