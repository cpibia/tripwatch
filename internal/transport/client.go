// Package transport delivers signed envelopes from the sensor to the verifier.
package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
)

const stateFile = "transport-state.json"

// ErrRejected means the verifier refused the envelope for good (chain broken, host revoked):
// sending it again will not help, the host has to be enrolled again.
var ErrRejected = errors.New("transport: envelope rejected by the verifier")

// persisted is the chain position and the envelope not yet acknowledged.
type persisted struct {
	// Key is the public signing key the state belongs to: after a re-enrollment the old chain
	// position and pending envelope mean nothing to the verifier.
	Key     []byte              `json:"key"`
	State   protocol.ChainState `json:"state"`
	Pending *protocol.Envelope  `json:"pending,omitempty"`
}

// Client seals and sends envelopes one at a time. The order is seal, persist, send: the new
// chain position and the envelope are on disk before they leave, so after a crash the same
// envelope is sent again instead of a different one with the same sequence number.
type Client struct {
	url      string
	http     *http.Client
	stateDir string
	sealer   *protocol.Sealer
	key      ed25519.PublicKey

	mu      sync.Mutex
	pending *protocol.Envelope
}

func New(url string, hc *http.Client, stateDir, hostID string, key ed25519.PrivateKey) (*Client, error) {
	var p persisted
	data, err := os.ReadFile(filepath.Join(stateDir, stateFile)) //nolint:gosec // the state directory is the operator's configuration
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("transport state: %w", err)
		}
		if !bytes.Equal(p.Key, key.Public().(ed25519.PublicKey)) {
			p = persisted{}
		}
	}
	return &Client{url: url, http: hc, stateDir: stateDir, sealer: protocol.NewSealer(hostID, key, p.State),
		key: key.Public().(ed25519.PublicKey), pending: p.Pending}, nil
}

// Send delivers payload as an envelope of the given kind. An envelope left over from an earlier
// failed attempt goes first; if it still cannot be delivered, the new payload is not sealed, so
// the chain never moves ahead of what the verifier has.
func (c *Client) Send(ctx context.Context, kind protocol.Kind, payload []byte, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.pending != nil {
		if err := c.deliver(ctx, *c.pending); err != nil {
			return fmt.Errorf("resending sequence %d: %w", c.pending.Sequence, err)
		}
		c.pending = nil
		if err := c.save(); err != nil {
			return err
		}
	}

	e := c.sealer.Seal(kind, payload, now)
	c.pending = &e
	if err := c.save(); err != nil {
		return err
	}
	if err := c.deliver(ctx, e); err != nil {
		return err
	}
	c.pending = nil
	return c.save()
}

func (c *Client) deliver(ctx context.Context, e protocol.Envelope) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusConflict, http.StatusForbidden:
		return fmt.Errorf("%w: %s", ErrRejected, bytes.TrimSpace(msg))
	default:
		return fmt.Errorf("verifier answered %s: %s", resp.Status, bytes.TrimSpace(msg))
	}
}

// save writes the state atomically and durably before anything is sent.
func (c *Client) save() error {
	data, err := json.Marshal(persisted{Key: c.key, State: c.sealer.State(), Pending: c.pending})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.stateDir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(c.stateDir, stateFile+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // the state directory is the operator's configuration
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.stateDir, stateFile))
}
