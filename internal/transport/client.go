// Package transport delivers signed envelopes from the sensor to the verifier.
package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/verifier/pki"
)

const stateFile = "transport-state.json"

// ErrRejected means the verifier refused the envelope for good (chain broken, host revoked):
// sending it again will not help, the host has to be enrolled again.
var ErrRejected = errors.New("transport: envelope rejected by the verifier")

// ErrTooLarge means the verifier refused the envelope for its size without recording it: it is
// dropped and the chain taken back to before it, so it never holds back the envelopes after it.
var ErrTooLarge = errors.New("transport: envelope too large for the verifier")

// ErrNotSealed means the payload was not sealed because an earlier envelope is still
// undelivered: the caller keeps it and sends it again later. Any other error from Send leaves
// the payload sealed and pending, to go out before the next one.
var ErrNotSealed = errors.New("transport: payload not sealed")

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

	// OnUpdate and OnUninstall, when set, receive the update or uninstall order and signature
	// the verifier's answer carries, unchecked: the caller verifies them.
	OnUpdate    func(payload, signature string)
	OnUninstall func(payload, signature string)
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
		err := c.deliver(ctx, *c.pending)
		switch {
		case errors.Is(err, ErrTooLarge) && c.sealer.Rewind(*c.pending):
		case err != nil:
			return fmt.Errorf("%w: resending sequence %d: %w", ErrNotSealed, c.pending.Sequence, err)
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
		if errors.Is(err, ErrTooLarge) && c.sealer.Rewind(e) {
			c.pending = nil
			return errors.Join(err, c.save())
		}
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
	// Declared ahead of the body so the verifier can apply the kind's limits before reading it.
	req.Header.Set("Tripwatch-Kind", string(e.Kind))
	// Marks the POST as safe to repeat, so net/http sends it again on a new connection when a
	// kept-alive one turns out closed by the verifier: a resent envelope is acknowledged as the
	// same one, and without this the beat would be lost until the next send.
	req.Header.Set("Idempotency-Key", strconv.FormatUint(e.Sequence, 10))
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch resp.StatusCode {
	case http.StatusOK:
		if order := resp.Header.Get(protocol.UpdateHeader); order != "" && c.OnUpdate != nil {
			c.OnUpdate(order, resp.Header.Get(protocol.UpdateSignatureHeader))
		}
		return nil
	case http.StatusRequestEntityTooLarge:
		return fmt.Errorf("%w: sequence %d, %d bytes: %s", ErrTooLarge, e.Sequence, len(body), bytes.TrimSpace(msg))
	case http.StatusConflict, http.StatusForbidden:
		if order := resp.Header.Get(protocol.UninstallHeader); order != "" && c.OnUninstall != nil {
			c.OnUninstall(order, resp.Header.Get(protocol.UninstallSignatureHeader))
		}
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
	if err := os.Rename(tmp, filepath.Join(c.stateDir, stateFile)); err != nil {
		return err
	}
	return pki.SyncDir(c.stateDir)
}

// RenewBefore is how long before expiry the sensor asks for a new client certificate; it is
// inside the verifier's renewal window, which leaves a month of daily retries.
const RenewBefore = 60 * 24 * time.Hour

// RenewIfDue replaces the client certificate of id with a new one from the verifier when the
// current one expires within RenewBefore. It reports whether it renewed.
func RenewIfDue(ctx context.Context, hc *http.Client, verifierURL string, id *pki.Identity, now time.Time) (bool, error) {
	if id.NotAfter().Sub(now) > RenewBefore {
		return false, nil
	}
	u, err := url.Parse(verifierURL)
	if err != nil {
		return false, err
	}
	u.Path, u.RawQuery = "/v1/renew", ""
	// The new TLS key is made here; only its public half goes to the verifier.
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, err
	}
	reqBody, err := json.Marshal(map[string][]byte{"tls_key": pub})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(reqBody))
	if err != nil {
		return false, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("verifier answered %s: %s", resp.Status, bytes.TrimSpace(body))
	}
	var r struct{ Cert string }
	if err := json.Unmarshal(body, &r); err != nil {
		return false, err
	}
	keyPEM, err := pki.EncodeKey(key)
	if err != nil {
		return false, err
	}
	return true, id.Replace([]byte(r.Cert), keyPEM)
}

// Enroll registers this host with a one-time token and returns its bundle. The TLS key and the
// signing key are generated here and only their public halves are sent; the verifier is
// trusted only if its chain ends in the CA the token names.
func Enroll(ctx context.Context, token pki.EnrollToken) (pki.Bundle, error) {
	u, err := url.Parse(token.URL)
	if err != nil {
		return pki.Bundle{}, err
	}
	tlsPub, tlsKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return pki.Bundle{}, err
	}
	signPub, signKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return pki.Bundle{}, err
	}
	body, err := json.Marshal(map[string]any{"secret": token.Secret, "tls_key": []byte(tlsPub), "signing_key": []byte(signPub)})
	if err != nil {
		return pki.Bundle{}, err
	}
	enrollURL := *u
	enrollURL.Path, enrollURL.RawQuery = "/v1/enroll", ""
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL.String(), bytes.NewReader(body))
	if err != nil {
		return pki.Bundle{}, err
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: token.PinnedTLS(u.Hostname())}, Timeout: time.Minute}
	resp, err := hc.Do(req)
	if err != nil {
		return pki.Bundle{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return pki.Bundle{}, fmt.Errorf("verifier answered %s: %s", resp.Status, bytes.TrimSpace(data))
	}
	var r struct {
		HostID string `json:"host_id"`
		CA     string `json:"ca"`
		Cert   string `json:"cert"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return pki.Bundle{}, err
	}
	keyPEM, err := pki.EncodeKey(tlsKey)
	if err != nil {
		return pki.Bundle{}, err
	}
	b := pki.Bundle{HostID: r.HostID, VerifierURL: token.URL, CA: r.CA, Cert: r.Cert, Key: string(keyPEM),
		SigningKey: base64.StdEncoding.EncodeToString(signKey.Seed())}
	// The answer must make a usable identity: the certificate is for our key, from the pinned CA.
	if _, err := b.ClientIdentity(""); err != nil {
		return pki.Bundle{}, fmt.Errorf("verifier answer unusable: %w", err)
	}
	return b, nil
}
