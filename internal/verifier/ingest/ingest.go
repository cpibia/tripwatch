// Package ingest receives the envelopes sensors push over mutual TLS.
package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// MaxEnvelopeSize bounds one request: a compressed snapshot of a large server is a few MB.
const MaxEnvelopeSize = 64 << 20

// Path is where sensors post envelopes.
const Path = "/v1/envelopes"

// A host may send at most SnapshotBurst snapshots per SnapshotWindow: more would only let a
// compromised host bury its history. The burst lets a restarted sensor deliver its startup
// snapshot right after the previous one; a refused snapshot blocks the chain, heartbeats
// included, until it gets through.
const (
	SnapshotBurst  = 3
	SnapshotWindow = 15 * time.Minute
)

// Server verifies and stores envelopes. Stored snapshots wait in the database until the
// analysis worker takes them; Wake only tells it there is work, so a slow analysis never
// delays a sensor and a restart loses nothing.
type Server struct {
	Store *store.Store
	Wake  chan<- struct{}
	Now   func() time.Time
	Log   *slog.Logger

	locks sync.Map // host -> *sync.Mutex
}

// lock serialises reading, verifying and storing the chain of one host.
func (s *Server) lock(host string) func() {
	m, _ := s.locks.LoadOrStore(host, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != Path {
		http.NotFound(w, r)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	identity := r.TLS.PeerCertificates[0].Subject.CommonName
	now := s.Now()

	var e protocol.Envelope
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxEnvelopeSize+1))
	if err != nil || len(body) > MaxEnvelopeSize {
		http.Error(w, "envelope too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	if err := json.Unmarshal(body, &e); err != nil {
		http.Error(w, "malformed envelope", http.StatusBadRequest)
		return
	}

	defer s.lock(identity)()
	host, err := s.Store.Host(r.Context(), identity)
	if errors.Is(err, store.ErrNotFound) || (err == nil && host.Revoked) {
		http.Error(w, "host not enrolled", http.StatusForbidden)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	if e.Kind == protocol.KindSnapshot {
		recent, err := s.Store.CountSnapshots(r.Context(), identity, now.Add(-SnapshotWindow))
		if err != nil {
			s.fail(w, err)
			return
		}
		if recent >= SnapshotBurst {
			// Refused before verification, so the chain does not move: the sensor keeps the
			// envelope and sends it again later.
			http.Error(w, "snapshots too frequent", http.StatusTooManyRequests)
			return
		}
	}
	state, err := protocol.Verify(e, identity, host.PublicKey, host.Chain)
	switch {
	case err == nil:
	case errors.Is(err, protocol.ErrReplay) && e.Sequence == host.Chain.Sequence && bytes.Equal(e.Digest(), host.Chain.LastDigest):
		// The sensor resent the envelope whose acknowledgement it did not receive.
		writeAck(w, host.Chain.Sequence)
		return
	default:
		s.chainAlert(r.Context(), identity, e, err, now)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	if err := s.Store.Accept(r.Context(), e, host.Chain, state, now); err != nil {
		s.fail(w, err)
		return
	}
	if e.Kind == protocol.KindSnapshot && s.Wake != nil {
		select {
		case s.Wake <- struct{}{}:
		default: // the worker is already due to run
		}
	}
	writeAck(w, state.Sequence)
}

// chainAlert raises a critical alert for an envelope that breaks the host's chain: replayed,
// out of sequence, forked, from another host or badly signed. Any of these means the sensor's
// key is used by someone else or the sensor was reinstalled without re-enrollment.
func (s *Server) chainAlert(ctx context.Context, host string, e protocol.Envelope, err error, now time.Time) {
	_, raiseErr := s.Store.Raise(ctx, store.Alert{
		HostID: host, Fingerprint: "chain:" + err.Error(), Severity: "critical", Kind: "chain",
		Title:  "Envelope rejected: " + err.Error(),
		Detail: fmt.Sprintf("Sequence %d, kind %s, sent at %s. The chain of this host does not accept it: the signing key may be used by someone else, or the sensor was reinstalled without enrolling again.", e.Sequence, e.Kind, e.SentAt.Format(time.RFC3339)),
	}, now)
	if raiseErr != nil {
		s.Log.Error("raise chain alert", "host", host, "err", raiseErr)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.Log.Error("ingest", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func writeAck(w http.ResponseWriter, seq uint64) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]uint64{"accepted": seq})
}
