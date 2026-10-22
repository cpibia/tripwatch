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
	"strconv"
	"sync"
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// Size limits per envelope kind. A compressed snapshot of a large server is a few MB and its
// decompressed form is capped at 32 MB by the analysis; heartbeats and events carry little.
const (
	MaxSnapshotSize = 48 << 20
	MaxSmallSize    = 256 << 10
)

// KindHeader declares the envelope kind before the body, so that a request is checked against
// the host's state and the size and rate limits of its kind before anything is read.
const KindHeader = "Tripwatch-Kind"

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

// DailySnapshotBytes is the storage quota of one host: snapshots received within a day beyond
// it are verified and keep the host alive, but are not stored. A server's hourly snapshots take
// a few to a few tens of MB a day; the quota only stops a host filling the verifier's disk.
const DailySnapshotBytes = 1 << 30

// ConcurrentSnapshots bounds the snapshot bodies held in memory at once, whatever the number of
// hosts: each costs its size several times over while it is decoded and stored.
const ConcurrentSnapshots = 2

// Server verifies and stores envelopes. Stored snapshots wait in the database until the
// analysis worker takes them; Wake only tells it there is work, so a slow analysis never
// delays a sensor and a restart loses nothing.
type Server struct {
	Store *store.Store
	Wake  chan<- struct{}
	Now   func() time.Time
	Log   *slog.Logger

	locks     sync.Map // host -> chan struct{}, a one-slot semaphore
	snapshots chan struct{}
	once      sync.Once
}

// acquire takes a one-slot semaphore, or gives up when the request ends.
func acquire(ctx context.Context, sem chan struct{}) (func(), bool) {
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, true
	case <-ctx.Done():
		return nil, false
	}
}

// lock serialises reading, verifying and storing the chain of one host. A host opening many
// connections only queues them, without a body read for any.
func (s *Server) lock(ctx context.Context, host string) (func(), bool) {
	m, _ := s.locks.LoadOrStore(host, make(chan struct{}, 1))
	return acquire(ctx, m.(chan struct{}))
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
	s.once.Do(func() { s.snapshots = make(chan struct{}, ConcurrentSnapshots) })
	identity := r.TLS.PeerCertificates[0].Subject.CommonName
	now := s.Now()
	ctx := r.Context()

	kind := protocol.Kind(r.Header.Get(KindHeader))
	limit := int64(MaxSmallSize)
	switch kind {
	case protocol.KindSnapshot:
		limit = MaxSnapshotSize
	case protocol.KindHeartbeat, protocol.KindEvent:
	default:
		http.Error(w, "missing or unknown "+KindHeader, http.StatusBadRequest)
		return
	}

	overQuota := false
	unlock, ok := s.lock(ctx, identity)
	if !ok {
		return
	}
	defer unlock()
	host, err := s.Store.Host(r.Context(), identity)
	if errors.Is(err, store.ErrNotFound) || (err == nil && host.Revoked) {
		http.Error(w, "host not enrolled", http.StatusForbidden)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	if kind == protocol.KindSnapshot {
		recent, err := s.Store.CountSnapshots(ctx, identity, now.Add(-SnapshotWindow))
		if err != nil {
			s.fail(w, err)
			return
		}
		if recent >= SnapshotBurst {
			// Refused before the body is read, so the chain does not move: the sensor keeps
			// the envelope and sends it again later.
			http.Error(w, "snapshots too frequent", http.StatusTooManyRequests)
			return
		}
		stored, err := s.Store.SnapshotBytes(ctx, identity, now.Add(-24*time.Hour))
		if err != nil {
			s.fail(w, err)
			return
		}
		overQuota = stored >= DailySnapshotBytes
		release, ok := acquire(ctx, s.snapshots)
		if !ok {
			return
		}
		defer release()
	}

	var e protocol.Envelope
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		http.Error(w, "envelope too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	if err := json.Unmarshal(body, &e); err != nil {
		http.Error(w, "malformed envelope", http.StatusBadRequest)
		return
	}
	if e.Kind != kind {
		http.Error(w, "envelope kind does not match "+KindHeader, http.StatusBadRequest)
		return
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

	if overQuota {
		if err := s.Store.AcceptDropped(ctx, e, host.Chain, state, now); err != nil {
			s.fail(w, err)
			return
		}
		if _, err := s.Store.Raise(ctx, store.Alert{HostID: identity, Fingerprint: "snapshot:quota", Severity: "high", Kind: "sensor",
			Title:  "Snapshot non conservati: quota giornaliera superata",
			Detail: fmt.Sprintf("Il server ha inviato più di %d MB di snapshot nelle ultime 24 ore. Gli snapshot oltre la quota vengono verificati ma non conservati né analizzati: un sensore integro non ne produce così tanti.", DailySnapshotBytes>>20),
		}, now); err != nil {
			s.Log.Error("raise quota alert", "host", identity, "err", err)
		}
		writeAck(w, state.Sequence)
		return
	}
	if err := s.Store.Accept(ctx, e, host.Chain, state, now); err != nil {
		s.fail(w, err)
		return
	}
	if e.Kind == protocol.KindEvent {
		s.event(ctx, identity, e, now)
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
		Title:  "Busta rifiutata: " + err.Error(),
		Detail: fmt.Sprintf("Busta numero %d, tipo %s, inviata il %s. La catena di questo server non la accetta: la chiave di firma può essere usata da qualcun altro, oppure il sensore è stato reinstallato senza registrarlo di nuovo.", e.Sequence, e.Kind, e.SentAt.Format(time.RFC3339)),
	}, now)
	if raiseErr != nil {
		s.Log.Error("raise chain alert", "host", host, "err", raiseErr)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.Log.Error("ingest", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// event turns the events a sensor reports into alerts. A start is worth one even when it is
// legitimate: a stop shorter than the silence threshold leaves no other trace.
func (s *Server) event(ctx context.Context, host string, e protocol.Envelope, now time.Time) {
	var ev struct {
		Event   string `json:"event"`
		Version string `json:"version"`
		BootID  string `json:"boot_id"`
	}
	if json.Unmarshal(e.Payload, &ev) != nil || ev.Event != "sensor_started" {
		return
	}
	detail := fmt.Sprintf("Il sensore si è avviato (versione %s, avvio del sistema %s). Se il server non è stato riavviato e il sensore non è stato aggiornato, qualcuno lo ha fermato e fatto ripartire: controlla cosa è successo mentre era fermo.", ev.Version, ev.BootID)
	if _, err := s.Store.Raise(ctx, store.Alert{HostID: host, Fingerprint: "sensor:started:" + strconv.FormatUint(e.Sequence, 10), Severity: "medium", Kind: "sensor-event",
		Title: "Sensore avviato", Detail: detail}, now); err != nil {
		s.Log.Error("raise start alert", "host", host, "err", err)
	}
}

func writeAck(w http.ResponseWriter, seq uint64) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]uint64{"accepted": seq})
}
