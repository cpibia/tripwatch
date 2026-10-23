// Package ingest receives the envelopes sensors push over mutual TLS.
package ingest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
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
	"github.com/cpibia/tripwatch/internal/verifier/pki"
	"github.com/cpibia/tripwatch/internal/verifier/store"
	"github.com/cpibia/tripwatch/internal/watch"
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

// Path is where sensors post envelopes; RenewPath is where they renew their client
// certificate, authenticated by the one they have.
const (
	Path       = "/v1/envelopes"
	RenewPath  = "/v1/renew"
	EnrollPath = "/v1/enroll"
)

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

// TotalSnapshotBytes bounds everything a host keeps stored, evidence included, which otherwise
// stays for 30 days whatever its size.
const TotalSnapshotBytes = 4 << 30

// A body must keep arriving: each 64 KB within ChunkTime, all of it within MaxBodyTime. A host
// trickling bytes would otherwise hold a snapshot slot for the whole read timeout. A sensor
// waits at most SnapshotWait for a slot before it is told to retry.
const (
	ChunkTime    = 10 * time.Second
	MaxBodyTime  = 90 * time.Second
	SnapshotWait = 30 * time.Second
)

// steadyReader moves the connection's read deadline forward one chunk at a time, never past end.
type steadyReader struct {
	r    io.Reader
	rc   *http.ResponseController
	end  time.Time
	left int
}

func (s *steadyReader) Read(p []byte) (int, error) {
	if s.left <= 0 {
		deadline := time.Now().Add(ChunkTime)
		if deadline.After(s.end) {
			deadline = s.end
		}
		// Not every connection supports deadlines (tests over plain handlers); the server's
		// read timeout still applies then.
		_ = s.rc.SetReadDeadline(deadline)
		s.left = 64 << 10
	}
	if len(p) > s.left {
		p = p[:s.left]
	}
	n, err := s.r.Read(p)
	s.left -= n
	return n, err
}

// currentCertificate accepts only the host's current client certificate, or the one it replaced
// until the current one is first used. A certificate from an earlier enrollment or renewal is
// refused and raises an alert: someone holds a copy of it.
func (s *Server) currentCertificate(ctx context.Context, w http.ResponseWriter, host store.Host, presented *x509.Certificate, now time.Time) bool {
	serial := presented.SerialNumber.Text(16)
	switch {
	case host.CertSerial == "":
		// Enrolled before certificates were recorded: the first one presented becomes the
		// host's, and any other is refused from then on.
		if err := s.Store.SetCertificate(ctx, host.ID, serial, false); err != nil {
			s.Log.Error("record certificate", "host", host.ID, "err", err)
		}
		return true
	case serial == host.CertSerial:
		if host.PrevSerial != "" && serial == host.CertSerial {
			if err := s.Store.CertificateUsed(ctx, host.ID); err != nil {
				s.Log.Error("forget previous certificate", "host", host.ID, "err", err)
			}
		}
		return true
	case serial == host.PrevSerial:
		return true
	}
	if _, err := s.Store.Raise(ctx, store.Alert{HostID: host.ID, Fingerprint: "cert:stale:" + serial, Severity: "high", Kind: "chain",
		Title:  "Superseded certificate used for this server",
		Detail: fmt.Sprintf("A connection presented certificate number %s, which is no longer valid: the server was enrolled again or the certificate was renewed. Someone keeps a copy of it.", serial),
	}, now); err != nil {
		s.Log.Error("raise stale certificate alert", "host", host.ID, "err", err)
	}
	http.Error(w, "certificate no longer valid for this host", http.StatusForbidden)
	return false
}

func (s *Server) raise(ctx context.Context, a store.Alert, now time.Time) {
	if _, err := s.Store.Raise(ctx, a, now); err != nil {
		s.Log.Error("raise alert", "host", a.HostID, "fingerprint", a.Fingerprint, "err", err)
	}
}

func (s *Server) enrollSem() chan struct{} {
	s.enrollOnce.Do(func() { s.enrolling = make(chan struct{}, 1) })
	return s.enrolling
}

// alive notes a host that reached the verifier but whose envelope had to wait.
func (s *Server) alive(ctx context.Context, host string, now time.Time) {
	if err := s.Store.Alive(ctx, host, now); err != nil {
		s.Log.Error("record liveness", "host", host, "err", err)
	}
}

// SlowPenalty keeps a host away from the snapshot slots for a while after it held one longer
// than SlowHold or took one for an upload that failed, so a few hosts cannot hold them in turn.
// A large snapshot on a good link takes seconds.
const (
	SlowPenalty = 15 * time.Minute
	SlowHold    = 30 * time.Second
)

// HeartbeatGap is the pause between two accepted heartbeats that raises an alert, with the
// sensor's default interval of one minute: one missed beat, with room for delivery delays.
const HeartbeatGap = 100 * time.Second

// ConcurrentSnapshots bounds the snapshot bodies held in memory at once, whatever the number of
// hosts: each costs its size several times over while it is decoded and stored.
const ConcurrentSnapshots = 2

// Server verifies and stores envelopes. Stored snapshots wait in the database until the
// analysis worker takes them; Wake only tells it there is work, so a slow analysis never
// delays a sensor and a restart loses nothing.
type Server struct {
	Store *store.Store
	CA    *pki.CA
	Wake  chan<- struct{}
	Now   func() time.Time
	Log   *slog.Logger

	locks      sync.Map // host -> chan struct{}, a one-slot semaphore
	snapshots  chan struct{}
	once       sync.Once
	enrolling  chan struct{}
	slow       sync.Map // host -> time.Time until which its snapshots wait
	enrollOnce sync.Once
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
	if r.Method != http.MethodPost || (r.URL.Path != Path && r.URL.Path != RenewPath && r.URL.Path != EnrollPath) {
		http.NotFound(w, r)
		return
	}
	// Enrollment is the one request made before the host has a certificate.
	if r.URL.Path == EnrollPath {
		s.enroll(w, r)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	if r.URL.Path == RenewPath {
		s.renew(w, r)
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

	overQuota, stored := false, false
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

	if !s.currentCertificate(ctx, w, host, r.TLS.PeerCertificates[0], now) {
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
			s.alive(ctx, identity, now)
			http.Error(w, "snapshots too frequent", http.StatusTooManyRequests)
			return
		}
		daily, err := s.Store.SnapshotBytes(ctx, identity, now.Add(-24*time.Hour))
		if err != nil {
			s.fail(w, err)
			return
		}
		total, err := s.Store.SnapshotBytes(ctx, identity, time.Time{})
		if err != nil {
			s.fail(w, err)
			return
		}
		overQuota = daily >= DailySnapshotBytes || total >= TotalSnapshotBytes
		if until, ok := s.slow.Load(identity); ok && now.Before(until.(time.Time)) {
			// Its last upload was too slow: it waits out the penalty without taking a slot.
			s.alive(ctx, identity, now)
			http.Error(w, "previous upload too slow, retry later", http.StatusServiceUnavailable)
			return
		}
		waitCtx, cancel := context.WithTimeout(ctx, SnapshotWait)
		release, ok := acquire(waitCtx, s.snapshots)
		cancel()
		if !ok {
			s.alive(ctx, identity, now)
			http.Error(w, "verifier busy, retry later", http.StatusServiceUnavailable)
			return
		}
		taken := time.Now()
		defer func() {
			release()
			// Holding a slot long, or taking one for an upload that then fails, costs the
			// host the slots for a while, however the upload ended.
			if held := time.Since(taken); held > SlowHold || !stored {
				s.slow.Store(identity, time.Now().Add(SlowPenalty))
				s.Log.Warn("snapshot slot held without result or too long", "host", identity, "held", held.Round(time.Second))
			}
		}()
	}

	var e protocol.Envelope
	body, err := io.ReadAll(&steadyReader{r: http.MaxBytesReader(w, r.Body, limit), rc: http.NewResponseController(w), end: time.Now().Add(MaxBodyTime)})
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
		stored = true
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
		stored = true
		if _, err := s.Store.Raise(ctx, store.Alert{HostID: identity, Fingerprint: "snapshot:quota", Severity: "high", Kind: "sensor",
			Title:  "Snapshots not kept: daily quota exceeded",
			Detail: fmt.Sprintf("The server exceeded its snapshot quota (%d MB in 24 hours, %d MB in all). Snapshots over the quota are verified but neither kept nor analysed: an intact sensor does not produce that many.", DailySnapshotBytes>>20, TotalSnapshotBytes>>20),
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
	stored = true
	if e.Kind == protocol.KindEvent {
		s.event(ctx, identity, e, now)
	}
	// A pause shorter than the silence threshold, a sensor frozen with SIGSTOP for instance,
	// shows only here: as a gap between two heartbeats that were both accepted.
	if e.Kind == protocol.KindHeartbeat && !host.LastHeartbeat.IsZero() && now.Sub(host.LastHeartbeat) > HeartbeatGap {
		s.raise(ctx, store.Alert{HostID: identity, Fingerprint: "sensor:gap:" + strconv.FormatInt(now.Unix(), 10), Severity: "medium", Kind: "sensor-event",
			Title: "Missed heartbeats",
			Detail: fmt.Sprintf("No heartbeat between %s and %s (%s). A network pause, or the sensor was suspended or stopped for a short while: check what happened in that interval.",
				host.LastHeartbeat.Format("15:04:05"), now.Format("15:04:05"), now.Sub(host.LastHeartbeat).Round(time.Second)),
		}, now)
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
		Title:  "Envelope refused: " + err.Error(),
		Detail: fmt.Sprintf("Envelope number %d, kind %s, sent at %s. This server's chain does not accept it: someone else may be using the signing key, or the sensor was reinstalled without enrolling it again.", e.Sequence, e.Kind, e.SentAt.Format(time.RFC3339)),
	}, now)
	if raiseErr != nil {
		s.Log.Error("raise chain alert", "host", host, "err", raiseErr)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.Log.Error("ingest", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// EnrollRequest is what a sensor sends to enroll with a token: the secret, and the public keys
// it generated; its private keys never leave it.
type EnrollRequest struct {
	Secret     string `json:"secret"`
	TLSKey     []byte `json:"tls_key"`
	SigningKey []byte `json:"signing_key"`
}

// EnrollResponse completes the sensor's bundle.
type EnrollResponse struct {
	HostID string `json:"host_id"`
	CA     string `json:"ca"`
	Cert   string `json:"cert"`
}

// enroll registers a host with a one-time token made in the interface. The token is consumed
// before anything else, so a guess or a replay costs nothing and works for no one.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	// Anonymous: the token is checked one request at a time, and a refusal costs the caller a
	// pause. Secrets cannot be guessed; this keeps a flood of requests off the database the
	// sensors write to. The body is read first, within a short deadline, so a slow anonymous client cannot hold
	// the single slot.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(ChunkTime))
	var req EnrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil ||
		len(req.TLSKey) != ed25519.PublicKeySize || len(req.SigningKey) != ed25519.PublicKeySize {
		http.Error(w, "malformed enrollment request", http.StatusBadRequest)
		return
	}
	release, ok := acquire(r.Context(), s.enrollSem())
	if !ok {
		return
	}
	now := s.Now()
	host, by, err := s.Store.ConsumeEnrollToken(r.Context(), req.Secret, now)
	release()
	if errors.Is(err, store.ErrTokenReused) {
		// Whoever used the token first, someone else holds it too: one of the two is not the
		// sensor the operator meant to enroll.
		s.raise(r.Context(), store.Alert{HostID: host, Fingerprint: "enroll:token-reused:" + strconv.FormatInt(now.Unix(), 10), Severity: "critical", Kind: "chain",
			Title:  "Enrollment token used twice",
			Detail: "The token " + by + " made for this server was presented again after being used. Someone copied it: the server enrolled with the first use may not be the real one. Revoke the server and enroll it again.",
		}, now)
	}
	if err != nil {
		// The pause is outside the slot: it slows the caller, not the others.
		time.Sleep(200 * time.Millisecond)
		http.Error(w, "token unknown, used or expired", http.StatusForbidden)
		return
	}
	certPEM, err := s.CA.IssueClient(host, ed25519.PublicKey(req.TLSKey), now)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.Store.Enroll(r.Context(), host, ed25519.PublicKey(req.SigningKey), now); err != nil {
		s.fail(w, err)
		return
	}
	serial, err := pki.Serial(certPEM)
	if err == nil {
		err = s.Store.SetCertificate(r.Context(), host, serial, false)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Log.Info("host enrolled with a token", "host", host, "token_by", by)
	s.raise(r.Context(), store.Alert{HostID: host, Fingerprint: "enroll:done:" + serial, Severity: "high", Kind: "sensor-event",
		Title:  "Server enrolled",
		Detail: "The server enrolled with the token made by " + by + ". If you did not just install it, someone else used the token.",
	}, now)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(EnrollResponse{HostID: host, CA: string(s.CA.PEM), Cert: string(certPEM)})
}

// renew issues a new client certificate, for a key the sensor generated, to an enrolled host
// whose current one, the one this connection was made with, expires within the renewal window. Earlier requests are refused,
// so a host cannot mint certificates at will.
func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	presented := r.TLS.PeerCertificates[0]
	identity := presented.Subject.CommonName
	now := s.Now()
	unlock, ok := s.lock(r.Context(), identity)
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
	if !s.currentCertificate(r.Context(), w, host, presented, now) {
		return
	}
	if s.CA == nil || presented.NotAfter.Sub(now) > pki.RenewWindow {
		http.Error(w, "renewal not due", http.StatusConflict)
		return
	}
	var req struct {
		TLSKey []byte `json:"tls_key"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil || len(req.TLSKey) != ed25519.PublicKeySize {
		http.Error(w, "renewal needs the new public key", http.StatusBadRequest)
		return
	}
	certPEM, err := s.CA.IssueClient(identity, ed25519.PublicKey(req.TLSKey), now)
	if err != nil {
		s.fail(w, err)
		return
	}
	serial, err := pki.Serial(certPEM)
	if err == nil {
		err = s.Store.RenewCertificate(r.Context(), identity, serial, presented.SerialNumber.Text(16))
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	// Visible, so that a renewal made with a stolen certificate does not pass unnoticed.
	if _, err := s.Store.Raise(r.Context(), store.Alert{HostID: identity, Fingerprint: "cert:renewed:" + serial, Severity: "high", Kind: "sensor-event",
		Title:  "Client certificate renewed",
		Detail: fmt.Sprintf("The sensor renewed its client certificate, which expired on %s. That is normal once every two years; an unexpected renewal means someone uses this server's certificate.", presented.NotAfter.Format("2006-01-02")),
	}, now); err != nil {
		s.Log.Error("raise renewal alert", "host", identity, "err", err)
	}
	s.Log.Info("client certificate renewed", "host", identity, "expired", presented.NotAfter)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"cert": string(certPEM)})
}

// event turns the events a sensor reports into alerts. A start is worth one even when it is
// legitimate: a stop shorter than the silence threshold leaves no other trace.
func (s *Server) event(ctx context.Context, host string, e protocol.Envelope, now time.Time) {
	var ev struct {
		Event   string `json:"event"`
		Version string `json:"version"`
		BootID  string `json:"boot_id"`
	}
	if json.Unmarshal(e.Payload, &ev) != nil {
		return
	}
	if ev.Event == watch.BatchEvent {
		s.watched(ctx, host, e, now)
		return
	}
	if ev.Event != "sensor_started" {
		return
	}
	detail := fmt.Sprintf("The sensor started (version %s, system boot %s). If the server was not rebooted and the sensor was not updated, someone stopped and restarted it: check what happened while it was down.", ev.Version, ev.BootID)
	if _, err := s.Store.Raise(ctx, store.Alert{HostID: host, Fingerprint: "sensor:started:" + strconv.FormatUint(e.Sequence, 10), Severity: "high", Kind: "sensor-event",
		Title: "Sensor started", Detail: detail}, now); err != nil {
		s.Log.Error("raise start alert", "host", host, "err", err)
	}
}

func writeAck(w http.ResponseWriter, seq uint64) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]uint64{"accepted": seq})
}
