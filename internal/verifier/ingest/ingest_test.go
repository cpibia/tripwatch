package ingest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/transport"
	"github.com/cpibia/tripwatch/internal/verifier/pki"
	"github.com/cpibia/tripwatch/internal/verifier/store"
)

var now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

type harness struct {
	t     *testing.T
	ca    *pki.CA
	store *store.Store
	srv   *httptest.Server
	wake  chan struct{}
	clock time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.LoadOrCreate(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cert, err := ca.ServerCertificate(dir, []string{"127.0.0.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	wake := make(chan struct{}, 1)
	h := &harness{t: t, ca: ca, store: st, wake: wake, clock: now}
	ingest := &Server{Store: st, CA: ca, Now: func() time.Time { return h.clock }, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Wake: wake}

	h.srv = httptest.NewUnstartedServer(ingest)
	h.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: ca.Pool(), ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS13}
	h.srv.StartTLS()
	t.Cleanup(h.srv.Close)
	return h
}

// sensor enrolls host and returns a transport client for it, with its own state directory.
func (h *harness) sensor(host string) (*transport.Client, pki.Bundle) {
	h.t.Helper()
	b, pub, err := h.ca.Enroll(host, h.srv.URL+Path, now)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.store.Enroll(context.Background(), host, pub, now); err != nil {
		h.t.Fatal(err)
	}
	return h.client(b, h.t.TempDir()), b
}

func (h *harness) client(b pki.Bundle, stateDir string) *transport.Client {
	h.t.Helper()
	id, err := b.ClientIdentity("")
	if err != nil {
		h.t.Fatal(err)
	}
	tlsConf := id.TLS()
	key, err := b.SigningPrivateKey()
	if err != nil {
		h.t.Fatal(err)
	}
	c, err := transport.New(b.VerifierURL, &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}, Timeout: 5 * time.Second}, stateDir, b.HostID, key)
	if err != nil {
		h.t.Fatal(err)
	}
	return c
}

// alerts returns the alerts of web-01, the host every test enrolls.
func (h *harness) alerts() []store.Alert {
	h.t.Helper()
	a, err := h.store.Alerts(context.Background(), store.AlertFilter{HostID: "web-01"})
	if err != nil {
		h.t.Fatal(err)
	}
	return a
}

func TestDeliveryAndChain(t *testing.T) {
	h := newHarness(t)
	c, _ := h.sensor("web-01")
	ctx := context.Background()

	if err := c.Send(ctx, protocol.KindHeartbeat, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := c.Send(ctx, protocol.KindSnapshot, []byte(`{"x":1}`), now); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.wake:
	default:
		t.Fatal("the analysis worker was not woken")
	}
	if pending, err := h.store.PendingSnapshots(ctx, 10); err != nil || len(pending) != 1 {
		t.Errorf("pending = %v, %v", pending, err)
	}
	// A restarted sensor may send its startup snapshot right away, but past the burst further
	// snapshots are refused without moving the chain.
	for i := 2; i <= SnapshotBurst; i++ {
		if err := c.Send(ctx, protocol.KindSnapshot, []byte(`{"x":`+strconv.Itoa(i)+`}`), now); err != nil {
			t.Fatalf("snapshot %d within the burst: %v", i, err)
		}
	}
	if err := c.Send(ctx, protocol.KindSnapshot, []byte(`{"x":9}`), now); err == nil || errors.Is(err, transport.ErrRejected) {
		t.Errorf("err = %v, want a retryable refusal", err)
	}

	hst, err := h.store.Host(ctx, "web-01")
	if err != nil || hst.Chain.Sequence != 1+SnapshotBurst || hst.LastHeartbeat.IsZero() || hst.LastSnapshot.IsZero() {
		t.Errorf("host = %+v, %v", hst, err)
	}
	snaps, err := h.store.LatestSnapshots(ctx, "web-01", 5)
	if err != nil || len(snaps) != SnapshotBurst || string(snaps[0].Payload) != `{"x":3}` {
		t.Errorf("snapshots = %+v, %v", snaps, err)
	}
	if a := h.alerts(); len(a) != 0 {
		t.Errorf("alerts = %+v", a)
	}
}

// A sensor whose state was wiped starts its chain again: the verifier refuses it and raises a
// critical alert, since that is also what a stolen key would look like.
func TestRestartedChainIsRejected(t *testing.T) {
	h := newHarness(t)
	c, b := h.sensor("web-01")
	ctx := context.Background()
	if err := c.Send(ctx, protocol.KindHeartbeat, nil, now); err != nil {
		t.Fatal(err)
	}

	fresh := h.client(b, t.TempDir())
	err := fresh.Send(ctx, protocol.KindHeartbeat, nil, now.Add(time.Minute))
	if !errors.Is(err, transport.ErrRejected) {
		t.Fatalf("err = %v, want rejection", err)
	}
	alerts := h.alerts()
	if len(alerts) != 1 || alerts[0].Severity != "critical" || alerts[0].Kind != "chain" {
		t.Errorf("alerts = %+v", alerts)
	}
}

func TestRevokedHostIsRefused(t *testing.T) {
	h := newHarness(t)
	c, _ := h.sensor("web-01")
	if err := h.store.Revoke(context.Background(), "web-01"); err != nil {
		t.Fatal(err)
	}
	if err := c.Send(context.Background(), protocol.KindHeartbeat, nil, now); !errors.Is(err, transport.ErrRejected) {
		t.Errorf("err = %v", err)
	}
}

// A certificate is bound to its host: web-01's certificate cannot report as web-02.
func TestCertificateBoundToHost(t *testing.T) {
	h := newHarness(t)
	_, b1 := h.sensor("web-01")
	_, b2 := h.sensor("web-02")
	// The sensor itself refuses such a bundle, so the client is built by hand to reach the
	// verifier with web-01's certificate and web-02's signing key.
	if _, err := (pki.Bundle{HostID: "web-02", CA: b2.CA, Cert: b1.Cert, Key: b1.Key}).ClientIdentity(""); err == nil {
		t.Error("a bundle with another host's certificate was accepted")
	}
	cert, err := tls.X509KeyPair([]byte(b1.Cert), []byte(b1.Key))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := b2.SigningPrivateKey()
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: h.ca.Pool(), MinVersion: tls.VersionTLS13}}, Timeout: 5 * time.Second}
	c, err := transport.New(b2.VerifierURL, hc, t.TempDir(), "web-02", key)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(context.Background(), protocol.KindHeartbeat, nil, now); !errors.Is(err, transport.ErrRejected) {
		t.Errorf("err = %v", err)
	}
	if len(h.alerts()) != 1 {
		t.Errorf("alerts on web-01 = %+v", h.alerts())
	}
}

// Without a client certificate only enrollment answers; envelopes and renewal are refused.
func TestNoClientCertificate(t *testing.T) {
	h := newHarness(t)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: h.ca.Pool(), MinVersion: tls.VersionTLS13}}}
	for _, p := range []string{Path, RenewPath} {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, h.srv.URL+p, strings.NewReader("{}"))
		req.Header.Set(KindHeader, string(protocol.KindHeartbeat))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without a client certificate: %d", p, resp.StatusCode)
		}
	}
}

func TestEnrollWithToken(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	secret, _, err := h.store.CreateEnrollToken(ctx, "web-09", "ops@example.net", now)
	if err != nil {
		t.Fatal(err)
	}
	token := pki.EnrollToken{URL: h.srv.URL + Path, Secret: secret, CA: h.ca.Fingerprint()}
	parsed, err := pki.ParseEnrollToken(token.String())
	if err != nil || parsed != token {
		t.Fatalf("token round trip: %+v %v", parsed, err)
	}

	tlsPub, tlsKey, _ := ed25519.GenerateKey(nil)
	signPub, signKey, _ := ed25519.GenerateKey(nil)
	pinned := &http.Client{Transport: &http.Transport{TLSClientConfig: token.PinnedTLS("127.0.0.1")}, Timeout: 5 * time.Second}
	post := func(c *http.Client, secret string) (*EnrollResponse, int) {
		t.Helper()
		body, _ := json.Marshal(EnrollRequest{Secret: secret, TLSKey: tlsPub, SigningKey: signPub}) //nolint:gosec // test token
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, h.srv.URL+EnrollPath, bytes.NewReader(body))
		resp, err := c.Do(req)
		if err != nil {
			return nil, 0
		}
		defer func() { _ = resp.Body.Close() }()
		var out EnrollResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return &out, resp.StatusCode
	}

	// A token pinning another CA refuses the verifier before the secret leaves.
	wrong := token
	wrong.CA = "AAAA"
	if _, code := post(&http.Client{Transport: &http.Transport{TLSClientConfig: wrong.PinnedTLS("127.0.0.1")}}, secret); code != 0 {
		t.Fatalf("a verifier with another CA was trusted: %d", code)
	}
	if _, code := post(pinned, "guess"); code != http.StatusForbidden {
		t.Fatalf("wrong secret: %d", code)
	}
	res, code := post(pinned, secret)
	if code != http.StatusOK || res.HostID != "web-09" {
		t.Fatalf("enroll: %d %+v", code, res)
	}
	if _, code := post(pinned, secret); code != http.StatusForbidden {
		t.Fatalf("token used twice: %d", code)
	}

	// The bundle the sensor writes from the response works: its own keys, the issued certificate.
	keyDER, _ := x509.MarshalPKCS8PrivateKey(tlsKey)
	b := pki.Bundle{HostID: res.HostID, VerifierURL: token.URL, CA: res.CA, Cert: res.Cert,
		Key:        string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		SigningKey: base64.StdEncoding.EncodeToString(signKey.Seed())}
	if err := h.client(b, t.TempDir()).Send(ctx, protocol.KindHeartbeat, nil, now); err != nil {
		t.Fatalf("heartbeat with the enrolled bundle: %v", err)
	}
}

// The envelope whose acknowledgement was lost is sent again identically and accepted once.
func TestResendAfterLostAcknowledgement(t *testing.T) {
	h := newHarness(t)
	_, b := h.sensor("web-01")
	dir := t.TempDir()
	c := h.client(b, dir)
	ctx := context.Background()
	if err := c.Send(ctx, protocol.KindHeartbeat, nil, now); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after sending, before the state recorded the acknowledgement: put the
	// last envelope back as pending.
	key, _ := b.SigningPrivateKey()
	sealer := protocol.NewSealer("web-01", key, protocol.ChainState{})
	again := sealer.Seal(protocol.KindHeartbeat, nil, now)
	writePending(t, dir, key.Public(), sealer.State(), again)

	restarted := h.client(b, dir)
	if err := restarted.Send(ctx, protocol.KindHeartbeat, nil, now.Add(time.Minute)); err != nil {
		t.Fatalf("resend refused: %v", err)
	}
	if hst, _ := h.store.Host(ctx, "web-01"); hst.Chain.Sequence != 2 {
		t.Errorf("sequence = %d, want 2", hst.Chain.Sequence)
	}
	if a := h.alerts(); len(a) != 0 {
		t.Errorf("alerts = %+v", a)
	}
}

func writePending(t *testing.T, dir string, key crypto.PublicKey, state protocol.ChainState, e protocol.Envelope) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"key": key, "state": state, "pending": e})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "transport-state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Concurrent envelopes forking the same chain position: exactly one is accepted.
func TestConcurrentForkAcceptedOnce(t *testing.T) {
	h := newHarness(t)
	_, b := h.sensor("web-01")
	key, _ := b.SigningPrivateKey()
	id, _ := b.ClientIdentity("")
	tlsConf := id.TLS()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}

	const n = 20
	results := make(chan int, n)
	for i := range n {
		go func() {
			e := protocol.NewSealer("web-01", key, protocol.ChainState{}).Seal(protocol.KindHeartbeat, []byte(strconv.Itoa(i)), now)
			body, _ := json.Marshal(e)
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, b.VerifierURL, strings.NewReader(string(body)))
			req.Header.Set(KindHeader, string(protocol.KindHeartbeat))
			resp, err := client.Do(req)
			if err != nil {
				results <- 0
				return
			}
			_ = resp.Body.Close()
			results <- resp.StatusCode
		}()
	}
	accepted := 0
	for range n {
		if <-results == http.StatusOK {
			accepted++
		}
	}
	if accepted != 1 {
		t.Errorf("%d forks accepted, want 1", accepted)
	}
}

// Requests are checked against the host and the limits of their declared kind before the body
// is read: a revoked host, a missing kind or an oversized heartbeat get nowhere.
func TestRequestsCheckedBeforeTheBody(t *testing.T) {
	h := newHarness(t)
	_, b := h.sensor("web-01")
	key, _ := b.SigningPrivateKey()
	id, _ := b.ClientIdentity("")
	tlsConf := id.TLS()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}
	post := func(kind string, body []byte) int {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, b.VerifierURL, bytes.NewReader(body))
		if kind != "" {
			req.Header.Set(KindHeader, kind)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	heartbeat, _ := json.Marshal(protocol.NewSealer("web-01", key, protocol.ChainState{}).Seal(protocol.KindHeartbeat, nil, now))

	if code := post("", heartbeat); code != http.StatusBadRequest {
		t.Errorf("no kind: %d", code)
	}
	if code := post(string(protocol.KindSnapshot), heartbeat); code != http.StatusBadRequest {
		t.Errorf("kind mismatch: %d", code)
	}
	if code := post(string(protocol.KindHeartbeat), bytes.Repeat([]byte("x"), MaxSmallSize+1)); code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized heartbeat: %d", code)
	}
	if hst, _ := h.store.Host(context.Background(), "web-01"); hst.Chain.Sequence != 0 {
		t.Fatalf("a refused request moved the chain to %d", hst.Chain.Sequence)
	}
	if code := post(string(protocol.KindHeartbeat), heartbeat); code != http.StatusOK {
		t.Errorf("valid heartbeat: %d", code)
	}
	if err := h.store.Revoke(context.Background(), "web-01"); err != nil {
		t.Fatal(err)
	}
	if code := post(string(protocol.KindSnapshot), bytes.Repeat([]byte("x"), 8<<20)); code != http.StatusForbidden {
		t.Errorf("revoked host: %d", code)
	}
}

func TestSensorStartRaisesAnAlert(t *testing.T) {
	h := newHarness(t)
	c, _ := h.sensor("web-01")
	if err := c.Send(context.Background(), protocol.KindEvent, []byte(`{"event":"sensor_started","version":"1.2.0","boot_id":"b1"}`), now); err != nil {
		t.Fatal(err)
	}
	a := h.alerts()
	if len(a) != 1 || a[0].Title != "Sensore avviato" || a[0].Severity != "medium" || !strings.Contains(a[0].Detail, "1.2.0") {
		t.Fatalf("alerts = %+v", a)
	}
}

func TestClientCertificateRenewal(t *testing.T) {
	h := newHarness(t)
	_, b := h.sensor("web-01")
	dir := t.TempDir()
	id, err := b.ClientIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: id.TLS()}, Timeout: 5 * time.Second}
	first := id.NotAfter()

	if renewed, err := transport.RenewIfDue(t.Context(), hc, b.VerifierURL, id, now); renewed || err != nil {
		t.Fatalf("renewed a fresh certificate: %v %v", renewed, err)
	}
	// The verifier refuses an early renewal even when the sensor asks.
	if renewed, err := transport.RenewIfDue(t.Context(), hc, b.VerifierURL, id, first.Add(-30*24*time.Hour)); renewed || err == nil {
		t.Fatalf("early renewal accepted: %v %v", renewed, err)
	}

	h.clock = first.Add(-30 * 24 * time.Hour)
	renewed, err := transport.RenewIfDue(t.Context(), hc, b.VerifierURL, id, h.clock)
	if err != nil || !renewed || !id.NotAfter().After(first) {
		t.Fatalf("renewal: %v %v, expires %v", renewed, err, id.NotAfter())
	}
	// A restarted sensor picks the renewed certificate up from its state directory.
	again, err := b.ClientIdentity(dir)
	if err != nil || !again.NotAfter().Equal(id.NotAfter()) {
		t.Fatalf("renewed certificate not kept: %v", err)
	}

	if err := h.store.Revoke(context.Background(), "web-01"); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RenewIfDue(t.Context(), hc, b.VerifierURL, id, id.NotAfter()); err == nil {
		t.Fatal("a revoked host renewed its certificate")
	}
}
