package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/verifier/pki"
)

func TestStateIsDiscardedWhenTheKeyChanges(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	dir := t.TempDir()
	_, oldKey, _ := ed25519.GenerateKey(rand.Reader)
	c, err := New(srv.URL, srv.Client(), dir, "web-01", oldKey)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := c.Send(t.Context(), protocol.KindHeartbeat, nil, time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	same, err := New(srv.URL, srv.Client(), dir, "web-01", oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := same.sealer.State().Sequence; got != 3 {
		t.Fatalf("restart with the same key: sequence %d, want 3", got)
	}
	_, newKey, _ := ed25519.GenerateKey(rand.Reader)
	fresh, err := New(srv.URL, srv.Client(), dir, "web-01", newKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := fresh.sealer.State().Sequence; got != 0 || fresh.pending != nil {
		t.Fatalf("after re-enrollment: sequence %d, pending %v; want a new chain", got, fresh.pending)
	}
}

// A failed delivery leaves the envelope pending; the next send delivers it first, unchanged,
// and only then seals the new one.
func TestPendingEnvelopeIsResentFirst(t *testing.T) {
	var got []protocol.Envelope
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Tripwatch-Kind") == "" {
			t.Error("kind header missing")
		}
		var e protocol.Envelope
		_ = json.NewDecoder(r.Body).Decode(&e)
		if fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		got = append(got, e)
	}))
	defer srv.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	c, _ := New(srv.URL, srv.Client(), dir, "web-01", key)
	if err := c.Send(t.Context(), protocol.KindSnapshot, []byte("s"), time.Now()); err == nil {
		t.Fatal("a refused delivery reported success")
	}
	fail = false
	restarted, _ := New(srv.URL, srv.Client(), dir, "web-01", key)
	if err := restarted.Send(t.Context(), protocol.KindHeartbeat, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Kind != protocol.KindSnapshot || got[0].Sequence != 1 || got[1].Sequence != 2 {
		t.Fatalf("delivered %+v", got)
	}
}

func TestRejectionIsFinal(t *testing.T) {
	for _, code := range []int{http.StatusConflict, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", code) }))
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		c, _ := New(srv.URL, srv.Client(), t.TempDir(), "web-01", key)
		if err := c.Send(t.Context(), protocol.KindHeartbeat, nil, time.Now()); !errors.Is(err, ErrRejected) {
			t.Errorf("%d: %v", code, err)
		}
		srv.Close()
	}
}

func TestCorruptStateIsReported(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := New("https://v", http.DefaultClient, dir, "web-01", key); err == nil {
		t.Fatal("a corrupt state file was ignored")
	}
}

// fakeVerifier answers enrollment and renewal like the verifier, with its own CA.
func fakeVerifier(t *testing.T) (*httptest.Server, *pki.CA) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	ca, err := pki.LoadOrCreate(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.ServerCertificate(dir, []string{"127.0.0.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Secret string `json:"secret"`
			TLSKey []byte `json:"tls_key"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.URL.Path == "/v1/enroll" && req.Secret != "right" {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		certPEM, err := ca.IssueClient("web-01", ed25519.PublicKey(req.TLSKey), time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"host_id": "web-01", "ca": string(ca.PEM), "cert": string(certPEM)})
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, ca
}

func TestEnrollAndRenew(t *testing.T) {
	srv, ca := fakeVerifier(t)
	token := pki.EnrollToken{URL: srv.URL + "/v1/envelopes", Secret: "wrong", CA: ca.Fingerprint()}
	if _, err := Enroll(t.Context(), token); err == nil {
		t.Fatal("a refused token enrolled")
	}
	token.Secret = "right"
	b, err := Enroll(t.Context(), token)
	if err != nil || b.HostID != "web-01" {
		t.Fatalf("enroll: %+v %v", b, err)
	}
	id, err := b.ClientIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), MinVersion: tls.VersionTLS13}}}
	if renewed, err := RenewIfDue(t.Context(), hc, b.VerifierURL, id, time.Now()); renewed || err != nil {
		t.Fatalf("renewed a fresh certificate: %v %v", renewed, err)
	}
	before := id.NotAfter()
	time.Sleep(1100 * time.Millisecond) // a later issue time gives a later expiry
	if renewed, err := RenewIfDue(t.Context(), hc, b.VerifierURL, id, before.Add(-time.Hour)); !renewed || err != nil || !id.NotAfter().After(before) {
		t.Fatalf("renewal: %v %v", renewed, err)
	}
	other := token
	other.CA = "AAAA"
	if _, err := Enroll(t.Context(), other); err == nil {
		t.Fatal("enrolled with a verifier whose CA is not the token's")
	}
}
