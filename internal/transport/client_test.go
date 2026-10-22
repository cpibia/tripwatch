package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
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
