package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cpibia/tripwatch/internal/transport"
	"github.com/cpibia/tripwatch/internal/watch"
)

// A batch the verifier refuses for its size goes back to the batcher as such, to be split,
// instead of passing for delivered; one that only failed to arrive passes, since it is sealed
// and goes out before the next envelope.
func TestSendEventsHandsBackWhatIsTooLarge(t *testing.T) {
	status := http.StatusRequestEntityTooLarge
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	defer srv.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	client, err := transport.New(srv.URL, srv.Client(), t.TempDir(), "web-01", key)
	if err != nil {
		t.Fatal(err)
	}
	send := sendEvents(slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	if err := send(t.Context(), []byte(`{"event":"watch"}`)); !errors.Is(err, watch.ErrTooLarge) {
		t.Fatalf("refused for its size: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := send(t.Context(), []byte(`{"event":"watch"}`)); err != nil {
		t.Fatalf("sealed but not delivered: %v", err)
	}
}
