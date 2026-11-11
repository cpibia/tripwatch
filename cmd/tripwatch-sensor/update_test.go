package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/provenance"
	"github.com/cpibia/tripwatch/internal/selfupdate"
	"github.com/cpibia/tripwatch/internal/transport"
)

// A refused update is reported once, as a signed event; a failure to reach the release is not
// reported at all.
func TestRefusedUpdateIsReportedAsAnEvent(t *testing.T) {
	dir := t.TempDir()
	recordRefusal(dir, errors.New("connection reset"))
	if _, err := os.Stat(filepath.Join(dir, refusedUpdateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a network failure was recorded as a refusal: %v", err)
	}
	recordRefusal(dir, &selfupdate.RejectedError{Version: "1.2.3", Err: errors.New("the release has no provenance.sigstore.json")})

	var events []map[string]string
	accept := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !accept {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var e protocol.Envelope
		_ = json.NewDecoder(r.Body).Decode(&e)
		var ev map[string]string
		if json.Unmarshal(e.Payload, &ev) == nil && ev["event"] != "" {
			events = append(events, ev)
		}
	}))
	defer srv.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	client, err := transport.New(srv.URL, srv.Client(), dir, "web-01", key)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// An envelope left pending holds the event back: the record stays for the next attempt.
	if err := client.Send(t.Context(), protocol.KindHeartbeat, nil, time.Now()); err == nil {
		t.Fatal("the verifier answered 503 and the heartbeat was delivered")
	}
	reportRefusedUpdate(t.Context(), log, client, dir)
	if _, err := os.Stat(filepath.Join(dir, refusedUpdateFile)); err != nil {
		t.Fatalf("record removed before the event was sealed: %v", err)
	}

	accept = true
	reportRefusedUpdate(t.Context(), log, client, dir)
	reportRefusedUpdate(t.Context(), log, client, dir)
	if len(events) != 1 || events[0]["event"] != "update_refused" || events[0]["version"] != "1.2.3" || !strings.Contains(events[0]["reason"], "no provenance") {
		t.Fatalf("events %v, want one refusal of 1.2.3", events)
	}
	if _, err := os.Stat(filepath.Join(dir, refusedUpdateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("record kept after the event was sent: %v", err)
	}
}

func TestVerifyReleaseChecksEveryFileNamed(t *testing.T) {
	testdata := filepath.Join("..", "..", "internal", "provenance", "testdata", "synthetic")
	root, err := os.ReadFile(filepath.Join(testdata, "trusted_root.json")) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	v, err := provenance.NewVerifier(root)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(testdata, "valid.jsonl")
	dir := t.TempDir()
	file := func(name, contents string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	deb := file("tripwatch-sensor_1.2.3_amd64.deb", "contents of tripwatch-sensor_1.2.3_amd64.deb")
	bin := file("tripwatch-sensor_1.2.3_linux_amd64", "contents of tripwatch-sensor_1.2.3_linux_amd64")
	if err := verifyRelease(io.Discard, v, bundle, "1.2.3", []string{deb, bin}); err != nil {
		t.Fatal(err)
	}
	for name, files := range map[string][]string{
		"altered file":       {deb, file("tripwatch-sensor-1.2.3-1.x86_64.rpm", "altered")},
		"file not attested":  {file("tripwatch-sensor_1.2.3_linux_arm64", "anything")},
		"another version":    nil,
		"no file to compare": {},
	} {
		version := "1.2.3"
		if name == "another version" {
			version, files = "1.2.4", []string{deb}
		}
		if err := verifyRelease(io.Discard, v, bundle, version, files); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}
