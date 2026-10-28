package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
)

// A host started before the run record exists is known from its latest start alert.
func TestRunFallsBackOnStartAlerts(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	for i, boot := range []string{"0b9e6f3c-0000-4000-8000-000000000001", "0b9e6f3c-0000-4000-8000-000000000002"} {
		if _, err := s.Raise(ctx, Alert{HostID: "web-01", Fingerprint: "sensor:started:" + string(rune('1'+i)), Severity: "high", Kind: "sensor-event",
			Title: "Sensor started", Detail: "The sensor started (version 0.1.8, system boot " + boot + "). If the server..."}, t0.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Run(ctx, "web-01")
	if err != nil || r.BootID != "0b9e6f3c-0000-4000-8000-000000000002" || r.Version != "0.1.8" || !r.StoppedAt.IsZero() {
		t.Fatalf("run = %+v, %v", r, err)
	}
	if err := s.Stopped(ctx, "web-01", t0.Add(2*time.Hour), "stopped", true); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Run(ctx, "web-01"); r.BootID != "0b9e6f3c-0000-4000-8000-000000000002" || !r.StoppedAt.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("after a stop: %+v", r)
	}
	if err := s.Started(ctx, "web-01", "b2", "0.1.10", t0.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Run(ctx, "web-01"); r.BootID != "b2" || r.Version != "0.1.10" || !r.StoppedAt.IsZero() || !r.StartedAt.Equal(t0.Add(3*time.Hour)) {
		t.Fatalf("after a start: %+v", r)
	}
}

// A database created by 0.1.10 gains the columns that record how the sensor stopped and when
// it started.
func TestRunsMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `CREATE TABLE sensor_runs (host_id TEXT PRIMARY KEY, boot_id TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '', stopped_at INTEGER NOT NULL DEFAULT 0);
		INSERT INTO sensor_runs (host_id, boot_id, version) VALUES ('web-01', 'b1', '0.1.10')`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.Stopped(context.Background(), "web-01", t0, "stopped", true); err != nil {
		t.Fatal(err)
	}
	if r, err := s.Run(context.Background(), "web-01"); err != nil || r.BootID != "b1" || !r.Shutdown || r.StopReason != "stopped" || !r.StartedAt.IsZero() {
		t.Fatalf("run = %+v, %v", r, err)
	}
}

// An envelope verified with a key the host no longer has cannot move the chain, even a chain
// that has not started.
func TestAcceptRequiresTheCurrentKey(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	oldPub, oldKey, _ := ed25519.GenerateKey(rand.Reader)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := s.EnrollWithCertificate(ctx, "web-01", oldPub, "aa", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.EnrollWithCertificate(ctx, "web-01", newPub, "bb", t0); err != nil {
		t.Fatal(err)
	}
	e := protocol.NewSealer("web-01", oldKey, protocol.ChainState{}).Seal(protocol.KindHeartbeat, nil, t0)
	if err := s.AcceptWithKey(ctx, e, oldPub, protocol.ChainState{}, protocol.ChainState{Sequence: 1}, t0, true); !errors.Is(err, ErrChainMoved) {
		t.Fatalf("an envelope of the old key moved the new chain: %v", err)
	}
}
