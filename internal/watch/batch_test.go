package watch

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func decodeBatch(t *testing.T, payload []byte) Batch {
	t.Helper()
	var b Batch
	if err := json.Unmarshal(payload, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

// Events wait while the verifier is unreachable and go out, with what was lost, once it is back.
func TestBatcherKeepsEventsUntilSealed(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	var sent [][]byte
	fail := true
	lostD, lostS := int64(0), int64(0)
	b := &Batcher{
		Send: func(_ context.Context, p []byte) error {
			if fail {
				return errors.New("unreachable")
			}
			sent = append(sent, p)
			return nil
		},
		Lost:           func() (int64, int64) { return lostD, lostS },
		PackageManager: func() bool { return true },
		Now:            func() time.Time { return now },
	}
	b.add(Event{Class: ClassSSH, Op: OpCreate, Path: "/root/.ssh/authorized_keys"})
	lostD, lostS = 2, 1
	b.Flush(context.Background())
	if len(sent) != 0 || len(b.queue) != 1 {
		t.Fatalf("sent %d, queued %d after a failure", len(sent), len(b.queue))
	}

	fail = false
	b.add(Event{Class: ClassSSH, Op: OpDelete, Path: "/root/.ssh/authorized_keys"})
	b.Flush(context.Background())
	if len(sent) != 0 {
		t.Fatal("retried before the backoff")
	}
	now = now.Add(time.Minute)
	b.Flush(context.Background())
	if len(sent) != 1 {
		t.Fatalf("sent %d batches, want 1", len(sent))
	}
	got := decodeBatch(t, sent[0])
	if got.Event != BatchEvent || len(got.Events) != 2 || got.Dropped != 2 || got.Skipped != 1 || !got.PackageManager {
		t.Fatalf("batch %+v", got)
	}

	b.Flush(context.Background())
	if len(sent) != 1 {
		t.Fatal("an empty batch was sent")
	}
	lostD = 5
	b.Flush(context.Background())
	if len(sent) != 2 || decodeBatch(t, sent[1]).Dropped != 3 {
		t.Fatalf("losses alone are not reported: %d batches", len(sent))
	}
}

// A flood is split into batches the verifier accepts, and what exceeds the queue is counted.
func TestBatcherBoundsBatchesAndQueue(t *testing.T) {
	var sent [][]byte
	b := &Batcher{Send: func(_ context.Context, p []byte) error {
		sent = append(sent, p)
		return nil
	}}
	b.Now = time.Now
	for i := 0; i < MaxQueued+10; i++ {
		b.add(Event{Class: ClassUpload, Op: OpCreate, Path: "/var/www/site/uploads/" + strings.Repeat("x", 200)})
	}
	b.Flush(context.Background())
	if len(sent) < 2 {
		t.Fatalf("%d batches for a flood", len(sent))
	}
	total, dropped := 0, int64(0)
	for _, p := range sent {
		if len(p) > MaxBatchBytes+4096 {
			t.Fatalf("batch of %d bytes", len(p))
		}
		got := decodeBatch(t, p)
		total += len(got.Events)
		dropped += got.Dropped
	}
	if total != MaxQueued || dropped != 10 {
		t.Fatalf("%d events sent and %d dropped", total, dropped)
	}
}

func TestPackageManagerRunning(t *testing.T) {
	fsys := fstest.MapFS{
		"proc/1/comm":    {Data: []byte("systemd\n")},
		"proc/812/comm":  {Data: []byte("nginx\n")},
		"proc/self/comm": {Data: []byte("dpkg\n")},
	}
	if PackageManagerRunning(fsys) {
		t.Fatal("no package manager runs")
	}
	fsys["proc/4242/comm"] = &fstest.MapFile{Data: []byte("dpkg\n")}
	if !PackageManagerRunning(fsys) {
		t.Fatal("dpkg runs")
	}
}
