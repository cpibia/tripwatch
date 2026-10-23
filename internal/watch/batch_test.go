package watch

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
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

// A package manager counts only when a process of root holds its lock: a process merely named
// dpkg does not.
func TestPackageManagerRunning(t *testing.T) {
	saved := lockIdentity
	defer func() { lockIdentity = saved }()
	lockIdentity = func(fs.FileInfo) (uint32, string, bool) { return 0, "08:01:1312", true }
	fsys := fstest.MapFS{
		"var/lib/dpkg/lock-frontend": {Mode: 0o640},
		"proc/4242/comm":             {Data: []byte("dpkg\n")},
		"proc/4242/status":           {Data: []byte("Name:\tdpkg\nUid:\t33\t33\t33\t33\n")},
		"proc/locks":                 {Data: []byte("1: POSIX  ADVISORY  WRITE 4242 08:01:1312 0 EOF\n2: POSIX  ADVISORY  WRITE 1 00:2a:1312 0 EOF\n")},
	}
	if PackageManagerRunning(fsys) {
		t.Fatal("a lock held by the web user's process counted")
	}
	fsys["proc/4242/status"] = &fstest.MapFile{Data: []byte("Name:\tdpkg\nUid:\t0\t0\t0\t0\n")}
	if !PackageManagerRunning(fsys) {
		t.Fatal("root holding dpkg's lock did not count")
	}
	fsys["var/lib/dpkg/lock-frontend"] = &fstest.MapFile{Mode: 0o666}
	if PackageManagerRunning(fsys) {
		t.Fatal("a lock file anyone can write counted")
	}
}

// A full queue lets upload noise go before a change to a system path, and says when a system
// event had to go anyway.
func TestBatcherKeepsSystemEventsOverNoise(t *testing.T) {
	b := &Batcher{}
	b.add(Event{Class: ClassSSH, Op: OpWrite, Path: "/root/.ssh/authorized_keys"})
	for i := 0; i < MaxQueued+5; i++ {
		b.add(Event{Class: ClassUpload, Op: OpCreate, Path: "/srv/u/cat.jpg"})
	}
	batch, _ := b.next()
	if !strings.Contains(string(batch.Events[0]), "authorized_keys") || batch.Dropped != 6 || batch.DroppedSystem != 0 {
		t.Fatalf("the system event was pushed out: dropped %d, system %d", batch.Dropped, batch.DroppedSystem)
	}
	b = &Batcher{}
	for i := 0; i < MaxQueued+2; i++ {
		b.add(Event{Class: ClassService, Op: OpCreate, Path: "/etc/systemd/system/x.service"})
	}
	if batch, _ := b.next(); batch.DroppedSystem != 2 {
		t.Fatalf("system events lost silently: %+v", batch.DroppedSystem)
	}
}

// What is queued when the sensor stops is still sent, with a deadline of its own.
func TestBatcherFlushesOnStop(t *testing.T) {
	in := make(chan Event, 4)
	var sent [][]byte
	b := &Batcher{In: in, Done: make(chan struct{}), Send: func(ctx context.Context, p []byte) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		sent = append(sent, p)
		return nil
	}}
	in <- Event{Class: ClassPrivilege, Op: OpCreate, Path: "/etc/sudoers.d/x"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b.Run(ctx)
	<-b.Done
	if len(sent) != 1 || !strings.Contains(string(sent[0]), "sudoers.d") {
		t.Fatalf("sent %d batches at stop", len(sent))
	}
}
