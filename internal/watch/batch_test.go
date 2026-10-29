package watch

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"slices"
	"strconv"
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
	lostD, lostS, lostB := int64(0), int64(0), int64(0)
	b := &Batcher{
		Send: func(_ context.Context, p []byte) error {
			if fail {
				return errors.New("unreachable")
			}
			sent = append(sent, p)
			return nil
		},
		Lost:           func() (int64, int64) { return lostD, lostS },
		LostBudget:     func() int64 { return lostB },
		PackageManager: func() bool { return true },
		Now:            func() time.Time { return now },
	}
	b.add(Event{Class: ClassSSH, Op: OpCreate, Path: "/root/.ssh/authorized_keys"})
	lostD, lostS, lostB = 2, 1, 1
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
	if got.Event != BatchEvent || len(got.Events) != 2 || got.Dropped != 2 || got.DroppedBudget != 1 || got.Skipped != 1 || !got.PackageManager {
		t.Fatalf("batch %+v", got)
	}

	b.Flush(context.Background())
	if len(sent) != 1 {
		t.Fatal("an empty batch was sent")
	}
	lostD, lostB = 5, 3
	b.Flush(context.Background())
	if len(sent) != 2 || decodeBatch(t, sent[1]).Dropped != 3 || decodeBatch(t, sent[1]).DroppedBudget != 2 {
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
	// One batch a call, as the verifier accepts them.
	b.Flush(context.Background())
	if len(sent) != 1 {
		t.Fatalf("%d batches in one flush", len(sent))
	}
	for len(b.queue) > 0 {
		b.Flush(context.Background())
	}
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
	batch := b.next()
	if !strings.Contains(string(batch.Events[0]), "authorized_keys") || batch.Dropped != 6 || batch.DroppedSystem != 0 {
		t.Fatalf("the system event was pushed out: dropped %d, system %d", batch.Dropped, batch.DroppedSystem)
	}
	b = &Batcher{}
	for i := 0; i < MaxQueued+2; i++ {
		b.add(Event{Class: ClassService, Op: OpCreate, Path: "/etc/systemd/system/x.service"})
	}
	if batch := b.next(); batch.DroppedSystem != 2 {
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

// A change to root's keys goes out in the next batch, ahead of a flood of scripts in the uploads.
func TestBatcherSendsSystemEventsFirst(t *testing.T) {
	var sent [][]byte
	b := &Batcher{Now: time.Now, Send: func(_ context.Context, p []byte) error {
		sent = append(sent, p)
		return nil
	}}
	for i := 0; i < 2000; i++ {
		b.add(Event{Class: ClassUpload, Op: OpCreate, Path: "/srv/u/" + strings.Repeat("x", 900) + ".php"})
	}
	b.add(Event{Class: ClassSSH, Op: OpWrite, Path: "/root/.ssh/authorized_keys"})
	b.Flush(context.Background())
	if len(sent) != 1 || !strings.Contains(string(decodeBatch(t, sent[0]).Events[0]), "authorized_keys") {
		t.Fatal("the system event waits behind the flood")
	}
}

// At a stop, what cannot go out in the final burst is counted as lost, not dropped silently.
func TestBatcherCountsWhatIsLeftAtStop(t *testing.T) {
	in := make(chan Event)
	var sent [][]byte
	b := &Batcher{In: in, Now: time.Now, Done: make(chan struct{}), Send: func(_ context.Context, p []byte) error {
		sent = append(sent, p)
		return nil
	}}
	queued := MaxQueued
	for i := 0; i < queued; i++ {
		b.add(Event{Class: ClassService, Op: OpCreate, Path: "/etc/systemd/system/" + strings.Repeat("y", 2000) + ".service"})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b.Run(ctx)
	<-b.Done
	events, dropped, system := 0, int64(0), int64(0)
	for _, p := range sent {
		got := decodeBatch(t, p)
		events += len(got.Events)
		dropped += got.Dropped
		system += got.DroppedSystem
	}
	if events+int(dropped) != queued || system != dropped || dropped == 0 {
		t.Fatalf("%d sent, %d counted lost (%d system) of %d", events, dropped, system, queued)
	}
}

// An account flooding its own home ranks below root's paths, and past its quota below a webshell:
// neither waits behind it, nor is evicted for it.
func TestBatcherRanksAnAccountsHomeBelowRoot(t *testing.T) {
	var sent [][]byte
	b := &Batcher{Now: time.Now, Send: func(_ context.Context, p []byte) error {
		sent = append(sent, p)
		return nil
	}}
	b.SetHomes([]Home{{User: "root", Dir: "/root"}, {User: "alice", Dir: "/home/alice", UID: 1000}, {User: "etc", Dir: "/etc", UID: 2}})
	for i := 0; i < MaxQueued; i++ {
		b.add(Event{Class: ClassSSH, Op: OpCreate, Path: "/home/alice/.ssh/" + strings.Repeat("k", 900) + strconv.Itoa(i)})
	}
	b.add(Event{Class: ClassUpload, Op: OpCreate, Path: "/srv/u/shell.php"})
	for i := 0; i < 2*MaxQueued; i++ {
		b.add(Event{Class: ClassSSH, Op: OpCreate, Path: "/home/alice/.ssh/" + strings.Repeat("k", 900) + strconv.Itoa(i)})
	}
	b.add(Event{Class: ClassSSH, Op: OpWrite, Path: "/root/.ssh/authorized_keys"})
	b.add(Event{Class: ClassHook, Op: OpWrite, Path: "/etc/profile"})
	b.Flush(context.Background())
	got := decodeBatch(t, sent[0])
	var first []Event
	for _, raw := range got.Events {
		var e Event
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		first = append(first, e)
	}
	if first[0].Path != "/root/.ssh/authorized_keys" || first[1].Path != "/etc/profile" || first[1].Owner != "" {
		t.Fatalf("root's paths are not first: %+v %+v", first[0], first[1])
	}
	if first[2].Owner != "alice" {
		t.Fatalf("an account's home is not its own: %+v", first[2])
	}
	if !slices.ContainsFunc(first, func(e Event) bool { return e.Path == "/srv/u/shell.php" }) {
		t.Fatal("the webshell waits behind an account's flood or was evicted for it")
	}
	if got.DroppedSystem != 0 || got.Dropped == 0 {
		t.Fatalf("dropped %d, %d of root's", got.Dropped, got.DroppedSystem)
	}
}

// An event passed over by higher ranks goes first once it has waited MaxWait.
func TestBatcherSendsWhatWaitedTooLong(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	var sent [][]byte
	b := &Batcher{Now: func() time.Time { return now }, Send: func(_ context.Context, p []byte) error {
		sent = append(sent, p)
		return nil
	}}
	homes := []Home{}
	for u := 0; u < 8; u++ {
		homes = append(homes, Home{User: "u" + strconv.Itoa(u), Dir: "/home/u" + strconv.Itoa(u), UID: 1000 + u})
	}
	b.SetHomes(homes)
	b.add(Event{Class: ClassUpload, Op: OpCreate, Path: "/srv/u/shell.php"})
	now = now.Add(MaxWait + time.Second)
	for u := 0; u < 8; u++ {
		for i := 0; i < MaxQueuedPerOwner; i++ {
			b.add(Event{Class: ClassHook, Op: OpWrite, Path: "/home/u" + strconv.Itoa(u) + "/.bashrc", SHA256: strings.Repeat("a", 64) + strings.Repeat("p", 400)})
		}
	}
	b.Flush(context.Background())
	if !strings.Contains(string(decodeBatch(t, sent[0]).Events[0]), "shell.php") {
		t.Fatal("an event that waited MaxWait is still passed over")
	}
}

// Owners come from the homes and, in the spools, from the files' UIDs, never from their names.
func TestBatcherOwners(t *testing.T) {
	b := &Batcher{}
	b.SetHomes([]Home{{User: "root", Dir: "/root"}, {User: "alice", Dir: "/home/alice", UID: 1000}})
	alice, root := uint32(1001), uint32(0)
	for _, c := range []struct {
		e    Event
		want string
	}{
		{Event{Class: ClassSSH, Op: OpCreate, Path: "/home/alice/.ssh", Dir: true}, "alice"},
		{Event{Class: ClassSSH, Op: OpDelete, Path: "/home/alice/.ssh", Root: true}, "alice"},
		{Event{Class: ClassHook, Op: OpCreate, Path: "/home/alice/.ssh", Dir: true}, "alice"},
		{Event{Class: ClassSSH, Op: OpWrite, Path: "/home/alice/.ssh/authorized_keys"}, "alice"},
		{Event{Class: ClassSSH, Op: OpWrite, Path: "/root/.ssh/authorized_keys"}, ""},
		{Event{Class: ClassSchedule, Op: OpCreate, Path: "/var/spool/cron/crontabs/alice", UID: &alice}, "uid 1001"},
		{Event{Class: ClassSchedule, Op: OpCreate, Path: "/var/spool/cron/crontabs/toor", UID: &root}, ""},
		{Event{Class: ClassSchedule, Op: OpCreate, Path: "/var/spool/cron/crontabs/tmp.Xk3a9Q"}, "spool"},
		{Event{Class: ClassSchedule, Op: OpAttrib, Path: "/var/spool/cron/crontabs", Dir: true, UID: &root}, ""},
		{Event{Class: ClassSchedule, Op: OpDelete, Path: "/var/spool/cron/crontabs/root"}, ""},
		{Event{Class: ClassSchedule, Op: OpCreate, Path: "/var/spool/cron/atjobs/a0001", UID: &alice}, "uid 1001"},
		{Event{Class: ClassSchedule, Op: OpDelete, Path: "/var/spool/cron/atjobs/a0001"}, "uid 1001"},
		{Event{Class: ClassSchedule, Op: OpDelete, Path: "/var/spool/cron/atjobs/a0001"}, "spool"},
		{Event{Class: ClassSchedule, Op: OpDelete, Path: "/var/spool/cron", Root: true}, ""},
		{Event{Class: ClassSchedule, Op: OpCreate, Path: "/etc/cron.d/alice", UID: &alice}, ""},
	} {
		if got := b.owner(c.e); got != c.want {
			t.Errorf("owner of %s %s = %q, want %q", c.e.Op, c.e.Path, got, c.want)
		}
	}
}

func TestBatcherRootEvent(t *testing.T) {
	b := &Batcher{}
	b.SetHomes([]Home{{User: "root", Dir: "/root"}, {User: "alice", Dir: "/home/alice", UID: 1000}})
	alice, root := uint32(1000), uint32(0)
	for _, c := range []struct {
		e    Event
		want bool
	}{
		{Event{Class: ClassSSH, Path: "/root/.ssh/authorized_keys"}, true},
		{Event{Class: ClassSSH, Path: "/home/alice/.ssh"}, false},
		{Event{Class: ClassHook, Path: "/home/alice/.bashrc"}, false},
		{Event{Class: ClassHook, Path: "/etc/ld.so.preload"}, true},
		{Event{Class: ClassSchedule, Path: "/var/spool/cron/crontabs/tmp.Xk3a", UID: &alice}, false},
		{Event{Class: ClassSchedule, Path: "/var/spool/cron/crontabs/tmp.Xk3a"}, false},
		{Event{Class: ClassSchedule, Path: "/var/spool/cron/crontabs/root"}, true},
		{Event{Class: ClassSchedule, Path: "/var/spool/cron/crontabs/root", UID: &root}, true},
		{Event{Class: ClassSchedule, Path: "/etc/cron.d/job"}, true},
		{Event{Class: ClassUpload, Path: "/srv/u/x.php"}, false},
	} {
		if got := b.RootEvent(c.e); got != c.want {
			t.Errorf("%s: %v, want %v", c.e.Path, got, c.want)
		}
	}
}

// With a full queue an event costs the same to add whatever the queue holds.
func BenchmarkBatcherAddFull(b *testing.B) {
	bt := &Batcher{Now: time.Now}
	for i := 0; i < MaxQueued; i++ {
		bt.add(Event{Class: ClassService, Op: OpCreate, Path: "/etc/systemd/system/x.service"})
	}
	e := Event{Class: ClassUpload, Op: OpCreate, Path: "/srv/u/a.jpg"}
	for b.Loop() {
		bt.add(e)
	}
}

// A watched root moved away blinds the watch below it: it is never dropped as upload noise.
func TestRootEventIsNotNoise(t *testing.T) {
	if lowPriority(Event{Class: ClassUpload, Op: OpDelete, Path: "/srv/up", Dir: true, Root: true}) {
		t.Error("the root event of an upload directory is low priority")
	}
	if !lowPriority(Event{Class: ClassUpload, Op: OpCreate, Path: "/srv/up/d", Dir: true}) {
		t.Error("a directory created in the uploads is not low priority")
	}
}
