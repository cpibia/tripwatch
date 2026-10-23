//go:build linux

package watch

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
)

// collect gathers the events that arrive within a short while.
func collect(t *testing.T, ch <-chan Event, want int) []Event {
	t.Helper()
	var got []Event
	deadline := time.After(3 * time.Second)
	for len(got) < want {
		select {
		case e := <-ch:
			got = append(got, e)
		case <-deadline:
			return got
		}
	}
	// Give stragglers a moment, so a test sees duplicates too.
	time.Sleep(200 * time.Millisecond)
	for {
		select {
		case e := <-ch:
			got = append(got, e)
		default:
			return got
		}
	}
}

func has(events []Event, class, op, p string) bool {
	for _, e := range events {
		if e.Class == class && e.Op == op && e.Path == p {
			return true
		}
	}
	return false
}

// Watched paths report creation, writes and removal as they happen, with the file's hash;
// a recursive upload target follows directories created later, and a home's .ssh created after
// the watch started is watched too.
func TestFilesReportChanges(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"etc/sudoers.d", "home/alice", "srv/app/uploads"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	src := collector.NewSource(root)
	ch := make(chan Event, 256)
	f, err := NewFiles(root, src, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	f.Set(Targets([]Home{{User: "alice", Dir: "/home/alice"}}, []string{"/srv/app/uploads"}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.Run(ctx) }()

	write := func(rel, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, rel), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/sudoers.d/90-x", "x ALL=(ALL) NOPASSWD:ALL\n")
	write("etc/passwd", "root:x:0:0::/root:/bin/sh\n")
	write("etc/unrelated.conf", "nothing to see\n")
	if err := os.MkdirAll(filepath.Join(root, "srv/app/uploads/2026/10"), 0o750); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	write("srv/app/uploads/2026/10/x.php", "<?php system($_GET['c']);")
	if err := os.Remove(filepath.Join(root, "srv/app/uploads/2026/10/x.php")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "home/alice/.ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	write("home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA test\n")

	got := collect(t, ch, 8)
	for _, w := range []struct{ class, op, path string }{
		{ClassPrivilege, OpWrite, "/etc/sudoers.d/90-x"},
		{ClassAccounts, OpCreate, "/etc/passwd"},
		{ClassUpload, OpCreate, "/srv/app/uploads/2026"},
		{ClassUpload, OpWrite, "/srv/app/uploads/2026/10/x.php"},
		{ClassUpload, OpDelete, "/srv/app/uploads/2026/10/x.php"},
		{ClassSSH, OpCreate, "/home/alice/.ssh"},
		{ClassSSH, OpWrite, "/home/alice/.ssh/authorized_keys"},
	} {
		if !has(got, w.class, w.op, w.path) {
			t.Errorf("missing %s %s %s in %+v", w.class, w.op, w.path, got)
		}
	}
	for _, e := range got {
		if e.Path == "/etc/unrelated.conf" {
			t.Error("an unwatched name was reported")
		}
		if e.Path == "/etc/sudoers.d/90-x" && e.Op == OpWrite && (e.SHA256 == "" || e.Size == 0) {
			t.Errorf("no hash for the written file: %+v", e)
		}
	}
}

// A link planted in a watched directory is reported without being followed.
func TestFilesDoNotFollowLinks(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "srv/up"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	ch := make(chan Event, 16)
	f, err := NewFiles(root, collector.NewSource(root), ch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	f.Set([]Target{{Dir: "/srv/up", Class: ClassUpload, Recursive: true}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.Run(ctx) }()
	if err := os.Symlink(filepath.Join(root, "secret"), filepath.Join(root, "srv/up/l.php")); err != nil {
		t.Fatal(err)
	}
	got := collect(t, ch, 1)
	if len(got) == 0 || got[0].SHA256 != "" || got[0].Mode == "" {
		t.Fatalf("link event = %+v", got)
	}
}

// What the bounds leave unwatched is said, not silently skipped; a terminal reached through a
// link in the uploads is never opened.
func TestFilesReportGapsAndSkipDevices(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "srv/u/a/b/c/d/e/f")
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}
	src := collector.NewSource(root)
	ch := make(chan Event, 16)
	f, err := NewFiles(root, src, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	f.Set([]Target{{Dir: "/srv/u", Class: ClassUpload, Recursive: true}})
	found := false
	for _, issue := range f.Issues() {
		found = found || strings.Contains(issue, "deeper than")
	}
	if !found {
		t.Fatalf("depth gap not reported: %v", f.Issues())
	}
	// A directory created later past the depth limit is a gap too.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.Run(ctx) }()
	if err := os.Mkdir(filepath.Join(root, "srv/u/a/b/c/x"), 0o750); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := os.Mkdir(filepath.Join(root, "srv/u/a/b/c/x/y"), 0o750); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(strings.Join(f.Issues(), "\n"), "/srv/u/a/b/c/x has directories deeper") {
		if time.Now().After(deadline) {
			t.Fatalf("live depth gap not reported: %v", f.Issues())
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Root's files have a hashing budget the other users cannot spend.
	for f.spend(1<<20, false) {
	}
	if !f.spend(1<<20, true) {
		t.Fatal("the users' hashing spent root's budget")
	}
	if err := os.Symlink("/dev/tty", filepath.Join(root, "srv/u/x.php")); err != nil {
		t.Fatal(err)
	}
	e := f.describe(ClassUpload, OpCreate, "/srv/u/x.php", false)
	if e.SHA256 != "" || !strings.HasPrefix(e.Mode, "L") {
		t.Fatalf("a link was followed: %+v", e)
	}
}

// A keys file that existed before the watch carries its earlier content into the events, so a
// key added and then removed shows as a return to it.
func TestFilesRememberPreviousContent(t *testing.T) {
	root := t.TempDir()
	keys := filepath.Join(root, "home/ops/.ssh/authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("ssh-ed25519 AAAA ops\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := collector.NewSource(root)
	ch := make(chan Event, 16)
	f, err := NewFiles(root, src, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	f.Set(Targets([]Home{{User: "ops", Dir: "/home/ops"}}, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	for _, content := range []string{"ssh-ed25519 AAAA ops\nssh-ed25519 BBBB intruder\n", "ssh-ed25519 AAAA ops\n"} {
		if err := os.WriteFile(keys, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	var writes []Event
	for _, e := range collect(t, ch, 2) {
		if e.Op == OpWrite && e.Path == "/home/ops/.ssh/authorized_keys" {
			writes = append(writes, e)
		}
	}
	if len(writes) != 2 || writes[0].PrevSHA256 == "" || writes[1].SHA256 != writes[0].PrevSHA256 || writes[1].PrevSHA256 != writes[0].SHA256 {
		t.Fatalf("writes = %+v", writes)
	}
}

// In the scratch directories only executables are reported, and the removal of those.
func TestFilesScratchReportsExecutablesOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "tmp"), 0o750); err != nil {
		t.Fatal(err)
	}
	src := collector.NewSource(root)
	ch := make(chan Event, 64)
	f, err := NewFiles(root, src, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	f.Set(Targets(nil, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	plain, dropper := filepath.Join(root, "tmp/sess_1"), filepath.Join(root, "tmp/.d")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropper, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dropper, 0o700); err != nil { //nolint:gosec // the test's dropper
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := os.Remove(plain); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dropper); err != nil {
		t.Fatal(err)
	}
	got := collect(t, ch, 2)
	for _, e := range got {
		if e.Path == "/tmp/sess_1" {
			t.Errorf("a plain file in /tmp was reported: %+v", e)
		}
	}
	if !has(got, ClassScratch, OpAttrib, "/tmp/.d") || !has(got, ClassScratch, OpDelete, "/tmp/.d") {
		t.Fatalf("events = %+v", got)
	}
}

// Directories created in /tmp by anyone never take the watches of the system, the homes or the
// uploads; places those lose to the bounds are listed for the verifier.
func TestFilesScratchCannotStarveSystemWatches(t *testing.T) {
	root := t.TempDir()
	for i := range MaxScratchWatches + 100 {
		if err := os.MkdirAll(filepath.Join(root, "tmp", "d"+strconv.Itoa(i)), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "root/.ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	src := collector.NewSource(root)
	ch := make(chan Event, 16)
	f, err := NewFiles(root, src, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	f.Set(Targets([]Home{{User: "root", Dir: "/root"}}, nil))
	if f.scratchWatches > MaxScratchWatches || len(f.Unwatched()) != 0 {
		t.Fatalf("scratch watches %d, unwatched %v", f.scratchWatches, f.Unwatched())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(root, "root/.ssh/authorized_keys"), []byte("ssh-ed25519 AAAA x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := collect(t, ch, 1); !has(got, ClassSSH, OpCreate, "/root/.ssh/authorized_keys") {
		t.Fatalf("root's keys unwatched behind a flood of /tmp: %+v", got)
	}
}
