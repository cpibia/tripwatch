//go:build linux

package watch

import (
	"context"
	"os"
	"path/filepath"
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
