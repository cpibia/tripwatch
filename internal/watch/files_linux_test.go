//go:build linux

package watch

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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

// Below a directory only root can enter, depth is no hiding place: no gap is reported there,
// while the same tree open to the group still is.
func TestFilesSkipGapsOnlyRootCanReach(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to own the directories")
	}
	root := t.TempDir()
	for _, d := range []string{"tmp/snap-private-tmp/snap.lxd/tmp/x", "tmp/open/shared/tmp/x"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "tmp/open/shared"), 0o750); err != nil { //nolint:gosec // the group can enter it on purpose
		t.Fatal(err)
	}
	f, err := NewFiles(root, collector.NewSource(root), make(chan Event, 16))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	f.Set([]Target{{Dir: "/tmp", Class: ClassScratch, Recursive: true, Depth: ScratchDepth}})
	var gaps []string
	for _, issue := range f.Issues() {
		if strings.Contains(issue, "deeper than") {
			gaps = append(gaps, issue)
		}
	}
	if len(gaps) != 1 || !strings.Contains(gaps[0], "/tmp/open/shared ") {
		t.Fatalf("gaps = %v, want only the one under /tmp/open/shared", gaps)
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
	if f.classWatches[ClassScratch] > MaxScratchWatches || slices.ContainsFunc(f.Unwatched(), func(u string) bool { return !strings.HasPrefix(u, ClassScratch+":") }) {
		t.Fatalf("scratch watches %d, unwatched %v", f.classWatches[ClassScratch], f.Unwatched())
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

// kernelWatches counts the watches the kernel holds on an inotify instance.
func kernelWatches(t *testing.T, fd int) int {
	t.Helper()
	data, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "inotify wd:")
}

// A watched directory renamed within the perimeter keeps reporting under its new name, and a
// loop of renames leaves the kernel holding no more watches than the sensor knows of.
func TestFilesFollowRenamedDirectories(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"srv/app/uploads/2024/a", "etc/systemd/system/x.service.d", "tmp/w"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	src := collector.NewSource(root)
	ch := make(chan Event, 4096)
	f, err := NewFiles(root, src, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	f.Set(Targets(nil, []string{"/srv/app/uploads"}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	for _, mv := range [][2]string{{"srv/app/uploads/2024", "srv/app/uploads/2025"}, {"etc/systemd/system/x.service.d", "etc/systemd/system/y.service.d"}} {
		if err := os.Rename(filepath.Join(root, mv[0]), filepath.Join(root, mv[1])); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	for len(ch) > 0 {
		<-ch
	}
	writes := map[string]string{
		"srv/app/uploads/2025/a/shell.php":             "<?php system($_GET['c']);",
		"etc/systemd/system/y.service.d/override.conf": "[Service]\nExecStartPre=/tmp/x\n",
	}
	for p, content := range writes {
		if err := os.WriteFile(filepath.Join(root, p), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := collect(t, ch, 2)
	if !has(got, ClassUpload, OpCreate, "/srv/app/uploads/2025/a/shell.php") || !has(got, ClassService, OpCreate, "/etc/systemd/system/y.service.d/override.conf") {
		t.Fatalf("events after renames: %+v", got)
	}
	for i := range 300 {
		dir := filepath.Join(root, "tmp/w", "d"+strconv.Itoa(i))
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(dir, dir+"x"); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(dir + "x"); err != nil {
			t.Fatal(err)
		}
	}
	// Out of the perimeter: the watches go with the directory.
	for i := range 300 {
		dir := filepath.Join(root, "tmp/w", "o"+strconv.Itoa(i))
		if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o750); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
		if err := os.Rename(dir, filepath.Join(root, "out"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(500 * time.Millisecond)
	f.mu.Lock()
	known := len(f.byWD)
	f.mu.Unlock()
	if kernel := kernelWatches(t, f.fd); kernel != known {
		t.Fatalf("the kernel holds %d watches, the sensor knows %d", kernel, known)
	}
}

// The root of a watched place moved away and back is reported and watched again within
// seconds.
func TestFilesRootMovedAndBack(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "srv/app/uploads"), 0o750); err != nil {
		t.Fatal(err)
	}
	src := collector.NewSource(root)
	ch := make(chan Event, 64)
	f, err := NewFiles(root, src, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	f.Set(Targets(nil, []string{"/srv/app/uploads"}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	up := filepath.Join(root, "srv/app/uploads")
	if err := os.Rename(up, up+".x"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(up+".x", up); err != nil {
		t.Fatal(err)
	}
	gone := false
	deadline := time.After(5 * time.Second)
	for !gone {
		select {
		case e := <-ch:
			gone = e.Root && e.Path == "/srv/app/uploads"
		case <-deadline:
			t.Fatal("the moved root was not reported")
		}
	}
	time.Sleep(3 * time.Second)
	if err := os.WriteFile(filepath.Join(up, "shell.php"), []byte("<?php"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := collect(t, ch, 1); !has(got, ClassUpload, OpCreate, "/srv/app/uploads/shell.php") {
		t.Fatalf("the root moved back is not watched again: %+v", got)
	}
}

// Two directories swapped in one call are watched again under their right names, and the
// records of renames do not pile up.
func TestFilesExchangedDirectories(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"srv/u/a", "srv/u/b"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	src := collector.NewSource(root)
	ch := make(chan Event, 4096)
	f, err := NewFiles(root, src, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	f.Set(Targets(nil, []string{"/srv/u"}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	a, b := filepath.Join(root, "srv/u/a"), filepath.Join(root, "srv/u/b")
	n := 200
	if v := os.Getenv("TW_EXCHANGES"); v != "" {
		n, _ = strconv.Atoi(v)
	}
	for range n {
		if err := unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE); err != nil {
			t.Skipf("renameat2 exchange not supported here: %v", err)
		}
	}
	time.Sleep(2 * time.Second)
	for len(ch) > 0 {
		<-ch
	}
	for _, p := range []string{a, b} {
		if err := os.WriteFile(filepath.Join(p, "x.php"), []byte("<?php"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := collect(t, ch, 2)
	if !has(got, ClassUpload, OpCreate, "/srv/u/a/x.php") || !has(got, ClassUpload, OpCreate, "/srv/u/b/x.php") {
		f.mu.Lock()
		dirs := map[string]int{}
		for d, wd := range f.byDir {
			dirs[d] = wd
		}
		recs := map[int]string{}
		for wd, w := range f.byWD {
			recs[wd] = w.dir
		}
		f.mu.Unlock()
		t.Fatalf("events after exchanges: %d, byDir %v, byWD %v, kernel %d, issues %v, dropped %d, class %v, replan %v", len(got), dirs, recs, kernelWatches(t, f.fd), f.Issues(), f.Dropped.Load(), f.classWatches, f.replanAt)
	}
	f.mu.Lock()
	renamed := len(f.renamed)
	f.mu.Unlock()
	if renamed > 2 {
		t.Fatalf("%d rename records left", renamed)
	}
}

// The root of a target under a watched parent (/etc/sudoers.d) moved aside and back is
// reported and watched again: the kernel reports the parent's side of the rename first, and
// the root's own event finds no record.
func TestFilesRootUnderWatchedParent(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/sudoers.d"), 0o750); err != nil {
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
	dir := filepath.Join(root, "etc/sudoers.d")
	if err := os.Rename(dir, dir+".x"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir+".x", dir); err != nil {
		t.Fatal(err)
	}
	if got := collect(t, ch, 1); !has(got, ClassPrivilege, OpDelete, "/etc/sudoers.d") {
		t.Fatalf("the moved root was not reported: %+v", got)
	}
	time.Sleep(3 * time.Second)
	if err := os.WriteFile(filepath.Join(dir, "zz"), []byte("x ALL=(ALL) ALL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := collect(t, ch, 1); !has(got, ClassPrivilege, OpCreate, "/etc/sudoers.d/zz") {
		t.Fatalf("the root moved back is not watched again: %+v", got)
	}
}

// An ancestor of the uploads moved aside and recreated leaves the old inode watched under a
// path that is now another directory's: the check of the roots reports it, drops the old
// watches and watches the directory now at the path.
func TestFilesAncestorReplaced(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "srv/app/wc/uploads/2024"), 0o750); err != nil {
		t.Fatal(err)
	}
	src := collector.NewSource(root)
	ch := make(chan Event, 64)
	f, err := NewFiles(root, src, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	f.Set(Targets(nil, []string{"/srv/app/wc/uploads"}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	wc := filepath.Join(root, "srv/app/wc")
	if err := os.Rename(wc, wc+".x"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(wc, "uploads/2024"), 0o750); err != nil {
		t.Fatal(err)
	}
	gone := false
	deadline := time.After(5 * time.Second)
	for !gone {
		select {
		case e := <-ch:
			gone = e.Root && e.Path == "/srv/app/wc/uploads"
		case <-deadline:
			t.Fatal("the replaced root was not reported")
		}
	}
	time.Sleep(3 * time.Second)
	if err := os.WriteFile(filepath.Join(wc+".x", "uploads/old.php"), []byte("<?php"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wc, "uploads/2024/shell.php"), []byte("<?php"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := collect(t, ch, 1)
	if !has(got, ClassUpload, OpCreate, "/srv/app/wc/uploads/2024/shell.php") {
		t.Fatalf("the directory now at the path is not watched: %+v", got)
	}
	if has(got, ClassUpload, OpCreate, "/srv/app/wc/uploads/old.php") {
		t.Fatalf("the old inode still reports under the path: %+v", got)
	}
}
