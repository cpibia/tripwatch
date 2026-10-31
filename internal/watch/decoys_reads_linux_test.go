//go:build linux

package watch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
)

// A read of a decoy names the process; one among many files of its directory read by the same
// process is marked as a sweep, whoever runs it (the verifier lowers only root's); the sensor's
// own reads are never reported.
func TestDecoyReads(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{filepath.Dir(root), root} {
		if err := os.Chmod(d, 0o755); err != nil { //nolint:gosec // another user reads the files below
			t.Fatal(err)
		}
	}
	dir := filepath.Join(root, "srv/backup")
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // see above
		t.Fatal(err)
	}
	for i := range 20 {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%02d.sql", i)), []byte("x\n"), 0o644); err != nil { //nolint:gosec // see above
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "10-full.sql"), []byte("bait\n"), 0o644); err != nil { //nolint:gosec // see above
		t.Fatal(err)
	}
	src := collector.NewSource(root)
	ch := make(chan Event, 64)
	d, err := NewDecoys(src, ch)
	if errors.Is(err, syscall.EPERM) {
		t.Skip("fanotify needs CAP_SYS_ADMIN")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	d.proc = collector.NewSource("/").FS
	if failed := d.Set([]string{"/srv/backup/10-full.sql"}); len(failed) > 0 {
		t.Fatal(failed)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Run(ctx) }()

	run := func(uid uint32, script string) Event {
		t.Helper()
		cmd := exec.CommandContext(ctx, "sh", "-c", script) //nolint:gosec // the test's own scripts
		cmd.Dir = dir
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", script, err, out)
		}
		select {
		case e := <-ch:
			return e
		case <-time.After(DecoyHold + 3*time.Second):
			t.Fatalf("%s: no event", script)
			return Event{}
		}
	}
	// The shell reads the files itself and lingers, so that its process is there to be named.
	if e := run(0, "read x < 10-full.sql; sleep 1; true"); e.Path != "/srv/backup/10-full.sql" || e.Reason != "" || e.User == nil || *e.User != 0 || e.Comm != "sh" {
		t.Errorf("isolated read: %+v", e)
	}
	if e := run(0, "for f in *.sql; do read x < $f; done; sleep 1; true"); e.Reason != ReasonSweep || e.Exe == "" {
		t.Errorf("sweep by root: %+v", e)
	}
	// The web server's user going through the directory to reach the decoy is a sweep too, and
	// its user says it is not root's.
	if e := run(33, "for f in *.sql; do read x < $f; done; sleep 1; true"); e.Reason != ReasonSweep || e.User == nil || *e.User != 33 {
		t.Errorf("sweep by another user: %+v", e)
	}
	if _, err := os.ReadFile(filepath.Join(dir, "10-full.sql")); err != nil { //nolint:gosec // the test's own file
		t.Fatal(err)
	}
	select {
	case e := <-ch:
		t.Errorf("the sensor's own read: %+v", e)
	case <-time.After(DecoyHold + time.Second):
	}
}
