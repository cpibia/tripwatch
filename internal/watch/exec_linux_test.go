//go:build linux

package watch

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cpibia/tripwatch/internal/collector"
)

// A program started from /tmp and a shell started by the web server's user are reported as they
// start; an ordinary program is not.
func TestExecsReportStarts(t *testing.T) {
	ch := make(chan Event, 64)
	x, err := NewExecs(collector.NewSource("/"), ch)
	// CI sets TRIPWATCH_REQUIRE_PROC_CONNECTOR and runs this as root, where it must not skip.
	if (errors.Is(err, unix.EPERM) || errors.Is(err, unix.EPROTONOSUPPORT)) && os.Getenv("TRIPWATCH_REQUIRE_PROC_CONNECTOR") == "" {
		t.Skipf("the process connector is not available here (%v): it needs CAP_NET_ADMIN in the initial network namespace", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = x.Close() }()
	x.SetWebUsers([]int{33})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = x.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)

	dir, err := os.MkdirTemp("/tmp", "tw-exec-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	payload := filepath.Join(dir, "payload")
	sh, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Skip("no /bin/sleep to copy")
	}
	if err := os.WriteFile(payload, sh, 0o700); err != nil { //nolint:gosec // a test executable
		t.Fatal(err)
	}
	if err := exec.CommandContext(t.Context(), payload, "0.3").Run(); err != nil { //nolint:gosec // the test's own copy
		t.Fatal(err)
	}
	web := exec.CommandContext(t.Context(), "/bin/sh", "-c", "sleep 0.3")
	web.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 33, Gid: 33}}
	if os.Getuid() == 0 {
		if err := web.Run(); err != nil {
			t.Fatal(err)
		}
	}
	if err := exec.CommandContext(t.Context(), "/bin/true").Run(); err != nil {
		t.Fatal(err)
	}

	var got []Event
	deadline := time.After(3 * time.Second)
	for len(got) < 3 {
		select {
		case e := <-ch:
			got = append(got, e)
		case <-deadline:
			goto done
		}
	}
done:
	found := map[string]bool{}
	for _, e := range got {
		found[e.Reason+" "+e.Exe] = true
		if e.Exe == "/bin/true" || e.Exe == "/usr/bin/true" {
			t.Errorf("an ordinary program was reported: %+v", e)
		}
	}
	if !found[ReasonUnusualPath+" "+payload] {
		t.Errorf("the program from /tmp was not reported: %+v", got)
	}
	if os.Getuid() == 0 && !found[ReasonWebShell+" /bin/sh"] && !found[ReasonWebShell+" /bin/busybox"] && !found[ReasonWebShell+" /usr/bin/dash"] && !found[ReasonWebShell+" /bin/dash"] {
		t.Errorf("the web user's shell was not reported: %+v", got)
	}
}
