//go:build linux

package watch

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/system"
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
	// The capability is given up once subscribed (the sensor is built without cgo, which
	// AllThreadsSyscall needs; CI runs this test the same way).
	if x.CapDropErr != nil && !errors.Is(x.CapDropErr, syscall.ENOTSUP) {
		t.Fatalf("CAP_NET_ADMIN not dropped: %v", x.CapDropErr)
	}
	if status, err := os.ReadFile("/proc/self/status"); err == nil && x.CapDropErr == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
				if eff, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64); err == nil && eff&(1<<unix.CAP_NET_ADMIN) != 0 {
					t.Fatal("CAP_NET_ADMIN still effective after subscribing")
				}
			}
		}
	}
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
	// Named after what it is: uutils' multi-call binary, which /bin/sleep is on recent Ubuntu,
	// picks the utility by the name it is run as.
	payload := filepath.Join(dir, "sleep")
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

// A health check is the runtime's child, through a shell, also while runc is caught exiting; the
// same command under the PHP pool is not, and neither is a process named runc that is not the
// system's, root-run runtime, nor an exiting "runc" that no verified runtime started.
func TestFromRuntime(t *testing.T) {
	proc := func(fsys fstest.MapFS, pid, ppid, uid int, exe string) {
		dir := "proc/" + strconv.Itoa(pid) + "/"
		fsys[dir+"status"] = &fstest.MapFile{Data: []byte("Name:\tx\nPPid:\t" + strconv.Itoa(ppid) + "\nUid:\t" + strings.Repeat(strconv.Itoa(uid)+"\t", 4) + "\n")}
		fsys[dir+"exe"] = &fstest.MapFile{Data: []byte(exe), Mode: fs.ModeSymlink}
		fsys[dir+"cmdline"] = &fstest.MapFile{Data: []byte(path.Base(exe) + "\x00")}
	}
	fsys := fstest.MapFS{}
	proc(fsys, 10, 1, 0, "/usr/bin/containerd-shim-runc-v2")
	proc(fsys, 20, 10, 33, "/bin/busybox")
	proc(fsys, 21, 20, 33, "/usr/bin/curl")
	proc(fsys, 30, 10, 33, "/usr/local/sbin/php-fpm")
	proc(fsys, 31, 30, 33, "/bin/busybox")
	proc(fsys, 40, 1, 33, "/tmp/runc")
	proc(fsys, 41, 40, 33, "/bin/busybox")
	exiting := func(pid, ppid, uid int) {
		dir := "proc/" + strconv.Itoa(pid) + "/"
		fsys[dir+"status"] = &fstest.MapFile{Data: []byte("Name:\trunc\nState:\tZ (zombie)\nPPid:\t" + strconv.Itoa(ppid) + "\nUid:\t" + strings.Repeat(strconv.Itoa(uid)+"\t", 4) + "\n")}
		fsys[dir+"comm"] = &fstest.MapFile{Data: []byte("runc\n")}
	}
	exiting(50, 10, 0)
	proc(fsys, 51, 50, 33, "/bin/busybox")
	exiting(60, 30, 0)
	proc(fsys, 61, 60, 33, "/bin/busybox")
	exiting(70, 10, 33)
	proc(fsys, 71, 70, 33, "/bin/busybox")
	x := &Execs{src: collector.Source{FS: fsys}}
	read := func(pid int) system.Process {
		p, ok := system.ReadProcess(fsys, pid)
		if !ok {
			t.Fatalf("pid %d unreadable", pid)
		}
		return p
	}
	if !x.fromRuntime(read(20)) || !x.fromRuntime(read(21)) {
		t.Error("a health check is not taken for the runtime's")
	}
	if x.fromRuntime(read(31)) || x.fromRuntime(read(41)) {
		t.Error("a shell of the PHP pool or of a fake runtime is taken for the runtime's")
	}
	if !x.fromRuntime(read(51)) {
		t.Error("a health check whose runc is exiting is not taken for the runtime's")
	}
	if x.fromRuntime(read(61)) || x.fromRuntime(read(71)) {
		t.Error("an exiting runc not started by a runtime, or not root, is taken for the runtime's")
	}
}

// A health check's shell seen started by the runtime vouches for the command it runs, inspected
// once runc has gone; a process that took the shell's PID later does not.
func TestRuntimeShellRemembered(t *testing.T) {
	fsys := fstest.MapFS{}
	proc := func(pid, ppid, uid int, exe string, start int) {
		dir := "proc/" + strconv.Itoa(pid) + "/"
		fsys[dir+"status"] = &fstest.MapFile{Data: []byte("Name:\tx\nPPid:\t" + strconv.Itoa(ppid) + "\nUid:\t" + strings.Repeat(strconv.Itoa(uid)+"\t", 4) + "\n")}
		fsys[dir+"exe"] = &fstest.MapFile{Data: []byte(exe), Mode: fs.ModeSymlink}
		fsys[dir+"cmdline"] = &fstest.MapFile{Data: []byte(path.Base(exe) + "\x00")}
		fsys[dir+"stat"] = &fstest.MapFile{Data: []byte(strconv.Itoa(pid) + " (x) S " + strconv.Itoa(ppid) + strings.Repeat(" 0", 17) + " " + strconv.Itoa(start) + " 0 0\n")}
	}
	proc(10, 1, 0, "/usr/bin/containerd-shim-runc-v2", 100)
	proc(15, 10, 0, "/usr/sbin/runc", 400)
	proc(20, 15, 101, "/bin/busybox", 500)
	proc(21, 20, 101, "/usr/bin/wget", 501)
	x := &Execs{src: collector.Source{FS: fsys}}
	read := func(pid int) system.Process {
		p, ok := system.ReadProcess(fsys, pid)
		if !ok {
			t.Fatalf("pid %d unreadable", pid)
		}
		return p
	}
	if !x.fromRuntime(read(20)) {
		t.Fatal("the health check's shell is not taken for the runtime's")
	}
	for name := range fsys {
		if strings.HasPrefix(name, "proc/15/") {
			delete(fsys, name)
		}
	}
	if !x.fromRuntime(read(21)) {
		t.Error("the command of a shell seen started by the runtime is not taken for the runtime's once runc is gone")
	}
	proc(20, 15, 101, "/bin/busybox", 900)
	if x.fromRuntime(read(21)) {
		t.Error("a process that took the shell's PID is taken for the runtime's")
	}
}

// The executables remembered from process starts answer for a process gone by its change of
// user, the oldest forgotten past the bound and a reused PID answered with its latest start.
func TestRecentExes(t *testing.T) {
	var r recentExes
	r.add(10, "/usr/bin/sudo", false)
	if exe, _ := r.get(10); exe != "/usr/bin/sudo" {
		t.Fatalf("remembered %q", exe)
	}
	r.add(10, "/tmp/x", true)
	if exe, deleted := r.get(10); exe != "/tmp/x" || !deleted {
		t.Fatalf("a reused PID: %q %v", exe, deleted)
	}
	for pid := 11; pid < 11+maxRecentExes; pid++ {
		r.add(pid, "/usr/bin/true", false)
	}
	if exe, _ := r.get(10); exe != "" || len(r.exes) != maxRecentExes {
		t.Errorf("past the bound: %q, %d kept", exe, len(r.exes))
	}
	if p := (system.Process{Exe: "/usr/bin/sudo"}); privileged(p, 1000, 0) {
		t.Error("sudo, read at its start, taken for a backdoor")
	}
}

// A job counts as cron's only when its parent, through shells, is a cron of root run from a
// system directory: a process of a user named cron, a copy elsewhere or a deleted binary is not.
func TestFromCronNeedsRootsCron(t *testing.T) {
	proc := func(fsys fstest.MapFS, pid, ppid, uid int, exe string) {
		dir := "proc/" + strconv.Itoa(pid) + "/"
		fsys[dir+"status"] = &fstest.MapFile{Data: []byte("Name:\tx\nPPid:\t" + strconv.Itoa(ppid) + "\nUid:\t" + strconv.Itoa(uid) + "\t" + strconv.Itoa(uid) + "\t0\t0\n")}
		fsys[dir+"exe"] = &fstest.MapFile{Data: []byte(exe), Mode: fs.ModeSymlink}
	}
	for _, c := range []struct {
		name string
		uid  int
		exe  string
		want bool
	}{
		{"root's cron", 0, "/usr/sbin/cron", true},
		{"a user's process named cron", 1000, "/usr/sbin/cron", false},
		{"a copy of cron elsewhere", 0, "/home/ubuntu/cron", false},
		{"a deleted cron", 0, "/usr/sbin/cron (deleted)", false},
	} {
		fsys := fstest.MapFS{}
		proc(fsys, 70, 1, c.uid, c.exe)
		proc(fsys, 77, 70, 1000, "/usr/bin/dash")
		x := &Execs{src: collector.Source{FS: fsys}}
		if got := x.fromCron(system.Process{PID: 80, PPID: 77, UID: 1000}); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
