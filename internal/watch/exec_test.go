package watch

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/collector/system"
)

// A job run every minute is reported once an hour, with the starts left out counted; anything
// that differs is reported at once, and a full memory reports rather than stays silent.
func TestRepeatedStartsAreReportedOnceAWindow(t *testing.T) {
	t0 := time.Date(2026, 10, 28, 7, 0, 0, 0, time.UTC)
	job := []string{ReasonWebShell, "/usr/bin/dash", "", "php", "1000", "1000", "/var/www/html", "sh -c /usr/bin/php8.3 artisan schedule:run"}
	var r repeats
	if ok, n := r.report(t0, job...); !ok || n != 0 {
		t.Fatalf("first start: %v %d", ok, n)
	}
	for m := 1; m < 60; m++ {
		if ok, _ := r.report(t0.Add(time.Duration(m)*time.Minute), job...); ok {
			t.Fatalf("repeat at minute %d reported", m)
		}
	}
	if ok, n := r.report(t0.Add(RepeatWindow), job...); !ok || n != 59 {
		t.Fatalf("after the window: %v %d", ok, n)
	}

	longer := append([]string(nil), job...)
	longer[7] += strings.Repeat(" x", 3000)
	other := append([]string(nil), longer...)
	other[7] += " ; id"
	for _, start := range [][]string{longer, other} {
		if ok, _ := r.report(t0.Add(RepeatWindow), start...); !ok {
			t.Errorf("a different start was left out: %.40s", start[7])
		}
	}
	// A clock set back does not hold a start back for longer than the window.
	if ok, _ := r.report(t0, job...); !ok {
		t.Error("a start before the last report was left out")
	}

	var full repeats
	for i := range maxRepeatKeys {
		full.report(t0, "exec", strconv.Itoa(i))
	}
	for range 3 {
		if ok, _ := full.report(t0.Add(time.Minute), job...); !ok {
			t.Fatal("with the memory full of recent starts, a repeat was left out")
		}
	}
	if len(full.seen) > maxRepeatKeys {
		t.Fatalf("%d starts remembered", len(full.seen))
	}
	// Once the old starts expire they make room.
	if ok, _ := full.report(t0.Add(RepeatWindow), job...); !ok {
		t.Fatal("first start after expiry")
	}
	if ok, _ := full.report(t0.Add(RepeatWindow+time.Minute), job...); ok {
		t.Fatal("the job was not remembered after the old starts expired")
	}
}

func TestClassifyExec(t *testing.T) {
	ctx := execContext{
		webUsers: map[int]bool{33: true},
		homes:    map[int]string{33: "/var/www", 1000: "/home/ubuntu"},
		uploads:  []string{"/home/ubuntu/applications/site/public/uploads"},
		// PPID 77 is cron; files under /home/ubuntu belong to 1000, but for one.
		fromCron: func(p system.Process) bool { return p.PPID == 77 },
		owner: func(f string) (int, bool) {
			if strings.HasPrefix(f, "/home/ubuntu/") && !strings.HasSuffix(f, "/root-owned.sh") {
				return 1000, true
			}
			return 0, true
		},
	}
	for _, c := range []struct {
		p      system.Process
		want   string
		script string
	}{
		{system.Process{UID: 0, Exe: "/usr/bin/dash", Cmdline: "/bin/sh /tmp/.dropper"}, ReasonUnusualPath, "/tmp/.dropper"},
		{system.Process{UID: 1000, PPID: 77, Exe: "/usr/bin/bash", Cmdline: "/bin/bash /home/ubuntu/applications/send_email.sh"}, "", "/home/ubuntu/applications/send_email.sh"},
		{system.Process{UID: 1000, PPID: 5, Exe: "/usr/bin/bash", Cmdline: "/bin/bash /home/ubuntu/applications/send_email.sh"}, ReasonUnusualPath, "/home/ubuntu/applications/send_email.sh"},
		{system.Process{UID: 1001, PPID: 77, Exe: "/usr/bin/bash", Cmdline: "/bin/bash /home/ubuntu/applications/send_email.sh"}, ReasonUnusualPath, "/home/ubuntu/applications/send_email.sh"},
		{system.Process{UID: 1000, PPID: 77, Exe: "/usr/bin/bash", Cmdline: "/bin/bash /home/ubuntu/../../tmp/x.sh"}, ReasonUnusualPath, "/tmp/x.sh"},
		{system.Process{UID: 1000, PPID: 77, Exe: "/usr/bin/bash", Cmdline: "/bin/bash /home/ubuntu/applications/site/public/uploads/x.sh"}, ReasonUnusualPath, "/home/ubuntu/applications/site/public/uploads/x.sh"},
		{system.Process{UID: 1000, PPID: 77, Exe: "/usr/bin/bash", Cmdline: "/bin/bash /home/ubuntu/root-owned.sh"}, ReasonUnusualPath, "/home/ubuntu/root-owned.sh"},
		{system.Process{UID: 33, Exe: "/usr/bin/perl", Cmdline: "perl /var/www/shop/x.pl"}, ReasonWebShell, "/var/www/shop/x.pl"},
		{system.Process{UID: 0, Exe: "/usr/bin/python3.11", Cmdline: "python3 -u /dev/shm/x.py arg"}, ReasonUnusualPath, "/dev/shm/x.py"},
		{system.Process{UID: 0, Exe: "/usr/bin/bash", Cmdline: "bash -c /tmp/x"}, "", ""},
		{system.Process{UID: 0, Exe: "/usr/bin/bash", Cmdline: "/bin/bash /usr/local/bin/backup.sh"}, "", "/usr/local/bin/backup.sh"},
		{system.Process{UID: 33, Exe: "/usr/bin/dash"}, ReasonWebShell, ""},
		{system.Process{UID: 33, Exe: "/usr/bin/python3.11"}, ReasonWebShell, ""},
		{system.Process{UID: 33, Exe: "/usr/bin/nc.openbsd"}, ReasonWebShell, ""},
		{system.Process{UID: 33, Exe: "/usr/sbin/php-fpm8.2"}, "", ""},
		{system.Process{UID: 1000, Exe: "/usr/bin/bash"}, "", ""},
		{system.Process{UID: 1000, Exe: "/tmp/.x/kworker"}, ReasonUnusualPath, ""},
		{system.Process{UID: 0, Exe: "/dev/shm/a"}, ReasonUnusualPath, ""},
		{system.Process{UID: 0, Exe: "/usr/bin/x", ExeDeleted: true}, ReasonDeleted, ""},
		{system.Process{UID: 0, Exe: "/usr/sbin/cron"}, "", ""},
	} {
		if got, script := classifyExec(c.p, ctx); got != c.want || script != c.script {
			t.Errorf("%+v: %q %q, want %q %q", c.p, got, script, c.want, c.script)
		}
	}
	if !privileged(system.Process{Exe: "/tmp/su"}, 1000, 0) || privileged(system.Process{Exe: "/usr/bin/sudo"}, 1000, 0) || privileged(system.Process{Exe: "/tmp/x"}, 0, 0) {
		t.Error("privileged")
	}
}

func TestWebUsers(t *testing.T) {
	acc := &system.AccountsResult{Accounts: []system.Account{{Name: "www-data", UID: 33}, {Name: "alice", UID: 1000}}}
	procs := &system.ProcessesResult{Processes: []system.Process{{Comm: "php-fpm8.2", UID: 998}, {Comm: "nginx", UID: 0}, {Comm: "nginx", UID: 101}, {Comm: "sshd", UID: 0}}}
	got := WebUsers(acc, procs)
	if len(got) != 3 || got[0] != 33 || got[1] != 101 || got[2] != 998 {
		t.Errorf("web users = %v", got)
	}
}
