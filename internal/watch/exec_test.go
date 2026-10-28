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

// apt runs each package's debconf configuration script from /tmp before installing it; only
// that script, run by root through dpkg-preconfigure from a root-owned file, is left out.
func TestPackageScriptsFromTmp(t *testing.T) {
	parents := map[int]system.Process{
		88: {Exe: "/usr/bin/perl", Cmdline: "/usr/bin/perl -w /usr/sbin/dpkg-preconfigure --apt"},
		89: {Exe: "/usr/bin/rpm", Cmdline: "rpm -U /tmp/tripwatch-sensor.rpm"},
	}
	ctx := execContext{
		parent: func(p system.Process) (system.Process, bool) {
			parent, ok := parents[p.PPID]
			return parent, ok
		},
		owner: func(f string) (int, bool) {
			if strings.Contains(f, "user-owned") || strings.HasSuffix(f, ".UsrOwn") {
				return 1000, true
			}
			return 0, true
		},
	}
	const config = "/tmp/nginx-common.config.HSv41h"
	for _, c := range []struct {
		name string
		p    system.Process
		want string
	}{
		{"apt", system.Process{PPID: 88, Exe: "/usr/bin/dash", Cmdline: "/bin/sh " + config + " configure 1.18.0-6ubuntu14.21"}, ""},
		{"var tmp", system.Process{PPID: 88, Exe: "/usr/bin/dash", Cmdline: "/bin/sh /var/tmp/libc6.config.Ab12Cd configure"}, ""},
		{"not from dpkg-preconfigure", system.Process{PPID: 5, Exe: "/usr/bin/dash", Cmdline: "/bin/sh " + config}, ReasonUnusualPath},
		{"not root", system.Process{UID: 1000, EUID: 1000, PPID: 88, Exe: "/usr/bin/dash", Cmdline: "/bin/sh " + config}, ReasonUnusualPath},
		{"file of another user", system.Process{PPID: 88, Exe: "/usr/bin/dash", Cmdline: "/bin/sh /tmp/user-owned.config.HSv41h"}, ReasonUnusualPath},
		{"other name", system.Process{PPID: 88, Exe: "/usr/bin/dash", Cmdline: "/bin/sh /tmp/payload.sh"}, ReasonUnusualPath},
		{"subdirectory", system.Process{PPID: 88, Exe: "/usr/bin/dash", Cmdline: "/bin/sh /tmp/x/nginx-common.config.HSv41h"}, ReasonUnusualPath},
		{"shared memory", system.Process{PPID: 88, Exe: "/usr/bin/dash", Cmdline: "/bin/sh /dev/shm/nginx-common.config.HSv41h"}, ReasonUnusualPath},
		{"program itself in tmp", system.Process{PPID: 88, Exe: config, Cmdline: config + " configure"}, ReasonUnusualPath},
		{"rpm scriptlet", system.Process{PPID: 89, Exe: "/usr/bin/bash", Cmdline: "/bin/sh /var/tmp/rpm-tmp.3udd1L 0"}, ""},
		{"rpm scriptlet from dpkg-preconfigure", system.Process{PPID: 88, Exe: "/usr/bin/bash", Cmdline: "/bin/sh /var/tmp/rpm-tmp.3udd1L 0"}, ReasonUnusualPath},
		{"debconf script from rpm", system.Process{PPID: 89, Exe: "/usr/bin/dash", Cmdline: "/bin/sh " + config}, ReasonUnusualPath},
		{"rpm scriptlet of another user", system.Process{PPID: 89, Exe: "/usr/bin/bash", Cmdline: "/bin/sh /var/tmp/rpm-tmp.UsrOwn 0"}, ReasonUnusualPath},
	} {
		if got, _ := classifyExec(c.p, ctx); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}

	for _, c := range []struct {
		name   string
		parent system.Process
		want   bool
	}{
		{"apt", system.Process{Exe: "/usr/bin/perl", Comm: "dpkg-preconfigu", Cmdline: "/usr/bin/perl -w /usr/sbin/dpkg-preconfigure --apt"}, true},
		{"named like it", system.Process{Exe: "/usr/bin/python3", Comm: "dpkg-preconfigu", Cmdline: "/usr/sbin/dpkg-preconfigure --apt"}, false},
		{"perl elsewhere", system.Process{Exe: "/tmp/perl", Cmdline: "perl -w /usr/sbin/dpkg-preconfigure"}, false},
		{"deleted perl", system.Process{Exe: "/usr/bin/perl", ExeDeleted: true, Cmdline: "perl -w /usr/sbin/dpkg-preconfigure"}, false},
		{"not root", system.Process{UID: 1000, EUID: 1000, Exe: "/usr/bin/perl", Cmdline: "perl -w /usr/sbin/dpkg-preconfigure"}, false},
		{"another script", system.Process{Exe: "/usr/bin/perl", Cmdline: "perl /tmp/x.pl /usr/sbin/dpkg-preconfigure"}, false},
		{"empty", system.Process{Exe: "/usr/bin/perl"}, false},
	} {
		if got := preconfigure(c.parent); got != c.want {
			t.Errorf("parent %s: %v", c.name, got)
		}
	}

	for _, c := range []struct {
		name   string
		parent system.Process
		want   bool
	}{
		{"rpm", system.Process{Exe: "/usr/bin/rpm", Cmdline: "rpm -Uvh x.rpm"}, true},
		{"dnf5", system.Process{Exe: "/usr/bin/dnf5", Cmdline: "dnf upgrade"}, true},
		{"dnf", system.Process{Exe: "/usr/bin/python3.9", Cmdline: "/usr/bin/python3 /usr/bin/dnf -y upgrade"}, true},
		{"yum on RHEL 8", system.Process{Exe: "/usr/libexec/platform-python3.6", Cmdline: "/usr/libexec/platform-python -s /usr/bin/yum update"}, true},
		{"python running another script", system.Process{Exe: "/usr/bin/python3", Cmdline: "python3 /tmp/dnf /usr/bin/dnf"}, false},
		{"python inline", system.Process{Exe: "/usr/bin/python3", Cmdline: "python3 -c /usr/bin/dnf"}, false},
		{"rpm elsewhere", system.Process{Exe: "/tmp/rpm", Cmdline: "rpm -U x.rpm"}, false},
		{"deleted rpm", system.Process{Exe: "/usr/bin/rpm", ExeDeleted: true}, false},
		{"not root", system.Process{UID: 1000, EUID: 1000, Exe: "/usr/bin/rpm"}, false},
	} {
		if got := rpmInstaller(c.parent); got != c.want {
			t.Errorf("rpm parent %s: %v", c.name, got)
		}
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
	// Where the web server's user also runs scheduled jobs, what cron starts is not a webshell's;
	// a framework's command-line entry point run from its application is not unusual.
	shared := ctx
	shared.webUsers = map[int]bool{33: true, 1000: true}
	for _, c := range []struct {
		p    system.Process
		want string
	}{
		{system.Process{UID: 1000, PPID: 77, Exe: "/usr/bin/dash", Cmdline: "/bin/sh -c /home/ubuntu/applications/send_email.sh"}, ""},
		{system.Process{UID: 1000, PPID: 77, Exe: "/usr/bin/curl", Cmdline: "curl -s https://example.com/send"}, ""},
		{system.Process{UID: 1000, PPID: 5, Exe: "/usr/bin/dash", Cmdline: "sh -c id"}, ReasonWebShell},
		{system.Process{UID: 1001, Exe: "/usr/bin/php8.3", Cmdline: "php /var/www/protocol/artisan schedule:run"}, ""},
		{system.Process{UID: 1001, Exe: "/usr/bin/php8.3", Cmdline: "php /var/www/shop/bin/magento cron:run"}, ""},
		{system.Process{UID: 1001, Exe: "/usr/bin/php8.3", Cmdline: "php /var/www/protocol/x.php"}, ReasonUnusualPath},
		{system.Process{UID: 1000, Exe: "/usr/bin/php8.3", Cmdline: "php /home/ubuntu/applications/site/public/uploads/artisan"}, ReasonUnusualPath},
	} {
		if got, _ := classifyExec(c.p, shared); got != c.want {
			t.Errorf("%+v: %q, want %q", c.p, got, c.want)
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
