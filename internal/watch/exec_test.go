package watch

import (
	"strings"
	"testing"

	"github.com/cpibia/tripwatch/internal/collector/system"
)

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
