package watch

import (
	"testing"

	"github.com/cpibia/tripwatch/internal/collector/system"
)

func TestClassifyExec(t *testing.T) {
	web := map[int]bool{33: true}
	for _, c := range []struct {
		p    system.Process
		want string
	}{
		{system.Process{UID: 33, Exe: "/usr/bin/dash"}, ReasonWebShell},
		{system.Process{UID: 33, Exe: "/usr/bin/python3.11"}, ReasonWebShell},
		{system.Process{UID: 33, Exe: "/usr/bin/nc.openbsd"}, ReasonWebShell},
		{system.Process{UID: 33, Exe: "/usr/sbin/php-fpm8.2"}, ""},
		{system.Process{UID: 1000, Exe: "/usr/bin/bash"}, ""},
		{system.Process{UID: 1000, Exe: "/tmp/.x/kworker"}, ReasonUnusualPath},
		{system.Process{UID: 0, Exe: "/dev/shm/a"}, ReasonUnusualPath},
		{system.Process{UID: 0, Exe: "/usr/bin/x", ExeDeleted: true}, ReasonDeleted},
		{system.Process{UID: 0, Exe: "/usr/sbin/cron"}, ""},
	} {
		if got := classifyExec(c.p, web); got != c.want {
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
