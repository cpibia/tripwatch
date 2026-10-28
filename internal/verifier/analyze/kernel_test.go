package analyze

import (
	"testing"

	"github.com/cpibia/tripwatch/internal/collector/system"
	"github.com/cpibia/tripwatch/internal/watch"
)

func TestKernelFindings(t *testing.T) {
	prev := State{Kernel: &system.KernelResult{Release: "6.1.0", TaintFlags: "",
		Modules:     []system.Module{{Name: "ext4", Path: "/lib/modules/6.1.0/kernel/fs/ext4/ext4.ko"}},
		BPFPrograms: []system.BPFProgram{{PID: 1, Comm: "systemd", Exe: "/usr/lib/systemd/systemd", Type: "cgroup_device"}},
	}}
	cur := State{Kernel: &system.KernelResult{Release: "6.1.0", TaintFlags: "OE",
		Modules: []system.Module{
			{Name: "ext4", Path: "/lib/modules/6.1.0/kernel/fs/ext4/ext4.ko"},
			{Name: "nf_tables", Path: "/lib/modules/6.1.0/kernel/net/netfilter/nf_tables.ko"},
			{Name: "diamorphine", Taint: "OE"},
			{Name: "reptile", Hidden: "proc", Taint: "OE"},
		},
		HiddenProcesses: []system.Process{{PID: 4242, Comm: "kworker_x", Exe: "/tmp/.x"}},
		BPFPrograms: []system.BPFProgram{
			{PID: 1, Comm: "systemd", Exe: "/usr/lib/systemd/systemd", Type: "cgroup_device"},
			{PID: 900, Comm: "agent", Exe: "/opt/agent/bin/agent", Type: "kprobe"},
			{PID: 901, Comm: "x", Exe: "/dev/shm/x", Type: "tracepoint"},
		},
		KprobeEvents: []string{"p:kprobes/h __x64_sys_getdents64"},
	}}
	got := map[string]string{}
	for _, f := range Evaluate(&prev, cur) {
		got[f.Fingerprint] = f.Severity
	}
	want := map[string]string{
		"kernel:hidden-module:reptile":                          "critical",
		"kernel:untracked-module:diamorphine":                   "high",
		"kernel:hidden-process:/tmp/.x:kworker_x":               "critical",
		"kernel:bpf-tracing:/dev/shm/x:tracepoint":              "critical",
		"kernel-change:module:nf_tables":                        "low",
		"kernel-change:module:diamorphine":                      "high",
		"kernel-change:taint:OE":                                "high",
		"kernel-change:bpf:/opt/agent/bin/agent:kprobe":         "medium",
		"kernel-change:bpf:/dev/shm/x:tracepoint":               "medium",
		"kernel-change:kprobe:p:kprobes/h __x64_sys_getdents64": "high",
	}
	for fp, sev := range want {
		if got[fp] != sev {
			t.Errorf("%s: %q, want %q", fp, got[fp], sev)
		}
	}
	for fp := range got {
		if _, ok := want[fp]; !ok {
			t.Errorf("unexpected %s", fp)
		}
	}
}

func TestRawSocketFindings(t *testing.T) {
	for _, tc := range []struct {
		so   system.Socket
		want string
	}{
		{system.Socket{Proto: "packet", PID: 700, Process: "dhclient", Exe: "/usr/sbin/dhclient"}, ""},
		{system.Socket{Proto: "packet", PID: 701, Process: "dhclient", Exe: "/var/tmp/.d/dhclient"}, "critical"},
		{system.Socket{Proto: "raw", PID: 702, Process: "droplet-agent", Exe: "/opt/digitalocean/bin/droplet-agent"}, ""},
		{system.Socket{Proto: "packet", PID: 702, Process: "udevd", Exe: "/usr/sbin/udevd (deleted)"}, "critical"},
		{system.Socket{Proto: "raw", PID: 703, Process: "agent", Exe: "/opt/agent/agent"}, "high"},
		{system.Socket{Proto: "raw6"}, "medium"},
		{system.Socket{Proto: "tcp", PID: 704, Exe: "/tmp/x"}, ""},
	} {
		f, ok := rawSocketFinding(tc.so)
		if got := map[bool]string{true: f.Severity}[ok]; got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.so, got, tc.want)
		}
	}
}

func TestProcessMemoryFindings(t *testing.T) {
	cur := State{Packages: &system.PackagesResult{Manager: "dpkg", Unowned: []string{"/usr/bin/planted"}}, Processes: &system.ProcessesResult{Processes: []system.Process{
		{PID: 10, Comm: "sshd", Exe: "/usr/sbin/sshd", Tracer: 66},
		{PID: 11, Comm: "app", Exe: "/usr/bin/app", Tracer: 67},
		{PID: 12, Comm: "node", Exe: "/usr/bin/node", Mapped: []string{"/var/www/app/node_modules/x/build/x.node", "/dev/shm/.l.so", "/memfd:s (deleted)"}},
		{PID: 13, Comm: "x", Exe: "/memfd:x", ExeDeleted: true},
		{PID: 14, Comm: "agetty", Exe: "/usr/sbin/agetty", ExeDeleted: true, ExeReplaced: true, ExePackaged: true},
		{PID: 19, Comm: "impl", Exe: "/usr/lib/x/impl", ExeDeleted: true, ExeReplaced: true},
		{PID: 15, Comm: "agetty", Exe: "/usr/sbin/gone", ExeDeleted: true},
		{PID: 17, Comm: "tool", Exe: "/usr/local/bin/tool", ExeDeleted: true, ExeReplaced: true},
		{PID: 18, Comm: "planted", Exe: "/usr/bin/planted", ExeDeleted: true, ExeReplaced: true},
		{PID: 16, Comm: "php-fpm8.4", Exe: "/usr/sbin/php-fpm8.4", Mapped: []string{"/dev/zero (deleted)"}},
		{PID: 66, Comm: "gdb", Exe: "/usr/bin/gdb"},
		{PID: 67, Comm: "gdb", Exe: "/usr/bin/gdb"},
	}}}
	got := map[string]string{}
	for _, f := range Evaluate(nil, cur) {
		got[f.Fingerprint] = f.Severity
	}
	for fp, sev := range map[string]string{
		"processes:traced:sshd:/usr/bin/gdb":                             "critical",
		"processes:mapped:node:/var/www/app/node_modules/x/build/x.node": "high",
		"processes:mapped:node:/dev/shm/.l.so":                           "critical",
		"processes:mapped:node:/memfd:s (deleted)":                       "critical",
		"processes:memfd:x:":                                             "critical",
		"processes:restart-pending:/usr/sbin/agetty:":                    "low",
		"processes:deleted:/usr/local/bin/tool:":                         "high",
		"processes:deleted:/usr/bin/planted:":                            "high",
		"processes:deleted:/usr/lib/x/impl:":                             "high",
		"processes:deleted:/usr/sbin/gone:":                              "high",
	} {
		if got[fp] != sev {
			t.Errorf("%s: %q, want %q", fp, got[fp], sev)
		}
	}
	if _, ok := got["processes:mapped:php-fpm8.4:/dev/zero (deleted)"]; ok {
		t.Error("a shared anonymous region reported by an older sensor raised an alert")
	}
	if _, ok := got["processes:traced:app:/usr/bin/gdb"]; ok {
		t.Error("a debugger on an ordinary process raised an alert")
	}
}

// An upgrade changes the list of installed versions; checksums rewritten by hand do not.
func TestPackageDatabaseChanges(t *testing.T) {
	pkgs := func(db, status string) State {
		return State{Packages: &system.PackagesResult{Manager: "dpkg", Packages: 500, DatabaseSHA256: db, StatusSHA256: status}}
	}
	states := func(db, status, v1, c1, v2, c2 string) State {
		st := pkgs(db, status)
		st.Packages.States = map[string]system.PackageState{"openssh-server": {Version: v1, Checksums: c1}, "libc6:amd64": {Version: v2, Checksums: c2}}
		return st
	}
	for _, tc := range []struct {
		name      string
		prev, cur State
		want      string
	}{
		{"upgrade", pkgs("d1", "s1"), pkgs("d2", "s2"), ""},
		{"checksums rewritten", pkgs("d1", "s1"), pkgs("d2", "s1"), "high"},
		{"unchanged", pkgs("d1", "s1"), pkgs("d1", "s1"), ""},
		{"older sensor", pkgs("d1", ""), pkgs("d2", ""), "medium"},
		{"one package rewritten while another upgrades", states("d1", "s1", "1.0", "aaaa", "2.0", "bbbb"), states("d2", "s2", "1.0", "cccc", "2.1", "dddd"), "high"},
		{"upgrade with states", states("d1", "s1", "1.0", "aaaa", "2.0", "bbbb"), states("d2", "s2", "1.1", "cccc", "2.0", "bbbb"), ""},
	} {
		got := ""
		for _, f := range Evaluate(&tc.prev, tc.cur) {
			if f.Kind == "packages-change" {
				got = f.Severity
			}
		}
		if got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestUnwatchedPlacesRaiseAlert(t *testing.T) {
	cur := State{Realtime: &watch.Status{Files: true, Unwatched: []string{
		"upload: watch: more than 6144 directories of class upload: /srv/app/uploads/x and others are not watched",
		"scratch: watch: /tmp/a/b has directories deeper than 2 levels below /tmp, not watched",
	}}}
	got := map[string]string{}
	for _, f := range Evaluate(nil, cur) {
		got[f.Fingerprint] = f.Severity
	}
	if got["sensor:unwatched:upload"] != "high" || got["sensor:unwatched:scratch"] != "medium" {
		t.Fatalf("unwatched alerts %v", got)
	}
}

// A program named like a kernel thread hides in ps; real kernel threads and programs whose titles
// merely use brackets or share a word with one are not reported.
func TestKernelThreadDisguise(t *testing.T) {
	for _, c := range []struct {
		pr   system.Process
		want bool
	}{
		{system.Process{PID: 900, PPID: 1, Comm: "raid5wq", Cmdline: "[raid5wq]", Exe: "/usr/lib/systemd/sd-helper"}, true},
		{system.Process{PID: 901, PPID: 1, Comm: "kswapd0", Cmdline: "", Exe: "/var/tmp/.x"}, true},
		{system.Process{PID: 902, PPID: 1, Comm: "kworker/0:2", Cmdline: "kworker/0:2", Exe: "/usr/bin/kw"}, true},
		{system.Process{PID: 903, PPID: 811, Comm: "[kthreadd]", Exe: "/opt/a/b"}, true},
		{system.Process{PID: 2, PPID: 0, Comm: "kthreadd"}, false},
		{system.Process{PID: 40, PPID: 2, Comm: "kworker/0:1H", Cmdline: ""}, false},
		{system.Process{PID: 700, PPID: 1, Comm: "watchdog", Cmdline: "/usr/sbin/watchdog", Exe: "/usr/sbin/watchdog"}, false},
		{system.Process{PID: 701, PPID: 1, Comm: "celery", Cmdline: "[celeryd: celery@web-01:MainProcess] -active- (worker)", Exe: "/usr/bin/python3.11"}, false},
		{system.Process{PID: 702, PPID: 1, Comm: "celery", Cmdline: "[celeryd: celery@web-01:ForkPoolWorker-1]", Exe: "/usr/bin/python3.11"}, false},
		{system.Process{PID: 703, PPID: 1, Comm: "gunicorn", Cmdline: "gunicorn: master [shop]", Exe: "/usr/bin/python3.11"}, false},
		{system.Process{PID: 704, PPID: 1, Comm: "mdadm", Cmdline: "/sbin/mdadm --monitor --scan", Exe: "/usr/sbin/mdadm"}, false},
	} {
		if got := kernelThreadDisguise(c.pr, nil); got != c.want {
			t.Errorf("%+v: %v, want %v", c.pr, got, c.want)
		}
	}

	// Names off the list are known from the kernel threads of the host itself.
	host := []string{"kthreadd", "kworker", "kauditd", "ksmd", "rcu_sched", "xfsaild", "scsi_eh_", "watchdog", "kswapd"}
	for _, c := range []struct {
		pr   system.Process
		want bool
	}{
		{system.Process{PID: 910, PPID: 1, Comm: "kauditd", Cmdline: "", Exe: "/usr/sbin/kauditd"}, true},
		{system.Process{PID: 911, PPID: 1, Comm: "perl", Cmdline: "[ksmd]", Exe: "/usr/bin/perl"}, true},
		{system.Process{PID: 912, PPID: 1, Comm: "xfsaild/sda1", Cmdline: "xfsaild/sda1", Exe: "/usr/local/bin/x"}, true},
		{system.Process{PID: 913, PPID: 1, Comm: "scsi_eh_7", Exe: "/usr/bin/svc"}, true},
		{system.Process{PID: 914, PPID: 1, Comm: "rcu_sched", Exe: "/usr/bin/svc"}, true},
		{system.Process{PID: 920, PPID: 1, Comm: "watchdog", Cmdline: "/usr/sbin/watchdog", Exe: "/usr/sbin/watchdog"}, false},
		{system.Process{PID: 921, PPID: 1, Comm: "auditd", Cmdline: "/sbin/auditd", Exe: "/usr/sbin/auditd"}, false},
		{system.Process{PID: 922, PPID: 1, Comm: "python3", Cmdline: "[ksmd worker]", Exe: "/usr/bin/python3"}, false},
		{system.Process{PID: 923, PPID: 2, Comm: "kauditd", Cmdline: "", Exe: "/usr/sbin/modprobe"}, false},
		{system.Process{PID: 924, PPID: 1, Comm: "nginx", Cmdline: "nginx: worker process", Exe: "/usr/sbin/nginx"}, false},
	} {
		if got := kernelThreadDisguise(c.pr, host); got != c.want {
			t.Errorf("host threads, %+v: %v, want %v", c.pr, got, c.want)
		}
	}
	cur := State{Processes: &system.ProcessesResult{Processes: []system.Process{{PID: 900, PPID: 1, Comm: "raid5wq", Cmdline: "[raid5wq]", Exe: "/usr/lib/systemd/sd-helper", ExeSHA256: "ab"}}}}
	for _, f := range Evaluate(nil, cur) {
		if f.Fingerprint == "processes:kthread-name:/usr/lib/systemd/sd-helper:ab" && f.Severity == "critical" {
			return
		}
	}
	t.Error("no critical finding for a process disguised as a kernel thread")
}
