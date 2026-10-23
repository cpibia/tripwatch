package analyze

import (
	"testing"

	"github.com/cpibia/tripwatch/internal/collector/system"
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
	cur := State{Processes: &system.ProcessesResult{Processes: []system.Process{
		{PID: 10, Comm: "sshd", Exe: "/usr/sbin/sshd", Tracer: 66},
		{PID: 11, Comm: "app", Exe: "/usr/bin/app", Tracer: 67},
		{PID: 12, Comm: "node", Exe: "/usr/bin/node", Mapped: []string{"/var/www/app/node_modules/x/build/x.node", "/dev/shm/.l.so", "/memfd:s (deleted)"}},
		{PID: 13, Comm: "x", Exe: "/memfd:x", ExeDeleted: true},
		{PID: 14, Comm: "agetty", Exe: "/usr/sbin/agetty", ExeDeleted: true, ExeReplaced: true},
		{PID: 15, Comm: "agetty", Exe: "/usr/sbin/gone", ExeDeleted: true},
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
		"processes:restart-pending:/usr/sbin/agetty":                     "low",
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
