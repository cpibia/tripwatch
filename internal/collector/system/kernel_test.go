package system

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/cpibia/tripwatch/internal/collector"
)

func proc(pid, tgid, comm string) fstest.MapFS {
	return fstest.MapFS{
		"proc/" + pid + "/status":  text("Name:\t" + comm + "\nTgid:\t" + tgid + "\nPPid:\t1\nUid:\t0\t0\t0\t0\n"),
		"proc/" + pid + "/comm":    text(comm + "\n"),
		"proc/" + pid + "/cmdline": text(comm + "\x00"),
		"proc/" + pid + "/stat":    text(pid + " (" + comm + ") S 1 0 0 0 -1 4194560 0 0 0 0"),
		"proc/" + pid + "/exe":     &fstest.MapFile{Data: []byte("/usr/bin/" + comm), Mode: fs.ModeSymlink},
	}
}

// listed hides some entries of /proc from ReadDir, as a rootkit filtering getdents does, while
// they stay reachable by name.
type listed struct {
	fstest.MapFS
	hide map[string]bool
}

func (l listed) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := l.MapFS.ReadDir(name)
	var out []fs.DirEntry
	for _, e := range entries {
		if name != "proc" || !l.hide[e.Name()] {
			out = append(out, e)
		}
	}
	return out, err
}

func TestKernel(t *testing.T) {
	fsys := fstest.MapFS{
		"proc/sys/kernel/osrelease": text("6.1.0-26-amd64\n"),
		"proc/sys/kernel/tainted":   text("12288\n"),
		"proc/sys/kernel/pid_max":   text("4194304\n"),
		"proc/loadavg":              text("0.00 0.01 0.05 1/120 300\n"),
		"proc/modules": text("ext4 1003520 2 - Live 0x0000000000000000\n" +
			"diamorphine 16384 0 - Live 0x0000000000000000 (OE)\n"),
		"sys/module/ext4/initstate":              text("live\n"),
		"sys/module/diamorphine/initstate":       text("live\n"),
		"sys/module/reptile/initstate":           text("live\n"),
		"sys/module/reptile/taint":               text("OE\n"),
		"sys/module/printk/parameters/time":      text("Y\n"),
		"lib/modules/6.1.0-26-amd64/modules.dep": text("kernel/fs/ext4/ext4.ko.xz: kernel/fs/jbd2/jbd2.ko.xz\n"),
		"sys/kernel/security/lockdown":           text("[none] integrity confidentiality\n"),
		"sys/kernel/tracing/kprobe_events":       text("p:kprobes/hide_getdents __x64_sys_getdents64\n"),
		"sys/fs/bpf/tc/globals/hidden_map":       text(""),
		"proc/1/fd/7":                            &fstest.MapFile{Data: []byte("anon_inode:bpf-prog"), Mode: fs.ModeSymlink},
		"proc/1/fd/8":                            &fstest.MapFile{Data: []byte("/dev/null"), Mode: fs.ModeSymlink},
		"proc/1/fdinfo/7":                        text("pos:\t0\nprog_type:\t2\nprog_jited:\t1\nprog_tag:\t3b185187f1855c4c\nprog_id:\t41\n"),
	}
	for _, p := range []fstest.MapFS{proc("1", "1", "systemd"), proc("250", "250", "sshd"), proc("251", "250", "sshd"), proc("290", "290", "kworker_x")} {
		for k, v := range p {
			fsys[k] = v
		}
	}
	src := collector.Source{FS: listed{MapFS: fsys, hide: map[string]bool{"290": true}}}
	r, err := Kernel{}.Collect(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	res := r.(KernelResult)
	if res.Release != "6.1.0-26-amd64" || res.TaintFlags != "OE" || res.Lockdown == "" || len(res.KprobeEvents) != 1 {
		t.Errorf("kernel = %+v", res)
	}
	mods := map[string]Module{}
	for _, m := range res.Modules {
		mods[m.Name] = m
	}
	if len(mods) != 3 || mods["ext4"].Path != "/lib/modules/6.1.0-26-amd64/kernel/fs/ext4/ext4.ko.xz" || mods["ext4"].Hidden != "" {
		t.Errorf("ext4 = %+v", mods["ext4"])
	}
	if m := mods["diamorphine"]; m.Path != "" || m.Taint != "OE" || m.Hidden != "" {
		t.Errorf("diamorphine = %+v", m)
	}
	if m := mods["reptile"]; m.Hidden != "proc" || m.Taint != "OE" {
		t.Errorf("reptile = %+v", m)
	}
	// 251 is a thread of a listed process, reachable but not listed: not hidden.
	if len(res.HiddenProcesses) != 1 || res.HiddenProcesses[0].PID != 290 || res.PIDScan.Limit != 300 || res.PIDScan.Probed != 300 {
		t.Errorf("hidden = %+v, scan %+v", res.HiddenProcesses, res.PIDScan)
	}
	if len(res.BPFPrograms) != 1 || res.BPFPrograms[0].Type != "kprobe" || res.BPFPrograms[0].ID != 41 || res.BPFPrograms[0].Comm != "systemd" {
		t.Errorf("bpf = %+v", res.BPFPrograms)
	}
	if len(res.BPFPinned) != 1 || res.BPFPinned[0] != "/sys/fs/bpf/tc/globals/hidden_map" {
		t.Errorf("pinned = %v", res.BPFPinned)
	}
}

func TestTaintFlags(t *testing.T) {
	if got := TaintFlags(1 | 1<<12 | 1<<13); got != "POE" {
		t.Errorf("TaintFlags = %q", got)
	}
}

// A status file past collector.MaxReadSize is streamed, not dropped.
func TestDpkgStatesLargeStatus(t *testing.T) {
	big := strings.Repeat("\n", 17<<20) + "Package: bash\nStatus: install ok installed\nVersion: 5.2-1\nArchitecture: amd64\n"
	fsys := fstest.MapFS{"var/lib/dpkg/status": &fstest.MapFile{Data: []byte(big)}}
	var issues collector.Issues
	st := dpkgStates(fsys, &issues)
	if st["bash"].Version != "5.2-1" || len(issues) != 0 {
		t.Fatalf("states %v, issues %v", st, issues)
	}
}
