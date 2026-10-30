package system

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
)

// Module is a loaded kernel module. Path is where modules.dep places it in the running kernel's
// module tree, empty when it is not there: a module loaded from elsewhere was built and loaded by
// hand. Hidden says which of the kernel's two lists of modules leaves it out ("proc" or "sysfs");
// a rootkit unlinks itself from one and often forgets the other.
type Module struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Refs   int    `json:"refs"`
	State  string `json:"state,omitempty"`
	Taint  string `json:"taint,omitempty"`
	Path   string `json:"path,omitempty"`
	Hidden string `json:"hidden,omitempty"`
}

// BPFProgram is an eBPF program a process holds open, as its fdinfo describes it.
type BPFProgram struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm"`
	Exe  string `json:"exe,omitempty"`
	Type string `json:"type"`
	ID   int    `json:"id,omitempty"`
	Tag  string `json:"tag,omitempty"`
}

// PIDScan says how far the search for hidden processes went: from which PID, how many it probed,
// and how many runs the sweep of every PID has taken so far, this one included.
type PIDScan struct {
	Probed    int  `json:"probed"`
	Limit     int  `json:"limit"`
	Truncated bool `json:"truncated,omitempty"`
	From      int  `json:"from,omitempty"`
	SweepRuns int  `json:"sweep_runs,omitempty"`
}

type KernelResult struct {
	Release         string           `json:"release,omitempty"`
	Tainted         int64            `json:"tainted"`
	TaintFlags      string           `json:"taint_flags,omitempty"`
	ModulesDisabled bool             `json:"modules_disabled,omitempty"`
	Lockdown        string           `json:"lockdown,omitempty"`
	Modules         []Module         `json:"modules"`
	HiddenProcesses []Process        `json:"hidden_processes,omitempty"`
	PIDScan         PIDScan          `json:"pid_scan"`
	BPFPrograms     []BPFProgram     `json:"bpf_programs,omitempty"`
	BPFPinned       []string         `json:"bpf_pinned,omitempty"`
	KprobeEvents    []string         `json:"kprobe_events,omitempty"`
	Issues          collector.Issues `json:"issues,omitempty"`
}

// Bounds of the kernel collector: the process table and the descriptors of every process are
// large on a busy server, and the PID search must not turn into minutes of work.
const (
	maxModules       = 2000
	maxPIDProbe      = 1 << 22
	maxSweepRuns     = 3
	maxHidden        = 100
	maxFDsPerProcess = 4096
	maxFDs           = 200_000
	maxBPFPrograms   = 500
	maxPinned        = 500
	maxKprobes       = 200
)

// taintLetters are the flags of /proc/sys/kernel/tainted, bit by bit, as the kernel prints them.
const taintLetters = "PFSRMBUDAWCIOELKXT"

// Kernel collects what a rootkit changes in the running kernel: modules, taint, processes hidden
// from /proc's listing, eBPF programs and dynamic probes.
// pidScanBudget is the time one run gives the search for hidden processes. A var for the tests.
var pidScanBudget = 10 * time.Second

// Kernel keeps where the search for hidden processes stopped: with pid_max in the millions it
// takes more than one run's budget, and the next run goes on from there, so that every PID is
// probed within a few runs instead of the same low half every time.
type Kernel struct {
	mu        sync.Mutex
	next      int
	sweepRuns int
}

func (*Kernel) Name() string { return "kernel" }

func (k *Kernel) Collect(ctx context.Context, src collector.Source) (any, error) {
	res := KernelResult{Modules: []Module{}}
	if b, err := fs.ReadFile(src.FS, "proc/sys/kernel/osrelease"); err == nil {
		res.Release = clipField(strings.TrimSpace(string(b)))
	}
	if b, err := fs.ReadFile(src.FS, "proc/sys/kernel/tainted"); err == nil {
		res.Tainted, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		res.TaintFlags = TaintFlags(res.Tainted)
	}
	if b, err := fs.ReadFile(src.FS, "proc/sys/kernel/modules_disabled"); err == nil {
		res.ModulesDisabled = strings.TrimSpace(string(b)) == "1"
	}
	if b, err := fs.ReadFile(src.FS, "sys/kernel/security/lockdown"); err == nil {
		res.Lockdown = clipField(strings.TrimSpace(string(b)))
	}
	if mods := modules(src.FS, res.Release, &res.Issues); mods != nil {
		res.Modules = mods
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	res.HiddenProcesses, res.PIDScan = k.searchHidden(ctx, src.FS, &res.Issues)
	res.BPFPrograms = bpfPrograms(ctx, src.FS, &res.Issues)
	res.BPFPinned = pinned(src.FS)
	if b, err := fs.ReadFile(src.FS, "sys/kernel/tracing/kprobe_events"); err == nil {
		res.KprobeEvents = lines(b, maxKprobes)
	} else if b, err := fs.ReadFile(src.FS, "sys/kernel/debug/tracing/kprobe_events"); err == nil {
		res.KprobeEvents = lines(b, maxKprobes)
	}
	return res, nil
}

// TaintFlags spells the taint mask the way the kernel does in an oops: one letter per flag set.
func TaintFlags(mask int64) string {
	var b strings.Builder
	for i := range len(taintLetters) {
		if mask&(1<<i) != 0 {
			b.WriteByte(taintLetters[i])
		}
	}
	return b.String()
}

// modules reads /proc/modules and /sys/module and reports each module in either.
func modules(fsys fs.FS, release string, issues *collector.Issues) []Module {
	var out []Module
	listed := map[string]bool{}
	data, err := fs.ReadFile(fsys, "proc/modules")
	issues.Add(err)
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || len(out) == maxModules {
			continue
		}
		m := Module{Name: clipField(f[0])}
		m.Size, _ = strconv.ParseInt(f[1], 10, 64)
		m.Refs, _ = strconv.Atoi(f[2])
		if len(f) >= 5 {
			m.State = clipField(f[4])
		}
		if last := f[len(f)-1]; strings.HasPrefix(last, "(") && strings.HasSuffix(last, ")") {
			m.Taint = clipField(strings.Trim(last, "()"))
		}
		listed[m.Name] = true
		out = append(out, m)
	}
	// /sys/module also lists built-in modules that have parameters: only loadable ones have
	// initstate.
	entries, _ := fs.ReadDir(fsys, "sys/module")
	for _, e := range entries {
		name := e.Name()
		if listed[name] || len(out) == maxModules {
			continue
		}
		if _, err := fs.Stat(fsys, "sys/module/"+name+"/initstate"); err != nil {
			continue
		}
		m := Module{Name: clipField(name), Hidden: "proc"}
		if b, err := fs.ReadFile(fsys, "sys/module/"+name+"/taint"); err == nil {
			m.Taint = clipField(strings.TrimSpace(string(b)))
		}
		if b, err := fs.ReadFile(fsys, "sys/module/"+name+"/coresize"); err == nil {
			m.Size, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		}
		out = append(out, m)
	}
	inSysfs := map[string]bool{}
	for _, e := range entries {
		inSysfs[e.Name()] = true
	}
	tree := moduleTree(fsys, release)
	for i := range out {
		if out[i].Hidden == "" && len(entries) > 0 && !inSysfs[out[i].Name] {
			out[i].Hidden = "sysfs"
		}
		out[i].Path = tree[out[i].Name]
	}
	slices.SortFunc(out, func(a, b Module) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// moduleTree maps module names to their files in the running kernel's modules.dep. Names use
// underscores where file names may use dashes, as the kernel does.
func moduleTree(fsys fs.FS, release string) map[string]string {
	tree := map[string]string{}
	if release == "" || strings.Contains(release, "/") {
		return tree
	}
	for _, base := range []string{"lib/modules/", "usr/lib/modules/"} {
		data, err := fs.ReadFile(fsys, base+release+"/modules.dep")
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for sc.Scan() {
			file, _, ok := strings.Cut(sc.Text(), ":")
			if !ok {
				continue
			}
			name := path.Base(file)
			if i := strings.Index(name, ".ko"); i > 0 {
				name = name[:i]
			}
			tree[strings.ReplaceAll(name, "-", "_")] = "/" + base + release + "/" + file
		}
		break
	}
	return tree
}

// searchHidden runs the search for hidden processes from where the last run stopped. Only a sweep
// that takes more than maxSweepRuns runs is an issue: below that, every PID is still probed every
// few hours.
func (k *Kernel) searchHidden(ctx context.Context, fsys fs.FS, issues *collector.Issues) ([]Process, PIDScan) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out, scan, next := hiddenProcesses(ctx, fsys, k.next, issues)
	k.sweepRuns++
	scan.SweepRuns = k.sweepRuns
	if !scan.Truncated {
		k.next, k.sweepRuns = 0, 0
		return out, scan
	}
	k.next = next
	if k.sweepRuns > maxSweepRuns {
		issues.Add(fmt.Errorf("hidden process search stopped at PID %d of %d: %d runs have not probed every PID", next, scan.Limit, k.sweepRuns))
	}
	return out, scan
}

// hiddenProcesses probes /proc/<pid> for every PID up to the highest one the kernel can have
// handed out, and reports those that exist but are missing from /proc's listing: a rootkit that
// filters getdents hides a process from ps and from the processes collector, not from a direct
// lookup. Threads are reachable the same way without being listed; they are told apart by Tgid.
// The probe starts at from, where an earlier run stopped, and next is where this one stopped.
func hiddenProcesses(ctx context.Context, fsys fs.FS, from int, issues *collector.Issues) (out []Process, scan PIDScan, next int) {
	before := pids(fsys)
	if len(before) == 0 {
		return nil, PIDScan{}, 0
	}
	listed := map[int]bool{}
	for _, p := range before {
		listed[p] = true
	}
	limit := scanLimit(fsys, before)
	if from < 1 || from > limit {
		from = 1
	}
	scan = PIDScan{Limit: limit, From: from}
	var candidates []int
	start := time.Now()
	for pid := from; pid <= limit; pid++ {
		if pid > from && (pid-from)%4096 == 0 && (ctx.Err() != nil || time.Since(start) > pidScanBudget) {
			scan.Truncated, next = true, pid
			break
		}
		scan.Probed++
		if listed[pid] {
			continue
		}
		if _, err := fs.Stat(fsys, "proc/"+strconv.Itoa(pid)); err != nil {
			continue
		}
		candidates = append(candidates, pid)
	}
	if len(candidates) == 0 {
		return nil, scan, next
	}
	// A process born during the search is listed now; one hidden is still not.
	for _, p := range pids(fsys) {
		listed[p] = true
	}
	for _, pid := range candidates {
		if listed[pid] || len(out) == maxHidden {
			continue
		}
		tgid := statusTgid(fsys, pid)
		if tgid != pid && (tgid == 0 || listed[tgid]) {
			continue
		}
		if p, ok := readProcess(fsys, pid, issues); ok && !p.kernel {
			out = append(out, p)
		}
	}
	return out, scan, next
}

// scanLimit is the highest PID worth probing: the last one handed out, unless PIDs have wrapped
// around, which a listed PID above it shows, in which case every PID up to pid_max.
func scanLimit(fsys fs.FS, listed []int) int {
	pidMax := maxPIDProbe
	if b, err := fs.ReadFile(fsys, "proc/sys/kernel/pid_max"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 {
			pidMax = min(n, maxPIDProbe)
		}
	}
	last := 0
	if b, err := fs.ReadFile(fsys, "proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) >= 5 {
			last, _ = strconv.Atoi(f[4])
		}
	}
	highest := listed[len(listed)-1]
	if last <= 0 || highest > last {
		return pidMax
	}
	return min(last, pidMax)
}

func statusTgid(fsys fs.FS, pid int) int {
	status, err := fs.ReadFile(fsys, "proc/"+strconv.Itoa(pid)+"/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "Tgid:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
}

// bpfPrograms lists the eBPF programs held open by processes, found as anon_inode:bpf-prog
// descriptors. A program attached and then closed by its loader is not seen this way; asking
// the kernel for every program would need CAP_SYS_ADMIN, which the sensor does not hold.
func bpfPrograms(ctx context.Context, fsys fs.FS, issues *collector.Issues) []BPFProgram {
	var out []BPFProgram
	seen := 0
	for _, pid := range pids(fsys) {
		if ctx.Err() != nil || seen >= maxFDs || len(out) >= maxBPFPrograms {
			break
		}
		dir := "proc/" + strconv.Itoa(pid)
		fds, err := fs.ReadDir(fsys, dir+"/fd")
		if err != nil {
			continue
		}
		var comm, exe string
		for i, fd := range fds {
			if i == maxFDsPerProcess || seen >= maxFDs || len(out) >= maxBPFPrograms {
				break
			}
			seen++
			target, err := fs.ReadLink(fsys, dir+"/fd/"+fd.Name())
			if err != nil || target != "anon_inode:bpf-prog" {
				continue
			}
			info, err := fs.ReadFile(fsys, dir+"/fdinfo/"+fd.Name())
			if err != nil {
				continue
			}
			if comm == "" {
				c, _ := fs.ReadFile(fsys, dir+"/comm")
				comm = clipField(strings.TrimSpace(string(c)))
				exe, _ = fs.ReadLink(fsys, dir+"/exe")
				exe = clipField(exe)
			}
			p := BPFProgram{PID: pid, Comm: comm, Exe: exe}
			for _, line := range strings.Split(string(info), "\n") {
				key, value, _ := strings.Cut(line, ":")
				value = strings.TrimSpace(value)
				switch key {
				case "prog_type":
					p.Type = bpfProgType(value)
				case "prog_id":
					p.ID, _ = strconv.Atoi(value)
				case "prog_tag":
					p.Tag = clipField(value)
				}
			}
			out = append(out, p)
		}
	}
	if seen >= maxFDs {
		issues.Add(fmt.Errorf("eBPF search stopped after %d descriptors", maxFDs))
	}
	return out
}

// bpfProgTypes names enum bpf_prog_type from include/uapi/linux/bpf.h.
var bpfProgTypes = []string{
	"unspec", "socket_filter", "kprobe", "sched_cls", "sched_act", "tracepoint", "xdp", "perf_event",
	"cgroup_skb", "cgroup_sock", "lwt_in", "lwt_out", "lwt_xmit", "sock_ops", "sk_skb", "cgroup_device",
	"sk_msg", "raw_tracepoint", "cgroup_sock_addr", "lwt_seg6local", "lirc_mode2", "sk_reuseport",
	"flow_dissector", "cgroup_sysctl", "raw_tracepoint_writable", "cgroup_sockopt", "tracing",
	"struct_ops", "ext", "lsm", "sk_lookup", "syscall", "netfilter",
}

func bpfProgType(v string) string {
	if n, err := strconv.Atoi(v); err == nil && n >= 0 && n < len(bpfProgTypes) {
		return bpfProgTypes[n]
	}
	return clipField(v)
}

// pinned lists what is pinned in the BPF filesystem: programs and maps that outlive the process
// that loaded them.
func pinned(fsys fs.FS) []string {
	var out []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		entries, err := fs.ReadDir(fsys, dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if len(out) == maxPinned {
				return
			}
			p := dir + "/" + e.Name()
			if e.IsDir() && depth < 4 {
				walk(p, depth+1)
				continue
			}
			out = append(out, clipField("/"+p))
		}
	}
	walk("sys/fs/bpf", 0)
	return out
}

func lines(b []byte, limit int) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && len(out) < limit {
			out = append(out, clipField(l))
		}
	}
	return out
}

// clipField bounds a value read from the kernel or a process: it ends up in alerts and pages.
func clipField(s string) string {
	if len(s) > 512 {
		s = s[:512]
	}
	return strings.ToValidUTF8(s, "")
}
