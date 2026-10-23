package analyze

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector/system"
)

// tracingPrograms are the eBPF program types that can read or rewrite what the kernel does for
// every process: the ones eBPF rootkits use to hide files, processes and connections.
var tracingPrograms = []string{"kprobe", "tracepoint", "raw_tracepoint", "raw_tracepoint_writable", "tracing", "lsm", "perf_event"}

// taintIntrusive are the taint flags a module loaded by hand leaves: out-of-tree, unsigned,
// forced load or unload.
const taintIntrusive = "OEFR"

func kernelFindings(prev *State, cur State) []Finding {
	k := cur.Kernel
	if k == nil {
		return nil
	}
	var out []Finding
	finding := func(kind, fp, sev, title, detail string, state bool) {
		out = append(out, Finding{Kind: kind, Fingerprint: kind + ":" + fp, Severity: sev, Title: title, Detail: detail, State: state, Owner: "root"})
	}
	var pk *system.KernelResult
	if prev != nil {
		pk = prev.Kernel
	}

	for _, m := range k.Modules {
		switch {
		case m.Hidden == "proc":
			finding("kernel", "hidden-module:"+m.Name, "critical", "Kernel module hidden: "+m.Name,
				fmt.Sprintf("The module %s is loaded (it is in /sys/module) but missing from /proc/modules, so lsmod does not show it: kernel rootkits unlink themselves from that list. Taint %s, %d bytes.", m.Name, orNone(m.Taint), m.Size), true)
		case m.Hidden == "sysfs":
			finding("kernel", "hidden-module:"+m.Name, "critical", "Kernel module hidden: "+m.Name,
				fmt.Sprintf("The module %s is in /proc/modules but missing from /sys/module: something removed its entry to hide it. Taint %s, %d bytes.", m.Name, orNone(m.Taint), m.Size), true)
		case m.Path == "" && k.Release != "":
			finding("kernel", "untracked-module:"+m.Name, "high", "Kernel module from outside the module tree: "+m.Name,
				fmt.Sprintf("The module %s is loaded but the module tree of kernel %s does not list it: it was built and loaded by hand, not installed with the kernel or by DKMS. Taint %s.", m.Name, k.Release, orNone(m.Taint)), true)
		}
	}
	for _, p := range k.HiddenProcesses {
		finding("kernel", "hidden-process:"+p.Exe+":"+p.Comm, "critical", "Process hidden from /proc: "+p.Comm,
			fmt.Sprintf("PID %d (%s, %s, UID %d) exists but /proc does not list it, so ps and top do not show it: something in the kernel filters the listing. Command line: %s", p.PID, p.Comm, orNone(p.Exe), p.UID, orNone(p.Cmdline)), true)
	}
	for _, b := range k.BPFPrograms {
		if slices.Contains(tracingPrograms, b.Type) && (b.Exe == "" || suspiciousPath(b.Exe) || strings.HasSuffix(b.Exe, " (deleted)")) {
			finding("kernel", "bpf-tracing:"+b.Exe+":"+b.Type, "critical", "eBPF tracing program from an unusual program",
				fmt.Sprintf("PID %d (%s, %s) holds an eBPF %s program (id %d, tag %s). Programs of this type see and can alter what the kernel does for every process; this one is not loaded by an installed tool.", b.PID, b.Comm, orNone(b.Exe), b.Type, b.ID, orNone(b.Tag)), true)
		}
	}

	if pk == nil {
		return out
	}
	before := map[string]bool{}
	for _, m := range pk.Modules {
		before[m.Name] = true
	}
	for _, m := range k.Modules {
		if before[m.Name] || m.Hidden != "" {
			continue
		}
		sev := "low"
		if strings.ContainsAny(m.Taint, taintIntrusive) {
			sev = "high"
		}
		finding("kernel-change", "module:"+m.Name, sev, "Kernel module loaded: "+m.Name,
			fmt.Sprintf("Taint %s, %d bytes, %s. Modules load on demand (a new device, a firewall rule); one that is out of tree or unsigned was loaded on purpose.", orNone(m.Taint), m.Size, orNone(m.Path)), false)
	}
	if gained := newFlags(pk.TaintFlags, k.TaintFlags); strings.ContainsAny(gained, taintIntrusive) {
		finding("kernel-change", "taint:"+gained, "high", "Kernel tainted by a module loaded by hand",
			fmt.Sprintf("The kernel gained the taint flags %s (now %s): O is a module from outside the kernel tree, E an unsigned one, F a forced load, R a forced unload. The flag stays until the next boot, even after the module is gone.", gained, k.TaintFlags), false)
	}
	holders := map[string]bool{}
	for _, b := range pk.BPFPrograms {
		holders[b.Exe+"\x00"+b.Type] = true
	}
	for _, b := range k.BPFPrograms {
		if holders[b.Exe+"\x00"+b.Type] {
			continue
		}
		holders[b.Exe+"\x00"+b.Type] = true
		finding("kernel-change", "bpf:"+b.Exe+":"+b.Type, "medium", "New eBPF program: "+b.Type+" from "+b.Comm,
			fmt.Sprintf("PID %d (%s, %s) holds an eBPF %s program (id %d, tag %s) it did not hold before. Monitoring agents, container networking and systemd load programs; check that this one is expected.", b.PID, b.Comm, orNone(b.Exe), b.Type, b.ID, orNone(b.Tag)), false)
	}
	known := setOf(pk.BPFPinned, func(s string) string { return s })
	for _, p := range k.BPFPinned {
		if !known.has(p) {
			finding("kernel-change", "bpf-pin:"+p, "medium", "eBPF object pinned: "+p,
				"A program or map pinned in the BPF filesystem outlives the process that loaded it.", false)
		}
	}
	probes := setOf(pk.KprobeEvents, func(s string) string { return s })
	for _, p := range k.KprobeEvents {
		if !probes.has(p) {
			finding("kernel-change", "kprobe:"+p, "high", "Dynamic kernel probe added",
				"A kprobe was defined through tracefs: "+p+". Debugging tools do this; so does a rootkit hooking a kernel function.", false)
		}
	}
	return out
}

// newFlags returns the letters of cur missing from old.
func newFlags(old, cur string) string {
	var b strings.Builder
	for _, c := range cur {
		if !strings.ContainsRune(old, c) {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
