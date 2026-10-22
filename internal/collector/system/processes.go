package system

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

const deletedSuffix = " (deleted)"

// Process is a running process as seen in /proc. Exe is where the binary was loaded from;
// ExeDeleted means it was removed from disk after starting, a common way to leave no file
// behind. ExeSHA256 is computed through /proc, so it is available even then.
type Process struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	UID        int    `json:"uid"`
	EUID       int    `json:"euid"`
	Comm       string `json:"comm"`
	Cmdline    string `json:"cmdline"`
	Exe        string `json:"exe,omitempty"`
	ExeDeleted bool   `json:"exe_deleted,omitempty"`
	ExeSHA256  string `json:"exe_sha256,omitempty"`
	Cwd        string `json:"cwd,omitempty"`
	Preload    string `json:"ld_preload,omitempty"`
	NetNS      string `json:"netns,omitempty"`
	MntNS      string `json:"mntns,omitempty"`

	kernel bool
}

// PF_KTHREAD from include/linux/sched.h: set only on kernel threads.
const pfKthread = 0x00200000

type ProcessesResult struct {
	Processes     []Process        `json:"processes"`
	KernelThreads int              `json:"kernel_threads"`
	Issues        collector.Issues `json:"issues,omitempty"`
}

// Processes collects every user-space process from /proc. Kernel threads, recognised by the
// PF_KTHREAD flag the kernel sets on them, are only counted; a process that names itself like
// one ([kworker/0:1]) or hides its command line is still listed.
type Processes struct{}

func (Processes) Name() string { return "processes" }

func (Processes) Collect(ctx context.Context, src collector.Source) (any, error) {
	var res ProcessesResult
	hashes := map[string]string{}

	for _, pid := range pids(src.FS) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p, ok := readProcess(src.FS, pid, &res.Issues)
		if !ok {
			continue
		}
		if p.kernel {
			res.KernelThreads++
			continue
		}
		if p.Exe != "" {
			p.ExeSHA256 = exeHash(src, pid, hashes, &res.Issues)
		}
		res.Processes = append(res.Processes, p)
	}
	return res, nil
}

// exeHash hashes the binary a process runs, through /proc/<pid>/exe so that a deleted or
// replaced file is still the one loaded. The cache is keyed by device and inode of that
// binary, never by its path: a process in another mount namespace can show the same path as
// a legitimate binary and must not inherit its hash.
func exeHash(src collector.Source, pid int, cache map[string]string, issues *collector.Issues) string {
	name := fmt.Sprintf("proc/%d/exe", pid)
	info, err := fs.Stat(src.FS, name)
	if err != nil {
		issues.Add(err)
		return ""
	}
	id, cacheable := collector.FileID(info)
	if cacheable {
		if sum, ok := cache[id]; ok {
			return sum
		}
	}
	f, err := collector.Describe(src, name)
	issues.Add(err)
	if cacheable {
		cache[id] = f.SHA256
	}
	return f.SHA256
}

// pids lists the numeric entries of /proc, in ascending order.
func pids(fsys fs.FS) []int {
	entries, err := fs.ReadDir(fsys, "proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && e.IsDir() {
			out = append(out, pid)
		}
	}
	slices.Sort(out)
	return out
}

// readProcess returns false when the process exited while being read.
func readProcess(fsys fs.FS, pid int, issues *collector.Issues) (Process, bool) {
	dir := fmt.Sprintf("proc/%d/", pid)
	status, err := fs.ReadFile(fsys, dir+"status")
	if err != nil {
		return Process{}, false
	}

	p := Process{PID: pid}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, _ := strings.Cut(line, ":")
		fields := strings.Fields(value)
		switch {
		case key == "PPid" && len(fields) > 0:
			p.PPID, _ = strconv.Atoi(fields[0])
		case key == "Uid" && len(fields) > 1:
			p.UID, _ = strconv.Atoi(fields[0])
			p.EUID, _ = strconv.Atoi(fields[1])
		}
	}

	comm, _ := fs.ReadFile(fsys, dir+"comm")
	p.Comm = strings.TrimSpace(string(comm))

	cmdline, _ := fs.ReadFile(fsys, dir+"cmdline")
	p.Cmdline = redactCmdline(strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00"))

	p.kernel = isKernelThread(fsys, dir, p.PPID, pid)
	if exe, err := fs.ReadLink(fsys, dir+"exe"); err == nil {
		p.Exe, p.ExeDeleted = strings.CutSuffix(exe, deletedSuffix)
	} else if !p.kernel {
		// Without CAP_SYS_PTRACE, or with hidepid, this fails: the process is still listed.
		*issues = append(*issues, fmt.Sprintf("pid %d: executable unreadable: %v", pid, err))
	}
	p.MntNS, _ = fs.ReadLink(fsys, dir+"ns/mnt")
	p.Cwd, _ = fs.ReadLink(fsys, dir+"cwd")
	p.NetNS, _ = fs.ReadLink(fsys, dir+"ns/net")

	if environ, err := fs.ReadFile(fsys, dir+"environ"); err == nil {
		for _, kv := range bytes.Split(environ, []byte{0}) {
			if v, ok := bytes.CutPrefix(kv, []byte("LD_PRELOAD=")); ok {
				p.Preload = string(v)
			}
		}
	}
	return p, true
}

var (
	secretOption = regexp.MustCompile(`(?i)^(--?[a-z0-9_-]*(password|passwd|passphrase|token|secret|apikey|api-key|api_key|credential|private-key)[a-z0-9_-]*)(=(.*))?$`)
	secretEnv    = regexp.MustCompile(`(?i)^([a-z0-9_]*(password|passwd|token|secret|api_?key|auth|credential)[a-z0-9_]*)=.+`)
	urlUserinfo  = regexp.MustCompile(`(://[^:/@\s]+):[^@/\s]+@`)
)

// redactCmdline joins the arguments of a process after removing the secrets commonly passed
// on the command line: values of password and token options (--password=x or --password x),
// NAME=value pairs with sensitive names, passwords in URLs, and the -p<password> form of the
// MySQL and MariaDB clients.
func redactCmdline(args []string) string {
	mysql := len(args) > 0 && strings.Contains(path.Base(args[0]), "mysql") || len(args) > 0 && strings.Contains(path.Base(args[0]), "mariadb")
	out := make([]string, 0, len(args))
	hideNext := false
	for _, a := range args {
		switch {
		case hideNext:
			out = append(out, "[redacted]")
			hideNext = false
			continue
		case mysql && strings.HasPrefix(a, "-p") && len(a) > 2:
			a = "-p[redacted]"
		case secretOption.MatchString(a):
			m := secretOption.FindStringSubmatch(a)
			if m[3] == "" {
				hideNext = true
			} else {
				a = m[1] + "=[redacted]"
			}
		case secretEnv.MatchString(a):
			a = secretEnv.FindStringSubmatch(a)[1] + "=[redacted]"
		}
		out = append(out, urlUserinfo.ReplaceAllString(a, "$1:[redacted]@"))
	}
	return strings.TrimSpace(strings.Join(out, " "))
}

// isKernelThread reads the flags field of /proc/<pid>/stat. The command name in that line is
// in parentheses and may itself contain spaces or parentheses, so fields are counted after
// the last ')'. Without a readable stat, kthreadd (pid 2) and its children are kernel threads.
func isKernelThread(fsys fs.FS, dir string, ppid, pid int) bool {
	stat, err := fs.ReadFile(fsys, dir+"stat")
	if err == nil {
		if i := bytes.LastIndexByte(stat, ')'); i >= 0 {
			fields := strings.Fields(string(stat[i+1:]))
			if len(fields) > 6 {
				if flags, err := strconv.ParseUint(fields[6], 10, 64); err == nil {
					return flags&pfKthread != 0
				}
			}
		}
	}
	return pid == 2 || ppid == 2
}
