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
	// ExeReplaced means a file exists again where a deleted executable was: a package upgrade
	// that the process has not been restarted for, not a binary that removed itself.
	ExeReplaced bool `json:"exe_replaced,omitempty"`
	// ExePackaged means dpkg's file lists name the executable's path: what replaced it was most
	// likely the package's own upgrade.
	ExePackaged bool   `json:"exe_packaged,omitempty"`
	ExeSHA256   string `json:"exe_sha256,omitempty"`
	Cwd         string `json:"cwd,omitempty"`
	Preload     string `json:"ld_preload,omitempty"`
	NetNS       string `json:"netns,omitempty"`
	MntNS       string `json:"mntns,omitempty"`
	// Tracer is the PID attached to this process with ptrace, what debuggers do and what
	// injectors and credential stealers do to a running sshd or su.
	Tracer int `json:"tracer,omitempty"`
	// Mapped lists the executable mappings of files a process should not run code from: memfd
	// files, files under the unusual directories, files deleted outside the system's library
	// directories (a library deleted there is only an upgrade the process was not restarted for).
	Mapped []string `json:"mapped,omitempty"`

	kernel bool
}

// PF_KTHREAD from include/linux/sched.h: set only on kernel threads.
const pfKthread = 0x00200000

type ProcessesResult struct {
	Processes     []Process `json:"processes"`
	KernelThreads int       `json:"kernel_threads"`
	// KernelThreadNames are the names of this host's kernel threads, as KernelThreadFamily
	// reduces them: a program that takes one is hiding among them in ps.
	KernelThreadNames []string         `json:"kernel_thread_names,omitempty"`
	Issues            collector.Issues `json:"issues,omitempty"`
}

// maxKernelThreadNames bounds the kernel thread names listed.
const maxKernelThreadNames = 512

// KernelThreadFamily reduces a kernel thread's name to what its instances share: the part
// before "/" and without trailing digits, so kworker/0:1H, kswapd0 and scsi_eh_3 are kworker,
// kswapd and scsi_eh_.
func KernelThreadFamily(comm string) string {
	name, _, _ := strings.Cut(comm, "/")
	return strings.TrimRight(name, "0123456789")
}

// Processes collects every user-space process from /proc. Kernel threads, recognised by the
// PF_KTHREAD flag the kernel sets on them, are only counted; a process that names itself like
// one ([kworker/0:1]) or hides its command line is still listed.
type Processes struct{}

func (Processes) Name() string { return "processes" }

func (Processes) Collect(ctx context.Context, src collector.Source) (any, error) {
	var res ProcessesResult
	hashes := map[string]string{}
	// The host's mount namespace: a path is looked up in the observed root, which is that
	// namespace's view, never a container's.
	hostMnt, _ := fs.ReadLink(src.FS, "proc/1/ns/mnt")
	hostRoot := &rootOf{}
	// dpkg's file lists, read at most once per snapshot and only when a process needs them.
	var owned map[string]bool
	packaged := func(p string) bool {
		if owned == nil {
			owned = dpkgOwned(src.FS)
		}
		// With merged /usr, dpkg may list /sbin/agetty for what runs as /usr/sbin/agetty.
		return owned[p] || owned[strings.TrimPrefix(p, "/usr")] || owned["/usr"+p]
	}

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
			if f := KernelThreadFamily(p.Comm); f != "" && !slices.Contains(res.KernelThreadNames, f) && len(res.KernelThreadNames) < maxKernelThreadNames {
				res.KernelThreadNames = append(res.KernelThreadNames, f)
			}
			continue
		}
		if p.Exe != "" {
			p.ExeSHA256 = exeHash(src, pid, hashes, &res.Issues)
		}
		p.Mapped = mappedCode(src.FS, pid, p.Exe)
		// Replaced only where the path means the same file for the process and for the sensor,
		// and only by a file of root nobody else can write: anyone could put a file there. A
		// service systemd sandboxes has a mount namespace of its own over the host's root, where
		// the path means the same; a container's root is another filesystem.
		if p.ExeDeleted && strings.HasPrefix(p.Exe, "/") && hostMnt != "" && (p.MntNS == hostMnt || hostRoot.sameAs(src.FS, pid)) {
			if info, err := fs.Lstat(src.FS, collector.Rel(p.Exe)); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o022 == 0 {
				if uid, ok := collector.Owner(info); ok && uid == 0 {
					p.ExeReplaced = true
					p.ExePackaged = packaged(p.Exe)
				}
			}
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

// maxOwnedPaths bounds the paths of dpkg's file lists held in memory.
const maxOwnedPaths = 1 << 20

// dpkgOwned reads every path dpkg's file lists name, bounded.
func dpkgOwned(fsys fs.FS) map[string]bool {
	owned := map[string]bool{}
	for _, name := range collector.Glob(fsys, "var/lib/dpkg/info/*.list") {
		lines, err := collector.ReadLines(fsys, name)
		if err != nil {
			continue
		}
		for _, l := range lines {
			if len(owned) >= maxOwnedPaths {
				return owned
			}
			owned[l] = true
		}
	}
	return owned
}

// Bounds on reading memory maps: a JVM or a browser maps thousands of regions.
const (
	maxMapsSize   = 4 << 20
	maxMappedList = 20
)

// unusualCodeDirs are where no code a process maps should come from.
var unusualCodeDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/home/", "/root/", "/var/www/", "/srv/", "/run/lock/", "/var/lib/php/"}

// systemLibDirs hold packaged code: a deleted file there is an upgrade, not an intrusion.
var systemLibDirs = []string{"/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/opt/", "/snap/", "/nix/store/"}

// mappedCode reads a process's executable mappings and keeps those of files it should not run
// code from, its own executable aside: the rules on the executable cover it.
func mappedCode(fsys fs.FS, pid int, exe string) []string {
	data, err := fs.ReadFile(fsys, fmt.Sprintf("proc/%d/maps", pid))
	if err != nil || len(data) > maxMapsSize {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		// address perms offset dev inode path. A shared anonymous region, what OPcache's JIT and
		// other caches map executable, shows as "/dev/zero (deleted)": that exact name, shared,
		// is no file at all. Shared mappings of real files, memfd ones included, still count.
		f := strings.SplitN(line, " ", 6)
		if len(f) < 6 || len(f[1]) < 4 || f[1][2] != 'x' {
			continue
		}
		// The kernel's internal shmem mount is the first anonymous device, 00:01: a real file
		// someone named /dev/zero and deleted lives elsewhere.
		if f[1][3] == 's' && f[3] == "00:01" && strings.TrimSpace(f[5]) == "/dev/zero (deleted)" {
			continue
		}
		file := strings.TrimSpace(f[5])
		if !strings.HasPrefix(file, "/") {
			continue
		}
		name, deleted := strings.CutSuffix(file, deletedSuffix)
		keep := strings.HasPrefix(name, "/memfd:") ||
			slices.ContainsFunc(unusualCodeDirs, func(d string) bool { return strings.HasPrefix(name, d) }) ||
			(deleted && !slices.ContainsFunc(systemLibDirs, func(d string) bool { return strings.HasPrefix(name, d) }))
		if keep && name != exe && !slices.Contains(out, file) {
			out = append(out, clipField(file))
			if len(out) == maxMappedList {
				break
			}
		}
	}
	return out
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

// ReadProcess reads one process the way the collector does, its command line redacted: for the
// real-time watcher, which looks at a process the moment it starts.
func ReadProcess(fsys fs.FS, pid int) (Process, bool) {
	var issues collector.Issues
	return readProcess(fsys, pid, &issues)
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
		case key == "TracerPid" && len(fields) > 0:
			p.Tracer, _ = strconv.Atoi(fields[0])
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
	secretOption = regexp.MustCompile(`(?i)^(--?[a-z0-9_-]*(password|passwd|passphrase|token|secret|apikey|api-key|api_key|credential|private-key)[a-z0-9_-]*)=(.*)$`)
	secretEnv    = regexp.MustCompile(`(?i)^([a-z0-9_]*(password|passwd|pwd|token|secret|api_?key|auth|credential)[a-z0-9_]*)=.+`)
	// The password may contain @: everything up to the last @ before the host is userinfo.
	urlUserinfo = regexp.MustCompile(`(://[^:/@\s]*):[^/\s]*@`)
	authHeader  = regexp.MustCompile(`(?i)^((proxy-)?authorization|x-api-key|cookie)\s*:.*`)
)

// Options whose next argument is a secret. Only known ones: hiding the argument after any
// option with a suspicious name would let a process hide, say, the address it connects to.
var secretNextArg = map[string][]string{
	"":          {"--password", "--passwd", "--token", "--secret", "--api-key", "--apikey", "--auth-token", "--access-token", "--client-secret"},
	"redis-cli": {"-a", "--pass", "--user-pass"},
	"sshpass":   {"-p"},
	"mysql":     {"--password"},
	"curl":      {"-u", "--user", "--proxy-user", "--oauth2-bearer"},
	"openssl":   {"-pass", "-passin", "-passout", "-k"},
	"wget":      {"--password", "--http-password", "--ftp-password", "--proxy-password"},
}

// redactCmdline joins the arguments of a process after removing the secrets commonly passed
// on the command line: values of password and token options, NAME=value pairs with sensitive
// names, passwords in URLs, authorization headers, the -p<password> form of the MySQL and
// MariaDB clients, and the same inside a shell's -c script.
func redactCmdline(args []string) string {
	prog := ""
	if len(args) > 0 {
		prog = path.Base(args[0])
	}
	out := make([]string, 0, len(args))
	hideNext := false
	for i, a := range args {
		if hideNext {
			out = append(out, "[redacted]")
			hideNext = false
			continue
		}
		// A script after -c, whether the program is a shell or a wrapper (sudo, su, env,
		// timeout...) that passes it to one.
		if i > 0 && args[i-1] == "-c" && strings.ContainsAny(a, " \t") {
			out = append(out, redactCmdline(shellWords(a)))
			continue
		}
		a, hideNext = redactArg(prog, a)
		out = append(out, a)
	}
	return strings.TrimSpace(strings.Join(out, " "))
}

func redactArg(prog, a string) (string, bool) {
	family := prog
	if strings.Contains(prog, "mysql") || strings.Contains(prog, "mariadb") {
		family = "mysql"
	}
	if slices.Contains(secretNextArg[family], a) || slices.Contains(secretNextArg[""], a) {
		return a, true
	}
	switch {
	case family == "mysql" && strings.HasPrefix(a, "-p") && len(a) > 2:
		return "-p[redacted]", false
	case family == "sshpass" && strings.HasPrefix(a, "-p") && len(a) > 2:
		return "-p[redacted]", false
	case family == "curl" && (strings.HasPrefix(a, "-u") && len(a) > 2):
		return "-u[redacted]", false
	case strings.HasPrefix(a, "pass:") || strings.HasPrefix(a, "env:"):
		return a[:5] + "[redacted]", false
	case secretOption.MatchString(a):
		return secretOption.FindStringSubmatch(a)[1] + "=[redacted]", false
	case secretEnv.MatchString(a):
		return secretEnv.FindStringSubmatch(a)[1] + "=[redacted]", false
	case authHeader.MatchString(a):
		name, _, _ := strings.Cut(a, ":")
		return name + ": [redacted]", false
	case strings.Contains(a, "Authorization:") || strings.Contains(a, "authorization:"):
		before, _, _ := strings.Cut(a, ":")
		return before + ": [redacted]", false
	}
	return urlUserinfo.ReplaceAllString(a, "$1:[redacted]@"), false
}

// shellWords splits a shell script into words, keeping quoted strings together, so that a
// header such as "Authorization: Bearer x" stays one argument.
func shellWords(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	in := false
	for _, r := range s {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote == 0 && (r == '"' || r == '\''):
			quote, in = r, true
		case quote == 0 && (r == ' ' || r == '\t' || r == ';' || r == '|' || r == '&'):
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(r)
			in = true
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
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

// rootOf caches the mount the host's init sees as "/".
type rootOf struct {
	read  bool
	entry mountEntry
	ok    bool
}

// sameAs reports whether process pid sees as "/" the same part of the same filesystem as the
// host's init.
func (h *rootOf) sameAs(fsys fs.FS, pid int) bool {
	if !h.read {
		h.entry, h.ok = rootMount(fsys, "proc/1/mountinfo")
		h.read = true
	}
	e, ok := rootMount(fsys, "proc/"+strconv.Itoa(pid)+"/mountinfo")
	return h.ok && ok && e.dev == h.entry.dev && e.root == h.entry.root
}

// rootMount is the mount at "/" in a mount table: the last one, which covers those before.
func rootMount(fsys fs.FS, name string) (mountEntry, bool) {
	entries, err := readMountEntries(fsys, name)
	if err != nil {
		return mountEntry{}, false
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].point == "/" {
			return entries[i], true
		}
	}
	return mountEntry{}, false
}
