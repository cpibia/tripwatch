package watch

import (
	"crypto/sha256"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/cpibia/tripwatch/internal/collector/system"
)

// RepeatWindow is how long an identical process start is reported only once. A job the web
// server's user runs every minute would otherwise fill the verifier's daily budget for what
// that user can produce; a start that differs in anything is reported at once.
const RepeatWindow = time.Hour

// maxRepeatKeys bounds the starts remembered. When it is full of recent starts a new one is not
// remembered and every repeat of it is reported: whoever fills it gains noise, not silence.
const maxRepeatKeys = 1024

// repeats remembers the process starts reported within RepeatWindow. It is used from the
// goroutine that reads process events only.
type repeats struct {
	seen map[[sha256.Size]byte]*repeat
}

type repeat struct {
	at      time.Time
	skipped int
}

// report says whether a start is to be reported, and how many identical starts were left out
// since the last one reported. The caller passes what identifies the start, everything an
// alert says of the process but its PID, before any clipping: two command lines that differ
// only past the clipped length are different starts.
func (r *repeats) report(now time.Time, identity ...string) (bool, int) {
	if r.seen == nil {
		r.seen = map[[sha256.Size]byte]*repeat{}
	}
	key := sha256.Sum256([]byte(strings.Join(identity, "\x00")))
	if prev, ok := r.seen[key]; ok {
		if now.Sub(prev.at) < RepeatWindow && !now.Before(prev.at) {
			prev.skipped++
			return false, 0
		}
		skipped := prev.skipped
		prev.at, prev.skipped = now, 0
		return true, skipped
	}
	if len(r.seen) >= maxRepeatKeys {
		for k, v := range r.seen {
			if now.Sub(v.at) >= RepeatWindow || now.Before(v.at) {
				delete(r.seen, k)
			}
		}
		if len(r.seen) >= maxRepeatKeys {
			return true, 0
		}
	}
	r.seen[key] = &repeat{at: now}
	return true, 0
}

// webUserNames are the accounts web servers and their PHP pools run as on common distributions.
var webUserNames = []string{"www-data", "nginx", "apache", "http", "wwwrun", "lighttpd", "caddy", "httpd"}

// webServerComms are the process names of web servers and of the interpreters they hand
// requests to.
var webServerComms = []string{"nginx", "apache2", "httpd", "caddy", "lighttpd", "lsphp", "php-fpm", "php-cgi", "gunicorn", "uwsgi", "puma", "unicorn", "passenger", "Passenger"}

// webTools are what a webshell runs once it is in: shells, interpreters, network and download
// tools, and the commands that make a foothold persistent.
var webTools = []string{
	"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "ash", "busybox",
	"python", "python2", "python3", "perl", "ruby", "lua", "node",
	"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "nmap", "ftp", "tftp",
	"base64", "xxd", "chmod", "chattr", "crontab", "at", "nohup", "setsid", "useradd", "usermod", "passwd",
}

// interpreters run a script named on their command line: /proc shows the interpreter as the
// executable, and the script is what was put in place.
var interpreters = []string{"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", "python", "python2", "python3", "perl", "ruby", "lua", "node", "php"}

// unusualExecDirs are where programs are not installed: what starts from there was put there.
var unusualExecDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/home/", "/root/", "/var/www/", "/srv/", "/run/lock/", "/var/lib/php/"}

// systemBinDirs are where packaged programs live, setuid ones included.
var systemBinDirs = []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/", "/lib/", "/usr/local/bin/", "/usr/local/sbin/", "/snap/"}

// WebUsers returns the UIDs the web server and its interpreters run as: the usual account names,
// and the owners of running web server processes other than root.
func WebUsers(accounts *system.AccountsResult, processes *system.ProcessesResult) []int {
	seen := map[int]bool{}
	if accounts != nil {
		for _, a := range accounts.Accounts {
			if slices.Contains(webUserNames, a.Name) && a.UID != 0 {
				seen[a.UID] = true
			}
		}
	}
	if processes != nil {
		for _, p := range processes.Processes {
			name := p.Comm
			if i := strings.IndexAny(name, ":. "); i > 0 {
				name = name[:i]
			}
			if p.UID != 0 && (slices.Contains(webServerComms, name) || strings.HasPrefix(name, "php-fpm") || strings.HasPrefix(name, "php")) {
				seen[p.UID] = true
			}
		}
	}
	out := make([]int, 0, len(seen))
	for uid := range seen {
		out = append(out, uid)
	}
	slices.Sort(out)
	return out
}

// execContext is what classifying a process start needs to know of the host.
type execContext struct {
	webUsers map[int]bool
	// homes maps UIDs to their home directories, uploads lists the upload directories.
	homes   map[int]string
	uploads []string
	// fromCron reports whether a process descends from cron; owner returns a file's owner.
	fromCron func(p system.Process) bool
	owner    func(path string) (int, bool)
}

// classifyExec says why a process that just started matters, or "" when it does not, and the
// script it runs when the executable is an interpreter.
func classifyExec(p system.Process, c execContext) (reason, script string) {
	exe := path.Clean(p.Exe)
	tool := toolName(exe, p.Comm)
	if slices.Contains(interpreters, tool) || strings.HasPrefix(tool, "php") {
		if script = scriptArg(p.Cmdline); script != "" {
			script = path.Clean(script)
		}
	}
	switch {
	case p.ExeDeleted:
		return ReasonDeleted, script
	case c.webUsers[p.UID] && slices.Contains(webTools, tool):
		return ReasonWebShell, script
	case (unusual(exe) && !c.ownCronJob(p, exe)) || (unusual(script) && !c.ownCronJob(p, script)):
		return ReasonUnusualPath, script
	}
	return "", script
}

// ownCronJob reports whether a program from an unusual place is an account's own scheduled job:
// run by cron, from the account's home, from a file the account owns, outside every upload
// directory. Root and the web server's user never qualify, the latter's home being often the
// web root.
func (c execContext) ownCronJob(p system.Process, file string) bool {
	home := c.homes[p.UID]
	if p.UID == 0 || c.webUsers[p.UID] || home == "" || home == "/" {
		return false
	}
	if !strings.HasPrefix(file, strings.TrimSuffix(path.Clean(home), "/")+"/") {
		return false
	}
	if slices.ContainsFunc(c.uploads, func(u string) bool { return file == u || strings.HasPrefix(file, strings.TrimSuffix(u, "/")+"/") }) {
		return false
	}
	if c.owner == nil || c.fromCron == nil {
		return false
	}
	if uid, ok := c.owner(file); !ok || uid != p.UID {
		return false
	}
	return c.fromCron(p)
}

func unusual(p string) bool {
	return p != "" && slices.ContainsFunc(unusualExecDirs, func(d string) bool { return strings.HasPrefix(p, d) })
}

// scriptArg is the script an interpreter's command line names: its first argument that is not
// an option, unless the code is given inline.
func scriptArg(cmdline string) string {
	fields := strings.Fields(cmdline)
	for _, f := range fields[min(1, len(fields)):] {
		switch {
		case f == "-c" || f == "-e" || f == "-r" || f == "-m":
			return ""
		case strings.HasPrefix(f, "-"):
			continue
		case strings.HasPrefix(f, "/"):
			return f
		}
		return ""
	}
	return ""
}

// privileged reports whether a change to an effective UID of 0 came from outside the system's
// binary directories: sudo and su gaining root are routine, a setuid copy in /tmp is not.
func privileged(p system.Process, ruid, euid int) bool {
	if euid != 0 || ruid == 0 {
		return false
	}
	return p.Exe == "" || !slices.ContainsFunc(systemBinDirs, func(d string) bool { return strings.HasPrefix(p.Exe, d) })
}

// toolName is the program a process runs, by its executable, with versions and variants
// dropped: python3.11 is python3, nc.openbsd is nc.
func toolName(exe, comm string) string {
	name := path.Base(exe)
	if exe == "" {
		name = comm
	}
	if i := strings.IndexFunc(name, func(r rune) bool { return r == '.' || (r >= '0' && r <= '9') }); i > 0 {
		for _, c := range []string{name[:i+1], name[:i]} {
			if slices.Contains(webTools, c) {
				return c
			}
		}
	}
	return name
}
