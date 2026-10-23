package watch

import (
	"path"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector/system"
)

// webUserNames are the accounts web servers and their PHP pools run as on common distributions.
var webUserNames = []string{"www-data", "nginx", "apache", "http", "wwwrun", "lighttpd", "caddy", "httpd"}

// webServerComms are the process names of web servers and of the interpreters they hand
// requests to.
var webServerComms = []string{"nginx", "apache2", "httpd", "caddy", "lighttpd", "lsphp", "php-fpm", "php-cgi"}

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

// classifyExec says why a process that just started matters, or "" when it does not, and the
// script it runs when the executable is an interpreter. homes maps UIDs to their home
// directories: an account running a program from its own home is its owner's business, such as
// a crontab calling a script, unless the account is the web server's, whose home is often the
// web root where uploads land.
func classifyExec(p system.Process, webUsers map[int]bool, homes map[int]string) (reason, script string) {
	exe := p.Exe
	tool := toolName(exe, p.Comm)
	if slices.Contains(interpreters, tool) || strings.HasPrefix(tool, "php") {
		script = scriptArg(p.Cmdline)
	}
	switch {
	case p.ExeDeleted:
		return ReasonDeleted, script
	case webUsers[p.UID] && slices.Contains(webTools, tool):
		return ReasonWebShell, script
	case (unusual(exe) && !ownHome(p.UID, exe, webUsers, homes)) || (unusual(script) && !ownHome(p.UID, script, webUsers, homes)):
		return ReasonUnusualPath, script
	}
	return "", script
}

// ownHome reports whether path lies in the home of the account uid, other than root's and the
// web server's.
func ownHome(uid int, p string, webUsers map[int]bool, homes map[int]string) bool {
	home := homes[uid]
	if uid == 0 || webUsers[uid] || home == "" || home == "/" {
		return false
	}
	return strings.HasPrefix(p, strings.TrimSuffix(home, "/")+"/")
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
