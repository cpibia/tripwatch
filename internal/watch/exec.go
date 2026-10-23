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

// classifyExec says why a process that just started matters, or "" when it does not.
func classifyExec(p system.Process, webUsers map[int]bool) string {
	exe := p.Exe
	switch {
	case p.ExeDeleted:
		return ReasonDeleted
	case webUsers[p.UID] && slices.Contains(webTools, toolName(exe, p.Comm)):
		return ReasonWebShell
	case exe != "" && slices.ContainsFunc(unusualExecDirs, func(d string) bool { return strings.HasPrefix(exe, d) }):
		return ReasonUnusualPath
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
