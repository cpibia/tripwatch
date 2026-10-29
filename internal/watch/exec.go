package watch

import (
	"crypto/sha256"
	"path"
	"regexp"
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
	// fromCron reports whether a process descends from cron, fromRuntime whether a container
	// runtime started it; owner returns a file's owner.
	fromCron    func(p system.Process) bool
	fromRuntime func(p system.Process) bool
	owner       func(path string) (int, bool)
	// parent returns the process that started p.
	parent func(p system.Process) (system.Process, bool)
}

// classifyExec says why a process that just started matters, or "" when it does not, and the
// script it runs when the executable is an interpreter.
func classifyExec(p system.Process, c execContext) (reason, script string) {
	exe := path.Clean(p.Exe)
	tool := toolName(exe, p.Comm)
	if slices.Contains(interpreters, tool) || strings.HasPrefix(tool, "php") {
		if script = scriptArg(rawCommand(p)); script != "" {
			script = path.Clean(script)
		}
	}
	switch {
	case p.ExeDeleted:
		return ReasonDeleted, script
	// Where the web server's user also runs scheduled jobs, what cron starts is those jobs; a
	// crontab the web user planted is reported by the schedule rules.
	case c.webUsers[p.UID] && slices.Contains(webTools, tool) && (c.fromCron == nil || !c.fromCron(p)) &&
		(c.fromRuntime == nil || !c.fromRuntime(p)) && !c.routineShell(p, tool):
		return ReasonWebShell, script
	case (unusual(exe) && !c.ownCronJob(p, exe)) || (unusual(script) && !c.ownCronJob(p, script) && !c.packageScript(p, script) && !c.frameworkCLI(script)):
		return ReasonUnusualPath, script
	}
	return "", script
}

// rawCommand is a process's command line as the kernel gives it: the redacted one hides the
// words that look like secrets, and a command must be judged on what runs.
func rawCommand(p system.Process) string {
	if p.Args == nil {
		return p.Cmdline
	}
	return strings.Join(p.Args, " ")
}

// sendmailCommand is the command PHP's mail() hands to sh -c: the configured sendmail with its
// options and nothing a shell would interpret.
var sendmailCommand = regexp.MustCompile(`^/usr/(?:s?bin|lib)/sendmail(?: +-[A-Za-z][^\s;&|$` + "`" + `<>()'"\\]*)*$`)

// virusScanCommand is ClamAV run on one uploaded file, as the upload plugins of CMSs do: the
// scanner from the system's directories, options only, and one file, single-quoted (where the
// shell expands nothing) or plain, its errors sent to the output the plugin reads.
var virusScanCommand = regexp.MustCompile(`^/usr/(?:local/)?bin/clamd?scan(?: +--?[a-z][a-z-]*(?:=[A-Za-z0-9_./-]+)?)* +(?:'[^']*'|[^\s;&|$` + "`" + `<>()'"\\]+)(?: 2>&1)?$`)

// terminalQuery is a console library asking for the terminal's size or settings, as Symfony's
// Console does (under Laravel's artisan, Composer, Drush and Magento's CLI) at every command:
// stty run alone, or through the shell, its output silenced or filtered for the columns.
var terminalQuery = regexp.MustCompile(`^stty(?: -[ag])?(?: 2> ?/dev/null| 2>&1)?(?: \| grep columns)?$`)

// errorReporterCommands are the shell commands error reporters run from the PHP pool when an
// application throws (Flare and Ignition read the project's git root): matched whole, they only
// print a directory, and anything appended makes them a shell command like any other.
var errorReporterCommands = []string{"echo $(git rev-parse --show-toplevel)"}

// backgroundTask is how Laravel's scheduler starts a task in the background: the task, then
// schedule:finish with the task's mutex name and exit status, both silenced. Only the task, in
// the first group, is then judged like any other command.
var backgroundTask = regexp.MustCompile(`^\(([^;&|$` + "`" + `<>()]+?) > '?/dev/null'? 2>&1 ; ([^;&|$` + "`" + `<>()]+) schedule:finish "?[A-Za-z0-9/_-]+"? "?\$\?"?\) > '?/dev/null'? 2>&1 ?&?$`)

// silenced is the redirection schedulers put after a command; plainCommand allows it, and
// nothing else a shell would interpret.
var silenced = regexp.MustCompile(` > '?/dev/null'? 2>&1$`)

func plainCommand(command string) (string, bool) {
	command = silenced.ReplaceAllString(command, "")
	return command, !strings.ContainsAny(command, ";&|$`<>()\n")
}

// routineShell reports a shell the web server's user starts for its own work, which a webshell
// cannot pass for: PHP's mail() running the configured sendmail, ClamAV scanning an upload, an
// error reporter reading the project's git root, and a framework's scheduler or
// queue worker running one of its commands. The scheduler is the parent, not something named in
// the command: the shells a webshell starts have the PHP pool as their parent.
func (c execContext) routineShell(p system.Process, tool string) bool {
	// Alpine's sh is BusyBox.
	if !slices.Contains([]string{"sh", "bash", "dash", "ash", "busybox"}, tool) {
		return false
	}
	// BusyBox's applets, stty among them, run as busybox itself.
	if tool == "busybox" && terminalQuery.MatchString(rawCommand(p)) {
		return true
	}
	_, command, ok := strings.Cut(rawCommand(p), " -c ")
	if !ok {
		return false
	}
	// Symfony's mailer ends the shell's options with "--" before the command.
	command = strings.TrimPrefix(command, "-- ")
	// Laravel's scheduler runs a task in the background as a subshell that reports its end.
	if m := backgroundTask.FindStringSubmatch(command); m != nil {
		if !c.frameworkCommand(m[2]) {
			return false
		}
		command = m[1]
	}
	// Queue supervisors replace the shell with the worker.
	command = strings.TrimPrefix(command, "exec ")
	if sendmailCommand.MatchString(command) || virusScanCommand.MatchString(command) || terminalQuery.MatchString(command) ||
		slices.Contains(errorReporterCommands, command) {
		return true
	}
	command, plain := plainCommand(command)
	if !plain || c.parent == nil || !c.frameworkCommand(command) {
		return false
	}
	parent, ok := c.parent(p)
	return ok && parent.UID == p.UID && c.frameworkCommand(rawCommand(parent))
}

// frameworkCommand reports whether a command line runs PHP on a framework's command-line entry
// point outside every upload directory, the way schedulers start each of their commands.
func (c execContext) frameworkCommand(cmdline string) bool {
	fields := strings.Fields(cmdline)
	if len(fields) < 2 || !strings.HasPrefix(path.Base(fields[0]), "php") {
		return false
	}
	return c.frameworkCLI(path.Clean(fields[1]))
}

// frameworkCLI reports whether a script is a framework's command-line entry point, which
// schedulers and queue workers run from the application all day (php artisan schedule:run,
// bin/console, bin/magento), outside every upload directory. A changed entry point is reported
// by the application's code manifest.
func (c execContext) frameworkCLI(script string) bool {
	base, dir := path.Base(script), path.Base(path.Dir(script))
	if base != "artisan" && (dir != "bin" || base != "console" && base != "magento") {
		return false
	}
	return !slices.ContainsFunc(c.uploads, func(u string) bool { return strings.HasPrefix(script, strings.TrimSuffix(u, "/")+"/") })
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

// debconfConfig is the name apt-extracttemplates gives the configuration script of a package it
// extracts for dpkg-preconfigure: the package name, ".config." and mkstemp's six characters.
var debconfConfig = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,99}\.config\.[A-Za-z0-9]{6}$`)

// rpmScriptlet is the name rpm gives a package's install or removal scriptlet it writes to
// %_tmppath and runs with the shell.
var rpmScriptlet = regexp.MustCompile(`^rpm-tmp\.[A-Za-z0-9]{6}$`)

// packageScript reports whether a script run from a scratch directory is one the package
// manager wrote there and runs as root during an installation or upgrade: apt's debconf
// configuration scripts, rpm's scriptlets. Run by root, as root, from a root-owned file named
// the way the package manager names it, started by the package manager itself. The parent is
// known by its executable, UID and command line, not by its process name, which anyone can set.
func (c execContext) packageScript(p system.Process, script string) bool {
	if p.UID != 0 || p.EUID != 0 || c.owner == nil || c.parent == nil {
		return false
	}
	if dir := path.Dir(script); dir != "/tmp" && dir != "/var/tmp" {
		return false
	}
	name := path.Base(script)
	debconf, rpm := debconfConfig.MatchString(name), rpmScriptlet.MatchString(name)
	if !debconf && !rpm {
		return false
	}
	if uid, ok := c.owner(script); !ok || uid != 0 {
		return false
	}
	parent, ok := c.parent(p)
	return ok && (debconf && preconfigure(parent) || rpm && rpmInstaller(parent))
}

// preconfigure reports whether a parent process is apt's dpkg-preconfigure: the system's perl,
// as root, running /usr/sbin/dpkg-preconfigure.
func preconfigure(parent system.Process) bool {
	if !rootProgram(parent) || (parent.Exe != "/usr/bin/perl" && parent.Exe != "/bin/perl") {
		return false
	}
	return scriptArg(rawCommand(parent)) == "/usr/sbin/dpkg-preconfigure"
}

// rpmPrograms run rpm's scriptlets themselves; rpmPythonTools are the Python front ends that
// load librpm into the interpreter.
var (
	rpmPrograms    = []string{"/usr/bin/rpm", "/bin/rpm", "/usr/bin/dnf5", "/usr/bin/microdnf", "/usr/libexec/packagekitd"}
	rpmPythonTools = []string{"/usr/bin/dnf", "/usr/bin/dnf-3", "/usr/bin/yum", "/usr/bin/dnf-automatic", "/bin/dnf", "/bin/yum"}
	systemPython   = regexp.MustCompile(`^/usr/(bin/python[0-9.]*|libexec/platform-python[0-9.]*)$`)
)

// rpmInstaller reports whether a parent process is rpm or a package manager built on librpm,
// as root, from the system's own executable.
func rpmInstaller(parent system.Process) bool {
	if !rootProgram(parent) {
		return false
	}
	if slices.Contains(rpmPrograms, parent.Exe) {
		return true
	}
	return systemPython.MatchString(parent.Exe) && slices.Contains(rpmPythonTools, scriptArg(rawCommand(parent)))
}

func rootProgram(p system.Process) bool {
	return p.UID == 0 && p.EUID == 0 && !p.ExeDeleted
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

// maxText bounds the text fields of process and container events.
const maxText = 256

func clipText(s string) string {
	if len(s) > maxText {
		s = s[:maxText]
	}
	return strings.ToValidUTF8(s, "")
}
