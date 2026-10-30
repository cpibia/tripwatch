package analyze

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cpibia/tripwatch/internal/collector/web"
	"github.com/cpibia/tripwatch/internal/watch"
)

// EventKind is the kind of the alerts raised from events reported in real time. They describe
// a change, so no snapshot resolves them: someone acknowledges them.
const EventKind = "realtime"

// TransientWindow is how soon a file has to go after it appeared to count as hidden from the
// snapshots: what lives less than this between two of them, an hour apart, is easily missed.
const TransientWindow = 15 * time.Minute

// History returns the host's earlier events on a path since a time, oldest first, the events of
// the batch being judged included.
type History func(path string, since time.Time) []watch.Event

// EvaluateEvents judges one batch of events. A package manager running when the batch was sent
// lowers the severity of the changes packages make all the time (see lowered).
func EvaluateEvents(events []watch.Event, packageManager bool, history History) []Finding {
	var out []Finding
	for _, e := range events {
		// The names package managers stage a file under while they install it come and go
		// with every installation: while one runs, the file under its own name is what counts.
		// Only outside the scratch directories and for no other user's file: dpkg stages a file
		// next to its destination, never in /tmp or /dev/shm, where the name would only hide a
		// dropper. A removal carries no owner; outside the scratch directories only root writes.
		if (packageManager || e.PackageManager) && lowered(e) && e.Class != watch.ClassScratch && packageTemp(e.Path) {
			continue
		}
		f, ok := judgeEvent(e, history)
		if !ok {
			continue
		}
		// The content is part of the fingerprint: an alert acknowledged for one content must
		// not absorb a different change to the same file later.
		if e.SHA256 != "" && !strings.Contains(f.Fingerprint, "-transient:") {
			f.Fingerprint += " sha256:" + e.SHA256[:min(16, len(e.SHA256))]
		}
		if (packageManager || e.PackageManager) && lowered(e) {
			f.Severity = lower(f.Severity)
			f.Detail += " A package manager was running at the time: an installation or an upgrade may have made this change."
		}
		out = append(out, f)
	}
	return out
}

// packageTemp reports the names under which dpkg, rpm and apk stage a file they install or keep
// the one they replace.
func packageTemp(p string) bool {
	return slices.ContainsFunc([]string{".dpkg-new", ".dpkg-tmp", ".dpkg-old", ".dpkg-dist", ".rpmnew", ".rpmsave", ".rpmorig", ".apk-new"},
		func(suffix string) bool { return strings.HasSuffix(p, suffix) })
}

// rootOwned reports an event on a file root owns, which no other user can have made.
func rootOwned(e watch.Event) bool {
	return e.UID != nil && *e.UID == 0 && notAnotherUsers(e)
}

// notAnotherUsers reports an event on no other user's file: not in a user's home or crontab nor
// owned by another user; a removal carries no owner, and outside those places only root writes.
func notAnotherUsers(e watch.Event) bool {
	return !e.WebUser && e.Owner == "" && (e.UID == nil || *e.UID == 0)
}

// lowered says whether a package manager running explains an event well enough to lower its
// severity: packages install services, scheduled tasks and start-up scripts all the time, and
// root's files in the scratch directories. Never who may become root, the accounts, SSH keys or
// library preloading, which a package rarely touches and an intruder always does; nor process
// starts or uploads, which no package explains; nor another user's files, a crontab or a start-up
// file in a home or anything in the scratch directories, which the web server's user can time to
// the package manager's lock, readable by anyone.
func lowered(e watch.Event) bool {
	switch e.Class {
	case watch.ClassService, watch.ClassSchedule:
		return notAnotherUsers(e)
	case watch.ClassScratch:
		return rootOwned(e)
	case watch.ClassHook:
		return path.Base(e.Path) != "ld.so.preload" && notAnotherUsers(e)
	}
	return false
}

func judgeEvent(e watch.Event, history History) (Finding, bool) {
	switch e.Class {
	case watch.ClassExec:
		return judgeExec(e)
	case watch.ClassContainer:
		return judgeContainer(e)
	}
	if e.Root {
		// Moving a watched place away and back blinds the watch on it until it is placed again:
		// that it happened is the signal, whoever did it.
		sev := "high"
		if e.Class == watch.ClassScratch {
			sev = "medium"
		}
		// Grouped by class and path: one directory moved again and again fills its own group,
		// never the one of a system directory.
		return event("watch-root", e.Class+":"+e.Path+"|"+strings.TrimSpace(occurrence(e)), sev, "Watched directory moved away or removed: "+e.Path,
			fmt.Sprintf("%s, watched in real time, was moved away or removed at %s. Changes inside it are not seen until it is back in place and watched again, which the sensor checks every few seconds; the next snapshot shows its state.", e.Path, e.At.Format("15:04:05"))), true
	}
	if e.Dir || e.Path == "" {
		return Finding{}, false
	}
	name := path.Base(e.Path)
	switch e.Class {
	case watch.ClassWebRoot:
		// Deploys write the web root all the time, and the snapshots name what changes there;
		// a script that appears and goes between two of them is a probe cleaning up after
		// itself.
		if !web.IsScript(name) || e.Op != watch.OpDelete {
			return Finding{}, false
		}
		if first, ok := appeared(e, history); ok {
			return event("webroot-transient", e.Path+occurrence(first), "critical", "A script appeared in a web root and was removed",
				fmt.Sprintf("%s was created at %s and removed at %s, too soon for any snapshot to show it. A probe or a webshell that deletes itself does this: check the web server's logs for requests to it in that interval. %s",
					e.Path, first.At.Format("15:04:05"), e.At.Format("15:04:05"), describeFile(first))), true
		}
		return Finding{}, false
	case watch.ClassUpload:
		if !web.IsScript(name) && !web.IsOverride(name) {
			return Finding{}, false
		}
		what := "A script"
		if web.IsOverride(name) {
			what = "A server configuration file"
		}
		if e.Op == watch.OpDelete {
			if first, ok := appeared(e, history); ok {
				return event("upload-transient", e.Path+occurrence(first), "critical", what+" appeared in an upload directory and was removed",
					fmt.Sprintf("%s was created at %s and removed at %s, too soon for any snapshot to show it. This is how a webshell is used and cleaned up: check the web server's logs for requests to it in that interval. %s",
						e.Path, first.At.Format("15:04:05"), e.At.Format("15:04:05"), describeFile(first))), true
			}
			return Finding{}, false
		}
		if e.Op == watch.OpAttrib && e.Mode == "" {
			return Finding{}, false
		}
		return event("upload-script", e.Path, "high", what+" appeared in an upload directory",
			fmt.Sprintf("%s: %s. Upload directories hold what visitors send; a script there is how a webshell lands, and a server configuration file there can make the server run what is uploaded next.", e.Path, describeFile(e))), true

	case watch.ClassScratch:
		dir := scratchRoot(e.Path)
		// Each account's drops are a group of their own: one user's builds, which come and go in
		// /tmp all day, never fold root's or the web server's into an aggregate.
		if e.Op == watch.OpDelete {
			if first, ok := appeared(e, history); ok {
				sev := "high"
				if first.WebUser || (first.UID != nil && *first.UID == 0) {
					sev = "critical"
				}
				return event("scratch-transient", owner(first)+"|"+e.Path+occurrence(first), sev, "Executable dropped in "+dir+" and removed",
					fmt.Sprintf("%s was written at %s and removed at %s: a program dropped, most likely run and deleted so that nothing stays on disk. %s",
						e.Path, first.At.Format("15:04:05"), e.At.Format("15:04:05"), describeFile(first))), true
			}
			return Finding{}, false
		}
		if !watch.Executable(e.Mode) {
			return Finding{}, false
		}
		sev := "medium"
		if e.WebUser || (e.UID != nil && *e.UID == 0) {
			sev = "high"
		}
		return event("scratch-exec", owner(e)+"|"+e.Path, sev, "Executable file in "+dir,
			fmt.Sprintf("%s: %s. Programs are not installed in %s; an executable there was put there, by a build, an installer, or an intruder staging a tool.", e.Path, describeFile(e), dir)), true

	case watch.ClassSSH:
		if name == "sshd_config" || strings.Contains(e.Path, "/sshd_config.d/") {
			if e.Op == watch.OpAttrib {
				return Finding{}, false
			}
			return event("sshd-config", e.Path, "high", "SSH server configuration changed",
				fmt.Sprintf("%s was %s: %s. Check that root login, password authentication and the accepted keys are still as intended.", e.Path, verb(e.Op), describeFile(e))), true
		}
		if name == "rc" && path.Dir(e.Path) != "/etc/ssh" {
			// sshd runs ~/.ssh/rc at each login of that account, before its shell.
			return systemChange(e, "hook", "medium", "Start-up script changed",
				"Code here runs at each SSH login of the account, before its shell.")
		}
		if name != "authorized_keys" && name != "authorized_keys2" {
			return Finding{}, false
		}
		switch e.Op {
		case watch.OpDelete:
			if first, ok := appeared(e, history); ok {
				return event("ssh-transient", e.Path+occurrence(first), "critical", "SSH keys added and removed within minutes",
					fmt.Sprintf("%s was written at %s and removed at %s: a key used for one login and then taken away, so that no snapshot shows it. Check the SSH logins in that interval. %s",
						e.Path, first.At.Format("15:04:05"), e.At.Format("15:04:05"), describeFile(first))), true
			}
			return event("removed", e.Path, "medium", "SSH keys file removed", e.Path+" was removed."), true
		case watch.OpCreate, watch.OpWrite:
			if back, ok := restored(e, history); ok {
				return event("ssh-transient", e.Path+occurrence(back), "critical", "SSH keys changed and put back within minutes",
					fmt.Sprintf("%s was changed at %s and restored to its earlier content at %s: a key added for one login and then taken away, so that no snapshot shows it. Check the SSH logins in that interval.",
						e.Path, back.At.Format("15:04:05"), e.At.Format("15:04:05"))), true
			}
			return event("ssh-keys", e.Path, "high", "SSH keys changed",
				fmt.Sprintf("%s was %s: %s. A new key is a way in that survives a password change.", e.Path, verb(e.Op), describeFile(e))), true
		}
		return Finding{}, false

	case watch.ClassPrivilege:
		return systemChange(e, "privilege-config", "critical", "Privilege configuration changed",
			"Who may become root is decided here: a line added is root for whoever it names.")

	case watch.ClassHook:
		if name == "ld.so.preload" {
			return systemChange(e, "preload", "critical", "Library preloading changed",
				"Every program started from now on loads what this file names: it is how user-space rootkits hide.")
		}
		if loaderConfig(e.Path) {
			if e.Op == watch.OpDelete {
				if first, ok := appeared(e, history); ok {
					return event("loader-transient", e.Path+occurrence(first), "critical", "Library search path changed and put back within minutes",
						fmt.Sprintf("%s was written at %s and removed at %s. ldconfig may have baked the directories it named into /etc/ld.so.cache in between, and they stay searched after the file is gone: compare ldconfig -p with the remaining configuration, and look for libraries in directories it does not name. %s",
							e.Path, first.At.Format("15:04:05"), e.At.Format("15:04:05"), describeFile(first))), true
				}
			}
			return systemChange(e, "loader-config", "high", "Library search path changed",
				"The loader looks for libraries in the directories named here: a library placed in one is loaded instead of the system's.")
		}
		if path.Dir(e.Path) == "/etc/ld.so.conf.d" {
			return Finding{}, false
		}
		// As the snapshot rule judges it: a snapshot finding this event already reported is
		// dropped, so a lower severity here would lower root's start-up files.
		severity := "high"
		if homeOwner(e.Path) != "root" {
			severity = "medium"
		}
		return systemChange(e, "hook", severity, "Start-up script changed",
			"Code here runs at each login, boot or authentication, as whoever triggers it.")

	case watch.ClassService:
		if !loadable(e.Path) || netplanOutput(e.Path) {
			return Finding{}, false
		}
		return systemChange(e, "service", "high", "Service added or changed",
			"A unit or a generator here starts with the system, as root unless it says otherwise.")

	case watch.ClassSchedule:
		return systemChange(e, "schedule", "high", "Scheduled task added or changed",
			"A scheduled task runs again and again, long after whoever planted it has gone.")

	case watch.ClassAccounts:
		return systemChange(e, "accounts", "medium", "Account database changed",
			"The next snapshot shows which accounts, groups or passwords changed.")
	}
	return Finding{}, false
}

// loaderConfig reports whether ldconfig reads the file: ld.so.conf and the .conf files it
// includes from ld.so.conf.d. The temporary names package managers write first are not read.
func loaderConfig(p string) bool {
	return p == "/etc/ld.so.conf" || path.Dir(p) == "/etc/ld.so.conf.d" && path.Ext(p) == ".conf"
}

// systemChange judges a change to a system configuration file: additions and changes at the
// rule's severity, removals at medium, changes of attributes only when they make a file
// writable by others.
// unitTypes are the suffixes systemd loads units from.
var unitTypes = []string{".service", ".socket", ".timer", ".path", ".mount", ".automount", ".target", ".slice", ".scope", ".swap", ".device"}

// loadable reports whether systemd would act on a file at this path: a unit, a drop-in in a
// unit's .d directory, or anything in a generator directory. Temporary names of atomic writes
// (netplan-ovs-cleanup.service.MA2FX3) are never loaded; the rename that ends the write is.
func loadable(p string) bool {
	dir := path.Dir(p)
	switch {
	case strings.HasSuffix(dir, "-generators"):
		return true
	case strings.HasSuffix(dir, ".d"):
		return path.Ext(p) == ".conf"
	}
	return slices.Contains(unitTypes, path.Ext(p))
}

// netplanOutput reports a unit netplan's generator writes to /run at every systemd reload: the
// generator is what persists, and a new one is reported by the snapshots.
func netplanOutput(p string) bool {
	if !strings.HasPrefix(p, "/run/systemd/system/") {
		return false
	}
	base := path.Base(p)
	return strings.HasPrefix(base, "netplan-") || strings.HasPrefix(base, "10-netplan") && path.Ext(base) == ".conf"
}

func systemChange(e watch.Event, rule, severity, title, why string) (Finding, bool) {
	switch e.Op {
	case watch.OpDelete:
		// Removing a service or a scheduled task stops something from running: cleanup, which
		// tools and package scripts do all the time, not a foothold.
		if e.Class == watch.ClassService || e.Class == watch.ClassSchedule {
			// Except an activation link: removing one disables a unit, a security service or
			// a firewall among them.
			if dir := path.Dir(e.Path); strings.HasSuffix(dir, ".wants") || strings.HasSuffix(dir, ".requires") {
				return event("removed", e.Path, "low", "Service disabled", fmt.Sprintf("%s was removed: the unit no longer starts with what it was attached to. %s", e.Path, why)), true
			}
			return Finding{}, false
		}
		return event("removed", e.Path, "medium", "Configuration file removed",
			fmt.Sprintf("%s was removed. %s", e.Path, why)), true
	case watch.OpAttrib:
		if !writableByOthers(e.Mode) {
			return Finding{}, false
		}
		return event(rule, e.Path, severity, title, fmt.Sprintf("%s was made writable by other users: %s. %s", e.Path, describeFile(e), why)), true
	}
	return event(rule, e.Path, severity, title, fmt.Sprintf("%s was %s: %s. %s", e.Path, verb(e.Op), describeFile(e), why)), true
}

func judgeExec(e watch.Event) (Finding, bool) {
	who := "uid ?"
	if e.User != nil {
		who = "uid " + strconv.Itoa(*e.User)
	}
	proc := fmt.Sprintf("%s (started by %s, as %s, in %s): %s", orUnknown(e.Exe), orUnknown(e.Parent), who, orUnknown(e.Cwd), orUnknown(e.Cmdline))
	// An interpreter's alerts are about the script it runs: /bin/sh is not what was planted.
	subject := e.Exe
	if e.Script != "" {
		subject = e.Script
	}
	switch e.Reason {
	case watch.ReasonWebShell:
		// One alert per command, not per shell: where the web server's user also runs scheduled
		// jobs, each job can be accepted on its own, and any other command is new. A command fed
		// a here-document is keyed on its head, the sensor's CommandSum covering the same part,
		// so a tool that pipes a new script at every run is one alert, accepted once.
		head, _ := watch.CommandHead(orUnknown(e.Cmdline))
		key := fmt.Sprintf("%s (started by %s, as %s, in %s): %s", orUnknown(e.Exe), orUnknown(e.Parent), who, orUnknown(e.Cwd), head)
		return event("webshell", e.Exe+"#"+processKey(key+e.CommandSum), "critical", "The web server's user started "+path.Base(orUnknown(e.Exe)),
			"Process "+proc+". A web server has no reason to run a shell or a network tool; a webshell in use does. Check the web server's logs for the request that started it."), true
	case watch.ReasonPrivilege:
		return event("privilege-gain", e.Exe, "critical", "A process became root through "+path.Base(orUnknown(e.Exe)),
			"Process "+proc+" gained root through a set-user-ID program outside the system's binary directories: a backdoor left to get root back."), true
	case watch.ReasonDeleted:
		return event("deleted-exe", subject, "high", "A program runs from a deleted file",
			"Process "+proc+". Its executable was removed after it started, which leaves nothing on disk to examine: malware does this, updates rarely do."), true
	case watch.ReasonUnusualPath:
		return event("unusual-exec", subject, "high", "A program started from "+path.Dir(orUnknown(subject)),
			"Process "+proc+". Programs are not installed there: what runs from there was put there."), true
	}
	return Finding{}, false
}

// judgeContainer raises a container with power over the host as soon as it starts, under the
// fingerprint the snapshot rule gives it, so the next snapshot adds nothing. Its removal raises
// nothing of its own: the start already did, and the event stays on the host's timeline as the
// only trace of a container gone before any snapshot.
func judgeContainer(e watch.Event) (Finding, bool) {
	c := e.Container
	if e.Op != watch.OpCreate || c == nil || len(c.Powers) == 0 {
		return Finding{}, false
	}
	if c.Replaces != "" && c.ImageID != "" {
		return containerImageFinding(*c), true
	}
	return containerFinding(*c, "Container with access to the host started"), true
}

// processKey identifies a process by what its alert says of it, the PID aside: executable,
// parent, user, directory and command line.
func processKey(proc string) string {
	sum := sha256.Sum256([]byte(proc))
	return hex.EncodeToString(sum[:6])
}

func event(rule, subject, severity, title, detail string) Finding {
	return Finding{Kind: EventKind, Fingerprint: EventKind + ":" + rule + ":" + subject, Severity: severity, Title: title, Detail: detail}
}

// appeared finds the creation, within TransientWindow, of the file a removal is about.
func appeared(e watch.Event, history History) (watch.Event, bool) {
	if history == nil {
		return watch.Event{}, false
	}
	for _, h := range history(e.Path, e.At.Add(-TransientWindow)) {
		// A file made executable counts as appearing: in the scratch directories that is the
		// first event reported of a dropper, written first and then given the execute bit.
		if (h.Op == watch.OpCreate || h.Op == watch.OpWrite || (h.Op == watch.OpAttrib && watch.Executable(h.Mode))) && !h.At.After(e.At) {
			return h, true
		}
	}
	return watch.Event{}, false
}

// restored finds, within TransientWindow, an earlier change of the file away from the content
// it has again now: a key added and then removed by rewriting the file.
func restored(e watch.Event, history History) (watch.Event, bool) {
	if history == nil || e.SHA256 == "" {
		return watch.Event{}, false
	}
	var before []watch.Event
	for _, h := range history(e.Path, e.At.Add(-TransientWindow)) {
		if h.At.After(e.At) || (h.At.Equal(e.At) && h.Op == e.Op && h.SHA256 == e.SHA256) {
			break
		}
		// A change within the window away from the content the file has again now: the content
		// before it may be months old, known to the sensor rather than to any event here.
		if h.PrevSHA256 == e.SHA256 && h.SHA256 != "" && h.SHA256 != e.SHA256 {
			return h, true
		}
		if h.SHA256 != "" {
			before = append(before, h)
		}
	}
	for i, h := range before {
		if h.SHA256 != e.SHA256 {
			continue
		}
		for _, later := range before[i+1:] {
			if later.SHA256 != e.SHA256 {
				return later, true
			}
		}
	}
	return watch.Event{}, false
}

// occurrence tells transient alerts apart: each appearance is an alert of its own, so one
// acknowledged does not silence the next on the same path, even with the same content.
// owner names the account of an event's file, for grouping alerts.
func owner(e watch.Event) string {
	if e.UID == nil {
		return "uid?"
	}
	return "uid" + strconv.FormatUint(uint64(*e.UID), 10)
}

// scratchRoot is the scratch directory a path lies in.
func scratchRoot(p string) string {
	for _, d := range []string{"/dev/shm", "/var/tmp", "/tmp", "/run/lock"} {
		if p == d || strings.HasPrefix(p, d+"/") {
			return d
		}
	}
	return path.Dir(p)
}

func occurrence(e watch.Event) string {
	// The time keeps the same content reused days later apart from an alert already taken in
	// charge; the hash keeps two contents of the same second apart.
	out := " at:" + strconv.FormatInt(e.At.Unix(), 10)
	if e.SHA256 != "" {
		out += " sha256:" + e.SHA256[:min(16, len(e.SHA256))]
	}
	return out
}

func describeFile(e watch.Event) string {
	var parts []string
	if e.SHA256 != "" {
		parts = append(parts, fmt.Sprintf("%d bytes, SHA-256 %s", e.Size, e.SHA256))
	} else if e.Size > 0 {
		parts = append(parts, fmt.Sprintf("%d bytes", e.Size))
	}
	if e.UID != nil {
		parts = append(parts, "owner uid "+strconv.FormatUint(uint64(*e.UID), 10))
	}
	if e.Mode != "" {
		parts = append(parts, "mode "+e.Mode)
	}
	if len(parts) == 0 {
		return "gone before it could be read"
	}
	return strings.Join(parts, ", ")
}

func verb(op string) string {
	switch op {
	case watch.OpCreate:
		return "created"
	case watch.OpDelete:
		return "removed"
	case watch.OpAttrib:
		return "changed in its attributes"
	}
	return "written"
}

// writableByOthers reports whether a mode as Go prints it ("-rw-rw-rw-") lets group or others
// write.
func writableByOthers(mode string) bool {
	return len(mode) >= 10 && (mode[len(mode)-5] == 'w' || mode[len(mode)-2] == 'w')
}

func lower(severity string) string {
	switch severity {
	case "critical":
		return "high"
	case "high":
		return "medium"
	}
	return "low"
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
