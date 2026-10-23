package analyze

import (
	"fmt"
	"path"
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
		f, ok := judgeEvent(e, history)
		if !ok {
			continue
		}
		// The content is part of the fingerprint: an alert acknowledged for one content must
		// not absorb a different change to the same file later.
		if e.SHA256 != "" && !strings.Contains(f.Fingerprint, "-transient:") {
			f.Fingerprint += " sha256:" + e.SHA256[:min(16, len(e.SHA256))]
		}
		if packageManager && lowered(e) {
			f.Severity = lower(f.Severity)
			f.Detail += " A package manager was running at the time: an installation or an upgrade may have made this change."
		}
		out = append(out, f)
	}
	return out
}

// lowered says whether a package manager running explains an event well enough to lower its
// severity: packages install services, scheduled tasks and start-up scripts all the time. Never
// who may become root, the accounts, SSH keys or library preloading, which a package rarely
// touches and an intruder always does; nor process starts or uploads, which no package explains.
func lowered(e watch.Event) bool {
	switch e.Class {
	case watch.ClassService, watch.ClassSchedule:
		return true
	case watch.ClassHook:
		return path.Base(e.Path) != "ld.so.preload"
	}
	return false
}

func judgeEvent(e watch.Event, history History) (Finding, bool) {
	if e.Class == watch.ClassExec {
		return judgeExec(e)
	}
	if e.Dir || e.Path == "" {
		return Finding{}, false
	}
	name := path.Base(e.Path)
	switch e.Class {
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
				return event("upload-transient", e.Path, "critical", what+" appeared in an upload directory and was removed",
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

	case watch.ClassSSH:
		if name == "sshd_config" || strings.Contains(e.Path, "/sshd_config.d/") {
			if e.Op == watch.OpAttrib {
				return Finding{}, false
			}
			return event("sshd-config", e.Path, "high", "SSH server configuration changed",
				fmt.Sprintf("%s was %s: %s. Check that root login, password authentication and the accepted keys are still as intended.", e.Path, verb(e.Op), describeFile(e))), true
		}
		if name != "authorized_keys" && name != "authorized_keys2" {
			return Finding{}, false
		}
		switch e.Op {
		case watch.OpDelete:
			if first, ok := appeared(e, history); ok {
				return event("ssh-transient", e.Path, "critical", "SSH keys added and removed within minutes",
					fmt.Sprintf("%s was written at %s and removed at %s: a key used for one login and then taken away, so that no snapshot shows it. Check the SSH logins in that interval. %s",
						e.Path, first.At.Format("15:04:05"), e.At.Format("15:04:05"), describeFile(first))), true
			}
			return event("removed", e.Path, "medium", "SSH keys file removed", e.Path+" was removed."), true
		case watch.OpCreate, watch.OpWrite:
			if back, ok := restored(e, history); ok {
				return event("ssh-transient", e.Path, "critical", "SSH keys changed and put back within minutes",
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
		severity := "high"
		if !strings.HasPrefix(e.Path, "/etc/") {
			severity = "medium"
		}
		return systemChange(e, "hook", severity, "Start-up script changed",
			"Code here runs at each login, boot or authentication, as whoever triggers it.")

	case watch.ClassService:
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

// systemChange judges a change to a system configuration file: additions and changes at the
// rule's severity, removals at medium, changes of attributes only when they make a file
// writable by others.
func systemChange(e watch.Event, rule, severity, title, why string) (Finding, bool) {
	switch e.Op {
	case watch.OpDelete:
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
		return event("webshell", e.Exe, "critical", "The web server's user started "+path.Base(orUnknown(e.Exe)),
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

func event(rule, subject, severity, title, detail string) Finding {
	return Finding{Kind: EventKind, Fingerprint: EventKind + ":" + rule + ":" + subject, Severity: severity, Title: title, Detail: detail}
}

// appeared finds the creation, within TransientWindow, of the file a removal is about.
func appeared(e watch.Event, history History) (watch.Event, bool) {
	if history == nil {
		return watch.Event{}, false
	}
	for _, h := range history(e.Path, e.At.Add(-TransientWindow)) {
		if (h.Op == watch.OpCreate || h.Op == watch.OpWrite) && !h.At.After(e.At) {
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
