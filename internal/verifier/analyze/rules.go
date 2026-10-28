package analyze

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/apps"
	"github.com/cpibia/tripwatch/internal/collector/system"
	"github.com/cpibia/tripwatch/internal/collector/web"
	"github.com/cpibia/tripwatch/internal/watch"
	"github.com/cpibia/tripwatch/internal/weblog"
)

// Finding is an alert to raise. State findings describe a condition that holds in the current
// snapshot and are resolved when it no longer does; the others describe a change and stay
// until someone acknowledges them.
type Finding struct {
	Kind        string
	Fingerprint string
	Severity    string
	Title       string
	Detail      string
	State       bool
	// Owner is the account the finding is about when it is not root's by nature: a key or a
	// crontab of another user, a setuid file owned by one. Empty means the kind decides.
	Owner string
	// Diff is the complete diff of a policy change, kept with the alert: Detail shows only its
	// first lines.
	Diff []string
}

// owned reports whether only root can have caused a finding: its owner says so, never its kind
// alone.
func (f Finding) owned() bool { return f.Owner == "root" }

// rootKinds are the alert kinds whose findings are root's unless the rule names another owner. Processes, listening ports and the sensor's own alerts are left out: the web server's
// user can start a program from /tmp, bind a port, or flood the findings of a snapshot.
var rootKinds = map[string]bool{
	"accounts": true, "accounts-change": true, "ssh": true, "ssh-change": true,
	"persistence": true, "persistence-change": true, "privileged": true, "privileged-change": true,
	"packages": true, "packages-change": true, "kernel": true, "kernel-change": true,
}

func kindOwner(kind string) string {
	if rootKinds[kind] {
		return "root"
	}
	return ""
}

// unitOwner is who could write a systemd unit, decided by where it lies: a unit in a home is
// that home's, whatever User= it names; a unit in the system directories is root's.
func unitOwner(u unitT) string { return homeOwner(u.Path) }

// noLogin are the shells that refuse a session. Only these exact paths count: a copy of bash
// named nologin elsewhere is a shell.
var noLogin = map[string]bool{"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true, "/usr/bin/false": true, "": true}

// grantWords mark policy lines that name who gets a power or take it away: sudo user specs,
// polkit results and identities, doas permit and deny. Plain substrings: a regexp over a large
// policy took seconds.
var grantWords = []string{"NOPASSWD", "ALL", "authenticate", "Runas_", "SETENV", "Result.", `"yes"`, "permit", "deny", "nopass", "keepenv", "unix-user", "unix-group", "isInGroup", "subject.user", "Identity", "ResultAny"}

func grantLine(l string) bool {
	if strings.HasPrefix(l, "%") || len(l) > 1 && l[0] == '#' && l[1] >= '0' && l[1] <= '9' {
		return true
	}
	return slices.ContainsFunc(grantWords, func(w string) bool { return strings.Contains(l, w) })
}

// maxDiffLines bounds a policy diff in an alert.
const maxDiffLines = 40

// ruleDiff lists the lines added (+) and removed (-) between two versions of a policy file.
// Lines that grant or deny come first and the cut is always stated: a grant hidden behind
// harmless lines would otherwise never reach the alert.
func ruleDiff(old, cur []string) string {
	lines := diffLines(old, cur)
	if lines == nil {
		return "Content changed with no line added or removed (order or whitespace)."
	}
	if len(lines) > maxDiffLines {
		hiddenAdded, hiddenRemoved := 0, 0
		for _, l := range lines[maxDiffLines:] {
			if l[0] == '+' {
				hiddenAdded++
			} else {
				hiddenRemoved++
			}
		}
		lines = append(lines[:maxDiffLines], fmt.Sprintf("(%d more lines added and %d removed not shown: the full diff is on the alert's page)", hiddenAdded, hiddenRemoved))
	}
	return strings.Join(lines, "\n")
}

// diffLines lists every added and removed line, grants first; nil when no line differs.
func diffLines(old, cur []string) []string {
	was, now := set{}, set{}
	was.add(old...)
	now.add(cur...)
	var added, removed []string
	for _, l := range cur {
		if !was.has(l) {
			added = append(added, "+ "+l)
		}
	}
	for _, l := range old {
		if !now.has(l) {
			removed = append(removed, "- "+l)
		}
	}
	if len(added)+len(removed) == 0 {
		return nil
	}
	// Grants added, grants removed, then the other removed lines (a removed condition can widen
	// a rule) and the other added ones.
	var lines []string
	for _, pass := range []struct {
		grants bool
		group  []string
	}{{true, added}, {true, removed}, {false, removed}, {false, added}} {
		for _, l := range pass.group {
			if grantLine(l[2:]) == pass.grants {
				lines = append(lines, l)
			}
		}
	}
	return lines
}

// fileAccess describes who can change a file: owner, group, mode and the FUSE mount it is on.
func fileAccess(f collector.File) string {
	id := func(v *uint32) string {
		if v == nil {
			return "?"
		}
		return strconv.FormatUint(uint64(*v), 10)
	}
	out := "owner " + id(f.UID) + ", group " + id(f.GID) + ", mode " + f.Mode
	if f.ACL != "" {
		out += ", ACL " + f.ACL
	}
	if f.Mount != "" {
		out += ", on " + f.Mount
	}
	return out
}

// policyTrust says which non-root accounts and groups may write a policy file. polkit's rule
// directories belong to its daemon account on a standard install; a group counts only when an
// account other than root is in it.
type policyTrust struct {
	known   bool
	daemons map[int]bool
	// daemonGIDs are polkit's groups with no member but the daemon itself.
	daemonGIDs map[int]bool
	members    map[int]int
}

var policyDaemons = map[string]bool{"polkitd": true, "polkit": true}

func policyAccounts(a *system.AccountsResult) policyTrust {
	t := policyTrust{daemons: map[int]bool{}, daemonGIDs: map[int]bool{}, members: map[int]int{}}
	if a == nil {
		return t
	}
	t.known = true
	byUID := map[int]int{}
	uidOf := map[string]int{}
	for _, acc := range a.Accounts {
		byUID[acc.UID]++
		uidOf[acc.Name] = acc.UID
	}
	// The daemon's UID is trusted only when it is a system account of its own with no shell:
	// another account given that UID, or the name on a login account, is not the daemon.
	daemon := map[string]bool{}
	for _, acc := range a.Accounts {
		if policyDaemons[acc.Name] && acc.UID > 0 && acc.UID < 1000 && byUID[acc.UID] == 1 && !realShell(acc.Shell) {
			t.daemons[acc.UID] = true
			daemon[acc.Name] = true
		}
	}
	others := map[int]map[string]bool{}
	for name, gids := range memberships(a) {
		if uid, ok := uidOf[name]; ok && uid == 0 {
			continue
		}
		for gid := range gids {
			if others[gid] == nil {
				others[gid] = map[string]bool{}
			}
			others[gid][name] = true
		}
	}
	for gid, names := range others {
		t.members[gid] = len(names)
	}
	for _, g := range a.Groups {
		if !policyDaemons[g.Name] || g.GID <= 0 {
			continue
		}
		trusted := true
		for name := range others[g.GID] {
			trusted = trusted && daemon[name]
		}
		if trusted {
			t.daemonGIDs[g.GID] = true
		}
	}
	return t
}

// groupWriters reports whether a group lets an account other than root (and polkit's daemon on
// polkit's files) write. Without the accounts every group other than root's counts.
func (t policyTrust) groupWriters(gid int, polkit bool) bool {
	switch {
	case gid == 0:
		return false
	case !t.known:
		return true
	case polkit && t.daemonGIDs[gid]:
		return false
	}
	return t.members[gid] > 0
}

// foreignWritable reports whether an account other than root can change a file: it owns it,
// it is on a user's FUSE mount, an ACL lets a named user or group write, or the mode lets
// others, or a group with an account other than root in it, write.
func foreignWritable(f collector.File, t policyTrust) bool {
	polkit := strings.Contains(f.Path+"/", "/polkit-1/")
	if f.Mount != "" || f.ACLWrite {
		return true
	}
	if f.UID != nil && *f.UID != 0 && (!polkit || !t.daemons[int(*f.UID)]) {
		return true
	}
	if len(f.Mode) < 9 {
		return false
	}
	perm := f.Mode[len(f.Mode)-9:]
	return perm[7] == 'w' || perm[4] == 'w' && f.GID != nil && t.groupWriters(int(*f.GID), polkit)
}

// policyWriteDetail explains in plain words who other than root can change a privilege policy
// file or directory, why that gives root, and the usual fix; the raw data closes the text.
func policyWriteDetail(f collector.File, t policyTrust, accounts *system.AccountsResult) string {
	var who []string
	if f.Mount != "" {
		who = append(who, "it is on a filesystem mounted by a user ("+f.Mount+"), who decides its owner and mode")
	}
	if f.ACLWrite {
		who = append(who, "an ACL grants write access to a user or group ("+f.ACL+")")
	}
	if f.UID != nil && *f.UID != 0 {
		who = append(who, "it belongs to the account "+accountName(accounts, int(*f.UID)))
	}
	if len(f.Mode) >= 9 {
		perm := f.Mode[len(f.Mode)-9:]
		if perm[7] == 'w' {
			who = append(who, "every user on the server can write to it (mode "+octal(perm)+")")
		}
		if perm[4] == 'w' && f.GID != nil && t.groupWriters(int(*f.GID), strings.Contains(f.Path+"/", "/polkit-1/")) {
			g := int(*f.GID)
			text := "the group " + groupLabel(accounts, g) + " can write to it"
			if m := groupMembers(accounts, g); len(m) > 0 {
				text += ", and its members are " + strings.Join(m, ", ")
			}
			who = append(who, text)
		}
	}
	if len(who) == 0 {
		who = append(who, "an account other than root can change it")
	}
	var b strings.Builder
	b.WriteString(strings.ToUpper(who[0][:1]) + who[0][1:])
	for _, w := range who[1:] {
		b.WriteString("; " + w)
	}
	b.WriteString(".\n\n")
	name := policyName(f.Path)
	if strings.HasPrefix(f.Mode, "d") {
		fmt.Fprintf(&b, "This directory holds the %s rules, which decide who can become root. Whoever can write to it can rename or replace what is inside (for example %s), give themselves root, and put everything back before the next check.\n\n", name, policyExample(name))
		fmt.Fprintf(&b, "The usual fix: chown root:root %s && chmod 755 %s", f.Path, f.Path)
	} else {
		fmt.Fprintf(&b, "This file holds %s rules, which decide who can become root. Whoever can change it can give themselves root and remove the line before the next check.\n\n", name)
		mode := "644"
		if name == "sudo" {
			mode = "440"
		}
		fmt.Fprintf(&b, "The usual fix: chown root:root %s && chmod %s %s", f.Path, mode, f.Path)
	}
	b.WriteString("\n\nCollected data: " + fileAccess(f) + ".")
	return b.String()
}

func policyExample(name string) string {
	switch name {
	case "polkit":
		return "the rules in /etc/polkit-1"
	case "doas":
		return "/etc/doas.conf"
	}
	return "/etc/sudoers"
}

// octal turns the nine permission letters into the numeric mode chmod takes.
func octal(perm string) string {
	n := 0
	for i, c := range perm {
		if c != '-' && c != 'S' && c != 'T' {
			n |= 1 << (8 - i)
		}
	}
	return fmt.Sprintf("%03o", n)
}

func accountName(r *system.AccountsResult, uid int) string {
	if r != nil {
		for _, a := range r.Accounts {
			if a.UID == uid {
				return fmt.Sprintf("%s (UID %d)", a.Name, uid)
			}
		}
	}
	return fmt.Sprintf("with UID %d", uid)
}

func groupLabel(r *system.AccountsResult, gid int) string {
	if r == nil {
		return fmt.Sprintf("with GID %d", gid)
	}
	return fmt.Sprintf("%s (GID %d)", groupNames(r.Groups, gid), gid)
}

// groupMembers lists the accounts in a group: those with it as primary group and those listed.
func groupMembers(r *system.AccountsResult, gid int) []string {
	if r == nil {
		return nil
	}
	var out []string
	for _, a := range r.Accounts {
		if a.GID == gid {
			out = append(out, a.Name)
		}
	}
	for _, g := range r.Groups {
		if g.GID == gid {
			for _, m := range append(g.Members, g.ShadowMembers...) {
				if !slices.Contains(out, m) {
					out = append(out, m)
				}
			}
		}
	}
	return out
}

// groupWritable reports whether a file's group may write it.
func groupWritable(f collector.File) bool {
	return len(f.Mode) >= 9 && f.Mode[len(f.Mode)-5] == 'w' && f.GID != nil && *f.GID != 0
}

// policyName names the privilege policy a file belongs to.
func policyName(p string) string {
	switch {
	case strings.Contains(p, "polkit"):
		return "polkit"
	case strings.Contains(p, "doas"):
		return "doas"
	}
	return "sudo"
}

// realShell reports whether a login shell lets the account open a session.
func realShell(sh string) bool { return !noLogin[sh] }

// memberships lists, per account, the GIDs it belongs to: its primary group and every group
// that names it in etc/group or etc/gshadow.
func memberships(r *system.AccountsResult) map[string]map[int]bool {
	out := map[string]map[int]bool{}
	if r == nil {
		return out
	}
	add := func(name string, gid int) {
		if out[name] == nil {
			out[name] = map[int]bool{}
		}
		out[name][gid] = true
	}
	for _, a := range r.Accounts {
		add(a.Name, a.GID)
	}
	for _, g := range r.Groups {
		for _, m := range append(append([]string{}, g.Members...), g.ShadowMembers...) {
			add(m, g.GID)
		}
	}
	return out
}

// sudoGroup matches the groups a sudoers rule grants to: %name or %#gid.
var sudoGroup = regexp.MustCompile(`%:?(#?)([A-Za-z0-9_.-]+)`)

// policyGroup matches the groups polkit and doas grant to.
var policyGroup = regexp.MustCompile(`unix-group:([A-Za-z0-9_.-]+)|isInGroup\(\s*["']([A-Za-z0-9_.-]+)["']|^permit\b.*?\s:([A-Za-z0-9_.-]+)`)

// sudoEscape matches the \xHH escapes sudoers allows in names.
var sudoEscape = regexp.MustCompile(`\\x([0-9A-Fa-f]{2})`)

// privilegedGIDs are the GIDs that grant root's power or close to it: 0, those of the groups in
// privilegedGroups under any of the names sharing the GID, and those sudoers rules grant to, in
// either snapshot.
func privilegedGIDs(snaps ...State) map[int]bool {
	out := map[int]bool{0: true}
	for _, st := range snaps {
		var groups []system.Group
		if st.Accounts != nil {
			groups = st.Accounts.Groups
		}
		// Built once per snapshot: a policy naming many groups must not scan them all for each.
		byName := map[string][]int{}
		for _, g := range groups {
			byName[strings.ToLower(g.Name)] = append(byName[strings.ToLower(g.Name)], g.GID)
			if privilegedGroups[g.Name] {
				out[g.GID] = true
			}
		}
		if st.Sudoers == nil {
			continue
		}
		// A group that may write a policy file or a directory above one can grant itself
		// anything: joining it is joining root.
		for _, d := range st.Sudoers.Dirs {
			if groupWritable(d) {
				out[int(*d.GID)] = true
			}
		}
		for _, f := range st.Sudoers.Files {
			if groupWritable(f.File) {
				out[int(*f.GID)] = true
			}
			for _, rule := range f.Rules {
				rule = sudoEscape.ReplaceAllStringFunc(rule, func(e string) string {
					n, _ := strconv.ParseUint(e[2:], 16, 8)
					return string(rune(n))
				})
				matches := sudoGroup.FindAllStringSubmatch(rule, -1)
				// polkit (unix-group:name, isInGroup("name")) and doas (permit ... :name).
				for _, m := range policyGroup.FindAllStringSubmatch(rule, -1) {
					matches = append(matches, []string{m[0], "", m[1] + m[2] + m[3]})
				}
				for _, m := range matches {
					if m[1] == "#" {
						if gid, err := strconv.Atoi(m[2]); err == nil {
							out[gid] = true
						}
						continue
					}
					// Compared without case: wrongly calling a group privileged costs an alert,
					// missing one costs a silent promotion.
					for _, gid := range byName[strings.ToLower(m[2])] {
						out[gid] = true
					}
				}
			}
		}
	}
	return out
}

func groupNames(groups []system.Group, gid int) string {
	var names []string
	for _, g := range groups {
		if g.GID == gid {
			names = append(names, g.Name)
		}
	}
	if len(names) == 0 {
		return fmt.Sprint(gid)
	}
	return strings.Join(names, ", ")
}

func groupPasswordSet(r *system.AccountsResult, name string) bool {
	if r == nil {
		return false
	}
	for _, g := range r.Groups {
		if g.Name == name {
			return g.Password == system.PasswordSet
		}
	}
	return false
}

// cronOwner is the user a crontab belongs to: a user's spool file is theirs, the system's
// tables are root's.
func cronOwner(p string) string {
	if dir, user := path.Split(p); strings.Contains(dir, "/spool/cron") {
		return user
	}
	return "root"
}

func uidOwner(uid *uint32) string {
	if uid == nil || *uid == 0 {
		return "root"
	}
	return fmt.Sprintf("uid %d", *uid)
}

// privilegedGroups grant root's power or close to it to whoever runs as them.
var privilegedGroups = map[string]bool{
	"root": true, "wheel": true, "disk": true, "shadow": true, "sudo": true, "adm": true, "admin": true,
	"docker": true, "lxd": true, "kmem": true, "tty": true, "sys": true, "systemd-journal": true,
}

// privilegedOwner is root for a file that grants root's or a privileged group's rights when
// run: setuid and owned by root, or setgid with GID 0 or a group named in privilegedGroups (by
// its name in the host's group database) that the file's owner is not in. A setgid file of a
// group its owner already belongs to, as primary group or as member, grants nothing the owner
// did not have: a web user in adm or docker can make those itself.
func privilegedOwner(f fileT, cur State, privGIDs map[int]bool, groups map[string]map[int]bool) string {
	// On a filesystem a user mounted, owner and mode are what that user chose: neither is root's.
	if f.Mount != "" {
		return "mount " + f.Mount
	}
	if strings.Contains(strings.SplitN(f.Mode, "-", 2)[0], "g") && f.GID != nil && privGIDs[int(*f.GID)] {
		gid := int(*f.GID)
		// A member if any account with the file's UID is, through any group line with that
		// GID: a process runs with the groups of the name it started as, and a web user's
		// alias may come later in the passwd file.
		member := false
		if cur.Accounts != nil && f.UID != nil {
			for _, a := range cur.Accounts.Accounts {
				if a.UID == int(*f.UID) && groups[a.Name][gid] {
					member = true
				}
			}
		}
		if !member || *f.UID == 0 {
			return "root"
		}
	}
	return uidOwner(f.UID)
}

// homeOwner names who wrote a configuration read from the given path: root for system
// directories, otherwise the home it lies in.
func homeOwner(p string) string {
	// Cleaned first: a sensor that lies could send /etc/../var/www to borrow /etc's owner.
	p = path.Clean("/" + p)
	if strings.HasPrefix(p, "/root/") {
		return "root"
	}
	if rest, ok := strings.CutPrefix(p, "/run/user/"); ok {
		uid, _, _ := strings.Cut(rest, "/")
		return "uid " + uid
	}
	// Under /run only systemd's own directories are root's: other services and users write
	// there too.
	for _, dir := range []string{"/etc/", "/run/systemd/", "/run/environment.d/", "/usr/", "/lib/"} {
		if strings.HasPrefix(p, dir) {
			return "root"
		}
	}
	if i := strings.Index(p, "/.config/"); i >= 0 {
		return "home " + p[:i]
	}
	if i := strings.Index(p, "/.local/"); i >= 0 {
		return "home " + p[:i]
	}
	return "path " + path.Dir(p)
}

// StateKinds are the kinds whose alerts resolve themselves when the condition disappears.
var StateKinds = []string{"accounts", "ssh", "persistence", "processes", "packages", "privileged", "web", "apps", "sensor", "kernel", "network"}

// Places a legitimate program does not run from.
var suspiciousDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/var/www/", "/home/", "/run/lock/"}

func suspiciousPath(p string) bool {
	if slices.ContainsFunc(suspiciousDirs, func(d string) bool { return strings.HasPrefix(p, d) }) {
		return true
	}
	return slices.ContainsFunc(strings.Split(p, "/"), func(seg string) bool { return strings.HasPrefix(seg, ".") && seg != "." && seg != ".." })
}

// set is a membership test built once per snapshot: comparing two snapshots stays linear in
// their size, however many entries a hostile sensor sends.
type set map[string]struct{}

func (s set) add(keys ...string) {
	for _, k := range keys {
		s[k] = struct{}{}
	}
}

func (s set) has(k string) bool {
	_, ok := s[k]
	return ok
}

func setOf[T any](items []T, key func(T) string) set {
	s := make(set, len(items))
	for _, it := range items {
		s[key(it)] = struct{}{}
	}
	return s
}

// Evaluate returns the findings of cur, comparing with prev when there is one. On the first
// snapshot of a host only state rules apply: everything would otherwise be "new".
func Evaluate(prev *State, cur State) []Finding {
	var out []Finding
	add := func(f Finding) { out = append(out, f) }
	state := func(kind, fp, sev, title, detail string) {
		add(Finding{Kind: kind, Fingerprint: kind + ":" + fp, Severity: sev, Title: title, Detail: detail, State: true, Owner: kindOwner(kind)})
	}
	change := func(kind, fp, sev, title, detail string) {
		if prev != nil {
			add(Finding{Kind: kind, Fingerprint: kind + ":" + fp, Severity: sev, Title: title, Detail: detail, Owner: kindOwner(kind)})
		}
	}
	stateBy := func(owner, kind, fp, sev, title, detail string) {
		add(Finding{Kind: kind, Fingerprint: kind + ":" + fp, Severity: sev, Title: title, Detail: detail, State: true, Owner: owner})
	}
	changeBy := func(owner, kind, fp, sev, title, detail string) {
		if prev != nil {
			add(Finding{Kind: kind, Fingerprint: kind + ":" + fp, Severity: sev, Title: title, Detail: detail, Owner: owner})
		}
	}

	for name, msg := range cur.Errors {
		state("sensor", "error:"+name, "medium", "Collector "+name+" did not complete", msg)
	}
	for _, w := range cur.Warnings {
		state("sensor", "warning:"+w, "medium", "Sensor guarantees reduced", w)
	}

	if a := cur.Accounts; a != nil {
		for _, acc := range a.Accounts {
			if acc.UID == 0 && acc.Name != "root" {
				state("accounts", "uid0:"+acc.Name, "critical", "Second root account: "+acc.Name,
					fmt.Sprintf("The account %s has UID 0, that is root's privileges. Home %s, shell %s.", acc.Name, acc.Home, acc.Shell))
			}
			if acc.Password == "empty" && realShell(acc.Shell) {
				state("accounts", "empty-password:"+acc.Name, "high", "Account without a password: "+acc.Name, "Shell "+acc.Shell+": anyone can log in with this name.")
			}
		}
		if prev != nil && prev.Accounts != nil {
			before := map[string]accountT{}
			for _, p := range prev.Accounts.Accounts {
				before[p.Name] = p
			}
			for _, acc := range a.Accounts {
				old, ok := before[acc.Name]
				if !ok {
					change("accounts-change", "new:"+acc.Name, "high", "New account: "+acc.Name,
						fmt.Sprintf("UID %d, home %s, shell %s.", acc.UID, acc.Home, acc.Shell))
					continue
				}
				// An existing account given root's power by a standard command: these files are
				// root's, so the change is.
				if old.UID != acc.UID {
					change("accounts-change", "uid:"+acc.Name+"|"+fmt.Sprint(acc.UID), "high", "UID changed for "+acc.Name,
						fmt.Sprintf("From %d to %d.", old.UID, acc.UID))
				}
				if old.Password != system.PasswordSet && acc.Password == system.PasswordSet {
					change("accounts-change", "password:"+acc.Name+"|"+acc.Password, "high", "Password set for "+acc.Name,
						"The account had no usable password before; now it has one.")
				}
				if !realShell(old.Shell) && realShell(acc.Shell) {
					change("accounts-change", "shell:"+acc.Name+"|"+acc.Shell, "high", "Shell enabled for "+acc.Name,
						fmt.Sprintf("From %s to %s: the account can now open a session.", old.Shell, acc.Shell))
				}
			}
			// Every group an account newly belongs to, by GID: a new name for a known GID, a
			// GID changed under the same name, a primary group, etc/gshadow, all count.
			privGIDs := privilegedGIDs(*prev, cur)
			was := memberships(prev.Accounts)
			for name, gids := range memberships(a) {
				_, existed := before[name]
				for gid := range gids {
					if was[name][gid] {
						continue
					}
					priv := privGIDs[gid]
					if !existed && !priv {
						continue
					}
					sev := "high"
					if priv {
						sev = "critical"
					}
					change("accounts-change", "member:"+name+"|"+fmt.Sprint(gid), sev, fmt.Sprintf("%s now in group %s", name, groupNames(a.Groups, gid)),
						fmt.Sprintf("%s now belongs to group GID %d (%s)%s.", name, gid, groupNames(a.Groups, gid), map[bool]string{true: ", which gives access equal or close to root's", false: ""}[priv]))
				}
			}
			admins := map[string]set{}
			for _, g := range prev.Accounts.Groups {
				admins[g.Name] = setOf(g.Admins, func(m string) string { return m })
			}
			for _, g := range a.Groups {
				// A group administrator can add anyone, itself included, at any time: a dormant
				// grant of the group.
				for _, m := range g.Admins {
					if !admins[g.Name].has(m) {
						sev := "high"
						if privGIDs[g.GID] {
							sev = "critical"
						}
						change("accounts-change", "group-admin:"+g.Name+"|"+m, sev, "Administrator of group "+g.Name+": "+m,
							fmt.Sprintf("%s can now add anyone, themselves included, to group %s (GID %d) with gpasswd.", m, g.Name, g.GID))
					}
				}
				if g.Password == system.PasswordSet && privGIDs[g.GID] && !groupPasswordSet(prev.Accounts, g.Name) {
					change("accounts-change", "group-password:"+g.Name, "critical", "Password set for group "+g.Name,
						"With the group password anyone on the server can join it with newgrp or sg.")
				}
			}
		}
	}

	// Accounts by name, to tell whose keys and crontabs are root's: any account with UID 0 is.
	uids := map[string]int{}
	if cur.Accounts != nil {
		for _, acc := range cur.Accounts.Accounts {
			uids[acc.Name] = acc.UID
		}
	}

	if s := cur.SSH; s != nil {
		if s.Settings["permitrootlogin"] == "yes" {
			state("ssh", "root-login", "medium", "SSH: root login with a password allowed", "PermitRootLogin yes.")
		}
		if s.Settings["passwordauthentication"] == "yes" {
			state("ssh", "password-auth", "medium", "SSH: password authentication enabled", "PasswordAuthentication yes: keys are much harder to guess.")
		}
		var known set
		if prev != nil && prev.SSH != nil {
			known = setOf(prev.SSH.Keys, func(p keyT) string { return p.User + "\x00" + p.Fingerprint })
		}
		for _, k := range s.Keys {
			if known != nil && !known.has(k.User+"\x00"+k.Fingerprint) {
				// The user names the group: one user's keys do not crowd out root's. Any account
				// with UID 0 is root.
				owner := k.User
				if uid, ok := uids[k.User]; ok && uid == 0 {
					owner = "root"
				}
				changeBy(owner, "ssh-change", "key:"+k.User+"|"+k.Fingerprint, "high", "New SSH key for "+k.User,
					fmt.Sprintf("%s %s (%s) in %s.", k.Type, k.Fingerprint, k.Comment, k.File))
			}
		}
	}

	if s := cur.Sudoers; s != nil {
		// polkit reads any rule it finds, whoever owns it: a policy file or directory another
		// account can write is a grant that can be written and removed between two snapshots.
		files := make([]collector.File, 0, len(s.Files)+len(s.Dirs))
		for _, f := range s.Files {
			files = append(files, f.File)
		}
		trusted := policyAccounts(cur.Accounts)
		for _, f := range append(files, s.Dirs...) {
			if !foreignWritable(f, trusted) {
				continue
			}
			// The access is in the fingerprint: a known exception taken in charge does not
			// absorb a later handover of the same file to another account.
			title := "Privilege policy writable by others: " + f.Path
			if strings.HasPrefix(f.Mode, "d") {
				title = "Privilege policy directory writable by others: " + f.Path
			}
			stateBy("root", "persistence", "policy-writable:"+f.Path+"|"+fileAccess(f), "critical", title, policyWriteDetail(f, trusted, cur.Accounts))
		}
	}

	if s := cur.Sudoers; s != nil && prev != nil && prev.Sudoers != nil {
		// Compared file by file and by content: polkit rules are code, so a rule made of lines
		// found elsewhere, or a condition removed, changes the file but adds no new line.
		before := map[string]sudoersT{}
		for _, p := range prev.Sudoers.Files {
			before[p.Path] = p
		}
		dirs := map[string]collector.File{}
		for _, d := range prev.Sudoers.Dirs {
			dirs[d.Path] = d
		}
		for _, d := range s.Dirs {
			if old, ok := dirs[d.Path]; ok && fileAccess(old) != fileAccess(d) {
				change("persistence-change", "policy-access:"+d.Path+"|"+fileAccess(d), "high", "Permissions changed on policy directory "+d.Path,
					"From "+fileAccess(old)+" to "+fileAccess(d)+".")
			}
		}
		for _, f := range s.Files {
			old, ok := before[f.Path]
			delete(before, f.Path)
			if ok && fileAccess(old.File) != fileAccess(f.File) {
				change("persistence-change", "policy-access:"+f.Path+"|"+fileAccess(f.File), "high", "Permissions changed on policy "+f.Path,
					"From "+fileAccess(old.File)+" to "+fileAccess(f.File)+". Whoever can write the file can give themselves root.")
			}
			if ok && old.SHA256 == f.SHA256 && slices.Equal(old.Rules, f.Rules) {
				continue
			}
			title := "New " + policyName(f.Path) + " policy: " + f.Path
			if ok {
				title = policyName(f.Path) + " policy changed: " + f.Path
			}
			add(Finding{Kind: "persistence-change", Fingerprint: "persistence-change:policy:" + f.Path + "|" + f.SHA256, Severity: "high",
				Title: title, Detail: ruleDiff(old.Rules, f.Rules), Owner: "root", Diff: append([]string{}, diffLines(old.Rules, f.Rules)...)})
		}
		for path, old := range before {
			add(Finding{Kind: "persistence-change", Fingerprint: "persistence-change:policy-removed:" + path + "|" + old.SHA256, Severity: "high",
				Title:  policyName(path) + " policy removed: " + path,
				Detail: "Removing a file can remove a prohibition.\n" + ruleDiff(old.Rules, nil), Owner: "root", Diff: append([]string{}, diffLines(old.Rules, nil)...)})
		}
	}

	if s := cur.Scheduled; s != nil {
		var known set
		if prev != nil && prev.Scheduled != nil {
			known = set{}
			for _, p := range prev.Scheduled.Tables {
				for _, e := range p.Entries {
					known.add(p.Path + "\x00" + e)
				}
			}
		}
		for _, t := range s.Tables {
			if t.Immutable {
				state("persistence", "immutable-cron:"+t.Path, "critical", "Crontab protected with chattr +i", t.Path+": the file cannot be changed or deleted, not even by root, until the attribute is removed.")
			}
			for _, e := range t.Entries {
				// A line is new to its table: the same line in another user's crontab earlier
				// does not make it known in root's.
				if known != nil && !known.has(t.Path+"\x00"+e) {
					owner := cronOwner(t.Path)
					if uid, ok := uids[owner]; ok && uid == 0 {
						owner = "root"
					}
					changeBy(owner, "persistence-change", "cron:"+t.Path+"|"+e, "high", "New cron line", e+"\nin "+t.Path)
				}
			}
		}
	}

	if s := cur.Services; s != nil {
		var knownUnits, knownGenerators set
		if prev != nil && prev.Services != nil {
			knownUnits = setOf(prev.Services.Units, func(p unitT) string { return p.Path })
			knownGenerators = setOf(prev.Services.Generators, func(p fileT) string { return p.Path })
		}
		for _, env := range s.Environment {
			if strings.Contains(env, "LD_PRELOAD") {
				// environment.d lines name their file; the others come from the managers' own
				// configuration in /etc.
				owner := "root"
				if i := strings.LastIndex(env, " ("); i >= 0 && strings.HasSuffix(env, ")") {
					owner = homeOwner(env[i+2 : len(env)-1])
				}
				stateBy(owner, "persistence", "default-env:"+owner+"|"+env, "critical", "Library injected into every service", env)
			}
		}
		for _, u := range s.Units {
			if u.Immutable {
				state("persistence", "immutable-unit:"+u.Path, "critical", "systemd unit protected with chattr +i", u.Path)
			}
			for _, x := range u.Exec {
				if _, cmd, ok := strings.Cut(x, "="); ok && len(strings.Fields(cmd)) > 0 && suspiciousPath(strings.TrimLeft(strings.Fields(cmd)[0], "-@+!:")) {
					stateBy(unitOwner(u), "persistence", "unit-exec:"+unitOwner(u)+"|"+u.Path+":"+x, "high", "Service running from an unusual directory", x+"\nin "+u.Path)
				}
			}
			if knownUnits != nil && !knownUnits.has(u.Path) {
				changeBy(unitOwner(u), "persistence-change", "unit:"+unitOwner(u)+"|"+u.Path, "medium", "New systemd service", u.Path+"\n"+strings.Join(u.Exec, "\n"))
			}
		}
		for _, g := range s.Generators {
			if knownGenerators != nil && !knownGenerators.has(g.Path) {
				change("persistence-change", "generator:"+g.Path, "high", "New systemd generator", g.Path+": root runs it at every boot.")
			}
		}
	}

	if h := cur.Hooks; h != nil {
		for _, lib := range h.Preload {
			state("persistence", "preload:"+lib, "critical", "Library loaded into every process", lib+" is in /etc/ld.so.preload: the technique of userspace rootkits.")
		}
	}

	out = append(out, kernelFindings(prev, cur)...)

	if rt := cur.Realtime; rt != nil && len(rt.Unwatched) > 0 {
		// Anyone able to create directories can push the watches past their bounds: places left
		// without one are an alert, one per class, high for the system, the homes and the uploads,
		// medium for the scratch directories, which anyone fills.
		byClass := map[string][]string{}
		for _, u := range rt.Unwatched {
			class, msg, ok := strings.Cut(u, ": ")
			if !ok {
				class, msg = "other", u
			}
			if len(byClass[class]) < 10 {
				byClass[class] = append(byClass[class], msg)
			}
		}
		for class, list := range byClass {
			sev := "high"
			if class == watch.ClassScratch {
				sev = "medium"
			}
			state("sensor", "unwatched:"+class, sev, "Places left without real-time watch: "+class,
				"The real-time watcher could not cover every watched place of this class; changes there show only in snapshots. Someone filling a watched tree with directories causes this.\n"+strings.Join(list, "\n"))
		}
	}

	if p := cur.Processes; p != nil {
		byPID := map[int]system.Process{}
		for _, pr := range p.Processes {
			byPID[pr.PID] = pr
		}
		for _, pr := range p.Processes {
			for _, m := range pr.Mapped {
				// Sensors before 0.1.11 also reported shared anonymous regions (OPcache, JITs);
				// later ones tell them from a file of that name by their device.
				if m == "/dev/zero (deleted)" && sensorBefore(cur, 0, 1, 11) {
					continue
				}
				// Applications ship native modules under homes and web roots (Node addons, Python
				// wheels): code from there is high, from the scratch directories critical.
				sev, why := "high", "a file in a home or a web root, where applications may keep native modules but injected libraries also land"
				switch {
				case strings.HasPrefix(m, "/memfd:"):
					sev, why = "critical", "a memory-only file (memfd), code that never touched the disk"
				case slices.ContainsFunc(scratchDirs, func(d string) bool { return strings.HasPrefix(m, d) }):
					sev, why = "critical", "a file in a scratch directory, where no code is installed"
				case !suspiciousPath(m) && !strings.HasPrefix(m, "/root/") && !strings.HasPrefix(m, "/srv/"):
					why = "a file deleted from disk after it was loaded"
				}
				state("processes", "mapped:"+pr.Comm+":"+m, sev, "Code injected into "+pr.Comm,
					fmt.Sprintf("PID %d (%s, %s) runs code from %s: %s. Libraries are loaded from the system's directories; this is how injected code and in-memory implants look.", pr.PID, pr.Comm, pr.Exe, m, why))
			}
			if pr.Tracer != 0 {
				if f, ok := tracedFinding(pr, byPID[pr.Tracer]); ok {
					add(f)
				}
			}
			switch {
			case strings.HasPrefix(pr.Exe, "/memfd:"):
				state("processes", "memfd:"+pr.Comm+":"+pr.ExeSHA256, "critical", "Fileless process: "+pr.Comm,
					fmt.Sprintf("PID %d (%s) runs %s, a file that exists only in memory: malware runs this way to leave nothing on disk. UID %d, hash %s, command line %s.", pr.PID, pr.Comm, pr.Exe, pr.UID, pr.ExeSHA256, pr.Cmdline))
			case pr.ExeDeleted && pr.ExeReplaced && pr.ExePackaged && packagedPath(pr.Exe, cur.Packages):
				state("processes", "restart-pending:"+pr.Exe+":"+pr.ExeSHA256, "low", "Process still runs a replaced binary: "+pr.Comm,
					fmt.Sprintf("PID %d (%s) still runs the old %s: the file was replaced, most likely by a package upgrade, and the process has not been restarted since. Restart it to run the new version.", pr.PID, pr.Comm, pr.Exe))
			case pr.ExeDeleted:
				state("processes", "deleted:"+pr.Exe+":"+pr.ExeSHA256, "high", "Process from a deleted executable", fmt.Sprintf("PID %d (%s) runs %s, removed from disk. Hash %s.", pr.PID, pr.Comm, pr.Exe, pr.ExeSHA256))
			case suspiciousPath(pr.Exe):
				state("processes", "exe:"+pr.Exe+":"+pr.ExeSHA256, "high", "Process from an unusual directory", fmt.Sprintf("PID %d (%s) runs %s as UID %d.", pr.PID, pr.Comm, pr.Exe, pr.UID))
			}
			if kernelThreadDisguise(pr) {
				state("processes", "kthread-name:"+pr.Exe+":"+pr.ExeSHA256, "critical", "Process disguised as a kernel thread: "+pr.Comm,
					fmt.Sprintf("PID %d calls itself %q (command line %q) but runs %s as UID %d, parent %d. Kernel threads have no executable and the sensor counts them apart; a program that takes their name is hiding in ps, as miners and backdoors do.", pr.PID, pr.Comm, pr.Cmdline, pr.Exe, pr.UID, pr.PPID))
			}
			if pr.Preload != "" {
				state("processes", "ld-preload:"+pr.Comm+":"+pr.Preload, "high", "Process with LD_PRELOAD", fmt.Sprintf("PID %d (%s) loads %s.", pr.PID, pr.Comm, pr.Preload))
			}
		}
	}

	if s := cur.Sockets; s != nil {
		for _, so := range s.Sockets {
			if f, ok := rawSocketFinding(so); ok {
				add(f)
			}
		}
	}

	if s := cur.Sockets; s != nil && prev != nil && prev.Sockets != nil {
		known := set{}
		for _, p := range prev.Sockets.Sockets {
			if p.State == "listen" {
				known.add(p.Proto + "\x00" + p.Local)
			}
		}
		for _, so := range s.Sockets {
			if so.State == "listen" && !known.has(so.Proto+"\x00"+so.Local) {
				change("network-change", "listen:"+so.Proto+":"+so.Local, "medium", "New listening port: "+so.Local, fmt.Sprintf("%s %s, process %s (PID %d).", so.Proto, so.Local, so.Process, so.PID))
			}
		}
	}

	if p := cur.Packages; p != nil {
		for _, m := range p.Modified {
			if !m.Config {
				state("packages", "modified:"+m.Path, "high", "System file modified: "+m.Path, "It no longer matches package "+m.Package+".")
			}
		}
		for _, h := range p.Hidden {
			state("packages", "hidden:"+h, "high", "Hidden entry in /usr: "+h, "No package installed this dot-named entry under /usr.")
		}
		if prev != nil && prev.Packages != nil {
			known := set{}
			known.add(prev.Packages.Unowned...)
			for _, u := range p.Unowned {
				if !known.has(u) {
					change("packages-change", "unowned:"+u, "medium", "New executable outside the packages: "+u, "")
				}
			}
			switch {
			case p.DatabaseSHA256 == prev.Packages.DatabaseSHA256:
			case len(p.States) > 0 && len(prev.Packages.States) > 0:
				// Package by package: checksums that changed while the version did not were
				// rewritten by hand, whatever else changed in the database at the same time.
				var rewritten []string
				for name, st := range p.States {
					if old, ok := prev.Packages.States[name]; ok && old.Version == st.Version && old.Checksums != st.Checksums {
						rewritten = append(rewritten, name)
					}
				}
				slices.Sort(rewritten)
				for i, name := range rewritten {
					if i == maxRewrittenPackages {
						break
					}
					change("packages-change", "rewritten:"+name+":"+p.States[name].Checksums, "high", "Package checksums changed without an upgrade: "+name,
						fmt.Sprintf("The checksums recorded for %s %s changed while its version did not: the way to make a replaced file of the package pass verification. %d packages in all are in this state.", name, p.States[name].Version, len(rewritten)))
				}
			case p.StatusSHA256 != "" && prev.Packages.StatusSHA256 != "":
				// The list of installed packages and versions tells an upgrade from checksums
				// rewritten by hand, where the manager keeps them apart (dpkg).
				if p.StatusSHA256 == prev.Packages.StatusSHA256 && p.StatusSHA256 != p.DatabaseSHA256 {
					change("packages-change", "database:"+p.DatabaseSHA256, "high", "Package checksums changed without installations",
						"The checksums or file lists of the package database changed while no package was installed, removed or upgraded: the way to make a replaced system file pass verification.")
				}
			case p.Packages == prev.Packages.Packages:
				change("packages-change", "database:"+p.DatabaseSHA256, "medium", "Package database changed without installations",
					"The number of packages is the same but the database differs: a normal update, or checksums rewritten to cover a replaced file.")
			}
		}
	}

	if p := cur.Privileged; p != nil {
		// Computed once per snapshot: per file they made a hostile snapshot quadratic.
		privGIDs, groupsOf := privilegedGIDs(cur), memberships(cur.Accounts)
		var known set
		if prev != nil && prev.Privileged != nil {
			known = setOf(prev.Privileged.Files, func(q fileT) string { return q.Path + "\x00" + q.SHA256 })
		}
		for _, f := range p.Files {
			switch {
			case f.Immutable || f.AppendOnly:
				state("privileged", "attr:"+f.Path, "high", "File protected with chattr: "+f.Path, "The immutable and append-only attributes are rare on servers and are used to make access persistent.")
			case suspiciousPath(f.Path) || !standardBinDir(f.Path):
				owner := privilegedOwner(f, cur, privGIDs, groupsOf)
				stateBy(owner, "privileged", "setid:"+owner+"|"+f.Path, "critical", "setuid/setgid binary in an unusual directory: "+f.Path, "Mode "+f.Mode+", owner "+owner+", hash "+f.SHA256+".")
			}
			if known != nil && !known.has(f.Path+"\x00"+f.SHA256) {
				owner := privilegedOwner(f, cur, privGIDs, groupsOf)
				changeBy(owner, "privileged-change", "new:"+owner+"|"+f.Path+":"+f.SHA256, "high", "New privileged file: "+f.Path, "Mode "+f.Mode+", owner "+owner+".")
			}
		}
	}

	if w := cur.Web; w != nil {
		prevApps := map[string]web.AppReport{}
		if prev != nil && prev.Web != nil {
			for _, pa := range prev.Web.Apps {
				prevApps[pa.Path] = pa
			}
		}
		for _, app := range w.Apps {
			for _, f := range app.Findings {
				sev, title := webFinding(f)
				if sev == "" {
					continue
				}
				detail := f.Path
				// Size and hash tell one file from another at the same path, for the operator
				// and for the evidence kept of each content.
				if f.SHA256 != "" {
					detail += fmt.Sprintf("\n%d bytes, SHA-256 %s", f.Size, f.SHA256)
				}
				if len(f.Signatures) > 0 {
					detail += "\nSignatures: " + strings.Join(f.Signatures, ", ")
				}
				if f.Reachable {
					detail += "\nReachable from the web according to the configuration."
				}
				state("web", f.Kind+":"+f.Path, sev, title, detail)
			}
			if pa, ok := prevApps[app.Path]; ok {
				for dir, sum := range app.DirHashes {
					if old, ok := pa.DirHashes[dir]; ok && old != sum {
						detail := "Without a deploy, someone changed the code of the application " + app.Path + "."
						if files := changedIn(app.Changes, dir); files != "" {
							detail += "\nChanged files:\n" + files
						}
						change("web-change", "code:"+dir+":"+sum, "medium", "Code changed in "+dir, detail)
					}
				}
				for _, f := range scriptChanges(app) {
					change("web-change", f.Fingerprint, f.Severity, f.Title, f.Detail)
				}
			}
		}
		for _, cfg := range w.Inventory.StaleConfig {
			state("web", "stale-config:"+cfg, "medium", "Web server configuration changed after it started", cfg)
		}
		// Files stuffed with code can spend the run's budget so a payload behind them is never
		// searched: the gap is an alert, and it names the files that caused it.
		if cs := w.CodeSearch; cs != nil && len(cs.Unsearched) > 0 {
			var b strings.Builder
			b.WriteString("The budget for searching data files for code ran out: these files were not searched through, and code in them may raise no alert.")
			for _, p := range cs.Unsearched {
				b.WriteString("\n  " + p)
			}
			if cs.UnsearchedMore > 0 {
				fmt.Fprintf(&b, "\n  and %d more", cs.UnsearchedMore)
			}
			if len(cs.Heaviest) > 0 {
				b.WriteString("\nThe files that spent the most of it:")
				for _, c := range cs.Heaviest {
					fmt.Fprintf(&b, "\n  %s: %d bytes of code, owner UID %d", c.Path, c.CodeBytes, c.UID)
				}
			}
			state("web", "code-search-incomplete", "high", "Data files not searched for code", b.String())
		}
	}

	if l := cur.Weblog; l != nil {
		for _, e := range l.Events {
			// A request that failed for a script missing from every root nginx could serve it
			// from ran no code: a probe, not an intrusion. A web shell answers as it likes, so
			// one that exists stays serious whatever its status.
			if e.OnDisk == "missing" && (e.Status < 200 || e.Status >= 300) {
				continue
			}
			if e.Severity != "critical" && e.Severity != "high" {
				continue
			}
			// Log events are new by construction (each run reads only new lines), so they count
			// from the first snapshot on.
			// The script the request reached names the alert's group: noise sent to other
			// scripts does not crowd out the one that matters.
			script := weblog.ScriptPath(path.Clean("/" + strings.SplitN(e.Evidence.Request, "?", 2)[0]))
			onDisk := ""
			if e.OnDisk == "present" {
				onDisk = " The script exists on the server."
			}
			add(Finding{Kind: "weblog", Fingerprint: "weblog:" + e.Rule + ":" + script + "|" + e.Evidence.Request + e.Log, Severity: e.Severity, Title: "Log: " + strings.ReplaceAll(e.Rule, "_", " "), Detail: fmt.Sprintf("%s %s, status %d, %d requests from %d addresses (first %s), log %s.%s\nRequest text, written by whoever sent it: %s",
				e.Method, path.Clean("/"+e.Evidence.Request), e.Status, e.Count, max(e.IPs, 1), e.IP, e.Log, onDisk, e.Evidence.Request)})
		}
		// A flood that pushed serious events out of the bounded list is itself an alert: it may
		// have been sent to hide one.
		if n := l.Stats.DroppedEvents["critical"] + l.Stats.DroppedEvents["high"]; n > 0 {
			var b strings.Builder
			fmt.Fprintf(&b, "%d critical or high events did not fit in the log list, filled by others. A wave of noisy requests can serve to hide the one that matters.", n)
			if len(l.Stats.DroppedSamples) > 0 {
				b.WriteString("\nSome of the dropped events (text written by whoever made the request):")
				for _, d := range l.Stats.DroppedSamples {
					fmt.Fprintf(&b, "\n  %s %s from %s: %s", d.Severity, strings.ReplaceAll(d.Rule, "_", " "), d.IP, d.Path)
				}
			}
			// Like the events, each run's drops are new: one alert per snapshot that had them.
			add(Finding{Kind: "weblog", Fingerprint: "weblog:dropped:" + strconv.FormatInt(cur.TakenAt.Unix(), 10), Severity: "high",
				Title: "Log: serious events dropped by saturation", Detail: b.String()})
		}
	}

	if a := cur.Apps; a != nil {
		for _, app := range a.Apps {
			for _, inj := range app.Injected {
				for _, d := range inj.Domains {
					state("apps", "script:"+app.Path+":"+inj.Where+":"+d, "high", "External script stored in the database: "+d,
						fmt.Sprintf("%s in %s (%s). Check that it is a wanted service: this is how skimmers are injected.", d, inj.Where, app.Path))
				}
			}
			for _, w := range app.Warnings {
				state("apps", "warning:"+app.Path+":"+w, "low", "Development setting in "+app.Path, w)
			}
			for _, o := range app.Objects {
				if len(o.Markers) == 0 {
					continue
				}
				sev, title := "critical", "Code in a stored "+objectLabel(o.Kind)+" of "+app.Path
				if o.Kind == apps.ObjectCustomer {
					sev, title = "high", "Template code in a customer's name in "+app.Path
				}
				state("apps", "markers:"+app.Path+":"+o.Kind+":"+o.ID+":"+o.Hash, sev, title,
					fmt.Sprintf("%s %s %s holds %s: rendered by the template engine, this runs code on the server.\nName, written by whoever created it: %s",
						objectLabel(o.Kind), o.ID, app.Path, strings.Join(o.Markers, ", "), o.Name))
			}
			if prev == nil || prev.Apps == nil {
				continue
			}
			for _, pa := range prev.Apps.Apps {
				if pa.Path != app.Path {
					continue
				}
				for _, ad := range app.Admins {
					i := slices.IndexFunc(pa.Admins, func(p adminT) bool { return p.ID == ad.ID })
					switch {
					case i < 0:
						change("apps-change", "admin:"+app.Path+":"+ad.ID, "critical", "New administrator in "+app.Path+": "+ad.Name,
							fmt.Sprintf("Email %s, created %s.", ad.Email, ad.Created))
					case pa.Admins[i].Name != ad.Name || pa.Admins[i].Email != ad.Email || pa.Admins[i].Active != ad.Active:
						old := pa.Admins[i]
						// A changed email is how an account is taken over through a password reset.
						change("apps-change", "admin-changed:"+app.Path+":"+ad.ID+":"+ad.Name+"|"+ad.Email+"|"+ad.Active, "high", "Administrator changed in "+app.Path+": "+ad.Name,
							fmt.Sprintf("Administrator %s: name %q, email %q, active %q; it was name %q, email %q, active %q.", ad.ID, ad.Name, ad.Email, ad.Active, old.Name, old.Email, old.Active))
					}
				}
				for _, f := range objectChanges(app.Path, pa, app) {
					change("apps-change", f.Fingerprint, f.Severity, f.Title, f.Detail)
				}
			}
		}
	}
	return out
}

// objectLabels name the kinds of database objects in alerts.
var objectLabels = map[string]string{
	apps.ObjectTrigger: "trigger", apps.ObjectProcedure: "stored procedure", apps.ObjectFunction: "stored function",
	apps.ObjectEvent: "scheduled event", apps.ObjectIntegration: "integration", apps.ObjectAdminToken: "admin API token",
	apps.ObjectLayoutUpdate: "layout update", apps.ObjectEmailTemplate: "email template", apps.ObjectCustomer: "customer",
}

func objectLabel(kind string) string { return cmp.Or(objectLabels[kind], kind) }

// sensitiveTables are the tables a trigger on which reads or rewrites payments, orders,
// credentials or settings.
var sensitiveTables = []string{"sales_", "quote", "payment", "order", "core_config_data", "admin_user", "users", "options", "customer"}

// objectChanges compares the database objects of an application with the previous snapshot:
// a new or changed one is how code is planted in the database. Only the kinds read in both
// snapshots are compared, so a kind read for the first time does not look new all at once.
func objectChanges(appPath string, prev, cur apps.Profile) []Finding {
	old := map[string]objectT{}
	for _, o := range prev.Objects {
		old[o.Kind+"\x00"+o.ID] = o
	}
	var out []Finding
	for _, o := range cur.Objects {
		if o.Kind == apps.ObjectCustomer || !slices.Contains(prev.ObjectsRead, o.Kind) {
			continue
		}
		before, seen := old[o.Kind+"\x00"+o.ID]
		if seen && before.Hash == o.Hash {
			continue
		}
		sev := "high"
		switch {
		case o.Kind == apps.ObjectEmailTemplate:
			sev = "medium"
		case o.Kind == apps.ObjectTrigger && slices.ContainsFunc(sensitiveTables, func(t string) bool { return strings.Contains(strings.ToLower(o.Target), t) }):
			sev = "critical"
		}
		title, what := "New "+objectLabel(o.Kind)+" in the database of "+appPath, "was added"
		if seen {
			title, what = "Database "+objectLabel(o.Kind)+" changed in "+appPath, "changed"
		}
		detail := fmt.Sprintf("The %s %s %s since the previous snapshot.", objectLabel(o.Kind), o.ID, what)
		if o.Target != "" {
			detail += " On: " + o.Target + "."
		}
		if o.Definer != "" {
			detail += " Definer: " + o.Definer + "."
		}
		if o.Created != "" {
			detail += " Created or changed: " + o.Created + "."
		}
		detail += "\nName, written by whoever created it: " + o.Name
		out = append(out, Finding{Fingerprint: "object:" + appPath + ":" + o.Kind + ":" + o.ID + ":" + o.Hash, Severity: sev, Title: title, Detail: detail})
	}
	return out
}

// maxNamedScripts is how many changed scripts of one application get an alert each; past it, a
// deploy is the likely cause and one alert lists them.
const maxNamedScripts = 20

// scriptChanges raises the scripts added or changed in an application since the previous
// snapshot, by name: a new script in the web root or a changed core file is how a backdoor lands,
// and the directory's hash alone does not say which file it is.
func scriptChanges(app web.AppReport) []Finding {
	var scripts []web.FileChange
	for _, c := range app.Changes {
		if c.Change != web.ChangeRemoved && web.IsScript(c.Path) {
			scripts = append(scripts, c)
		}
	}
	if len(scripts) == 0 {
		return nil
	}
	if len(scripts) > maxNamedScripts {
		var list []string
		for _, c := range scripts[:maxNamedScripts] {
			list = append(list, c.Change+" "+c.Path)
		}
		sum := sha256.Sum256([]byte(strings.Join(list, "\n")))
		return []Finding{{Fingerprint: "scripts:" + app.Path + ":" + hex.EncodeToString(sum[:8]), Severity: "high",
			Title:  fmt.Sprintf("%d scripts added or changed in %s", len(scripts), app.Path),
			Detail: fmt.Sprintf("%d code files changed in all since the previous snapshot, a deploy if one was made. The first scripts:\n%s", app.ChangeCount, strings.Join(list, "\n"))}}
	}
	out := make([]Finding, 0, len(scripts))
	for _, c := range scripts {
		title := "Script changed: " + c.Path
		if c.Change == web.ChangeAdded {
			title = "Script added: " + c.Path
		}
		detail := fmt.Sprintf("%s was %s in %s since the previous snapshot, without a deploy if none was made.", c.Path, c.Change, app.Path)
		if c.SHA256 != "" {
			detail += "\nSHA-256 " + c.SHA256
		}
		out = append(out, Finding{Fingerprint: "file:" + c.Path + ":" + c.SHA256, Severity: "high", Title: title, Detail: detail})
	}
	return out
}

// changedIn lists the changes under a directory, at most maxNamedScripts of them.
func changedIn(changes []web.FileChange, dir string) string {
	var list []string
	for _, c := range changes {
		if strings.HasPrefix(c.Path, dir+"/") {
			if len(list) == maxNamedScripts {
				list = append(list, "...")
				break
			}
			list = append(list, c.Change+" "+c.Path)
		}
	}
	return strings.Join(list, "\n")
}

// webFinding maps a web finding kind to a severity and a title.
func webFinding(f web.Finding) (string, string) {
	switch f.Kind {
	// A script where uploads go is critical when its content carries a webshell signature. Some
	// applications keep generated templates there, so one with none is high: still to look at,
	// and an accepted one that changes is raised again, with its signatures if any. The detail
	// stays as it was, so acceptances given before keep holding.
	case web.KindScriptInUploads:
		if len(f.Signatures) > 0 {
			return "critical", "Script in upload directories"
		}
		return "high", "Script in upload directories"
	case web.KindSignature, web.KindCodeInUploads, web.KindPolyglotImage, web.KindCodeInData:
		return "critical", map[string]string{
			web.KindSignature:     "Webshell signature",
			web.KindCodeInUploads: "Code inside an uploaded file",
			web.KindPolyglotImage: "Image with hidden code",
			web.KindCodeInData:    "Code inside a data file",
		}[f.Kind]
	case web.KindHiddenScript, web.KindSuspiciousSymlink, web.KindAppInData:
		return "high", map[string]string{
			web.KindHiddenScript:      "Hidden script",
			web.KindSuspiciousSymlink: "Suspicious link",
			web.KindAppInData:         "Application inside an upload directory",
		}[f.Kind]
	case web.KindOverrideInData:
		if slices.Contains(f.Signatures, "handler_directive") {
			return "critical", "Configuration that makes uploads executable"
		}
		return "", ""
	case web.KindHiddenInData:
		return "medium", "Hidden file in data directories"
	case web.KindSkimmer:
		return "critical", "Payment skimmer in changed code"
	case web.KindActiveSVG:
		if slices.Contains(f.Signatures, "obfuscation") {
			return "critical", "SVG with hidden script in upload directories"
		}
		return "high", "SVG that runs script in upload directories"
	}
	return "", ""
}

// kernelThreadNames are the names of kernel threads a disguised process takes; only those with a
// shape no user-space program has, so the watchdog daemon or md tools stay out.
var kernelThreadNames = regexp.MustCompile(`^(?:\[[\w./:+-]{1,64}\]|(?:kworker|ksoftirqd|migration|cpuhp|irq|jbd2|rcuop|rcuos|idle_inject|kcompactd|scsi_eh)/.*|kswapd\d+|kthreadd|kworker|raid\d+wq|kdevtmpfs|khugepaged|oom_reaper)$`)

// kernelThreadDisguise reports a process of user space named like a kernel thread. Kernel
// threads are told apart by the collector from the flag the kernel sets on them and never
// listed; one listed with an executable and a parent other than kthreadd is a program.
func kernelThreadDisguise(pr system.Process) bool {
	if pr.Exe == "" || pr.PPID == 2 {
		return false
	}
	// Only a bare name in brackets, as ps shows kernel threads: titles such as celery's
	// "[celeryd: worker@host:MainProcess]" have spaces in them.
	cmd := strings.TrimSpace(pr.Cmdline)
	return kernelThreadNames.MatchString(pr.Comm) || (strings.HasPrefix(cmd, "[") && kernelThreadNames.MatchString(cmd))
}

// scratchDirs are writable by everyone and hold no installed code.
var scratchDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/run/lock/"}

// debuggers attach to processes with ptrace for a living.
var debuggers = []string{"gdb", "strace", "ltrace", "lldb", "lldb-server", "perf", "valgrind", "rr", "dlv", "criu", "py-spy", "rbspy", "gdbserver", "systemd-coredump"}

// secretHolders are the processes whose memory holds passwords and keys as they are typed or
// used: what a tracer attached to them is after.
var secretHolders = []string{"sshd", "sshd-session", "su", "sudo", "login", "passwd", "ssh-agent", "gpg-agent", "ssh", "polkitd", "gnome-keyring-d"}

// tracedFinding judges a process another one is attached to with ptrace.
func tracedFinding(pr, tracer system.Process) (Finding, bool) {
	exe := strings.TrimSuffix(tracer.Exe, " (deleted)")
	known := tracer.PID != 0 && standardBinDir(exe) && slices.Contains(debuggers, path.Base(exe)) && !tracer.ExeDeleted
	secret := slices.Contains(secretHolders, pr.Comm)
	if known && !secret {
		return Finding{}, false
	}
	sev := "high"
	if secret || tracer.PID == 0 || suspiciousPath(exe) || tracer.ExeDeleted {
		sev = "critical"
	}
	by := fmt.Sprintf("PID %d", pr.Tracer)
	if tracer.PID != 0 {
		by = fmt.Sprintf("PID %d (%s, %s)", tracer.PID, tracer.Comm, tracer.Exe)
	}
	return Finding{Kind: "processes", State: true, Severity: sev, Fingerprint: "processes:traced:" + pr.Comm + ":" + exe,
		Title:  "Process under ptrace: " + pr.Comm,
		Detail: fmt.Sprintf("PID %d (%s, %s) is traced by %s, which can read and change its memory: debuggers do this, and so do tools that steal passwords from sshd or su and inject code into running processes.", pr.PID, pr.Comm, pr.Exe, by)}, true
}

// packetTools are the programs that legitimately read raw traffic: DHCP clients and servers,
// network managers, capture and intrusion detection tools, ping.
var packetTools = []string{
	"dhclient", "dhcpcd", "udhcpc", "dhcpd", "kea-dhcp4", "dnsmasq", "NetworkManager", "systemd-networkd", "wpa_supplicant",
	"tcpdump", "tshark", "dumpcap", "wireshark", "lldpd", "keepalived", "arping", "ping", "ping6", "suricata", "snort", "zeek",
	"iftop", "nethogs", "vnstatd", "pmacctd", "fprobe", "ladvd", "ntopng", "nmap", "traceroute", "mtr-packet",
}

// rawSocketFinding judges a packet or raw socket: it receives traffic before any port does, so a
// backdoor that opens no port waits on one for its trigger packet. Known tools in the system's
// directories are fine; a program elsewhere, deleted, or not found holding one is not.
func rawSocketFinding(so system.Socket) (Finding, bool) {
	if so.Proto != "packet" && !strings.HasPrefix(so.Proto, "raw") {
		return Finding{}, false
	}
	exe, deleted := strings.CutSuffix(so.Exe, " (deleted)")
	what := "Raw socket"
	if so.Proto == "packet" {
		what = "Packet socket"
	}
	where := fmt.Sprintf("%s %s (%s), process %s (PID %d, %s)", so.Proto, so.Local, so.State, orNone(so.Process), so.PID, orNone(so.Exe))
	f := Finding{Kind: "network", State: true}
	switch {
	case so.PID == 0:
		f.Severity, f.Title = "medium", what+" with no process"
		f.Fingerprint = "network:raw-orphan:" + so.Proto + ":" + so.Local
		f.Detail = where + ". No process in /proc holds it: a kernel component, or a process hidden from the listing."
	case deleted || suspiciousPath(exe):
		f.Severity, f.Title = "critical", what+" held by "+path.Base(exe)
		f.Fingerprint = "network:raw:" + exe + ":" + so.Proto
		f.Detail = where + ". A program from an unusual place or deleted from disk reads raw traffic: the way backdoors that open no port wait for their trigger packet."
	case standardBinDir(exe) && slices.Contains(packetTools, path.Base(exe)):
		return Finding{}, false
	default:
		f.Severity, f.Title = "high", what+" held by "+path.Base(orNone(exe))
		f.Fingerprint = "network:raw:" + exe + ":" + so.Proto
		f.Detail = where + ". It reads traffic before any port does; capture and network tools do this, and so do backdoors that open no port. Check that this program is expected."
	}
	return f, true
}

// maxRewrittenPackages bounds the alerts raised for packages whose checksums changed.
const maxRewrittenPackages = 20

// sensorBefore reports whether the snapshot comes from a sensor older than the given release;
// one that does not say is old.
func sensorBefore(st State, release ...int) bool {
	sys := st.Environment.System
	if sys == nil {
		return true
	}
	v := strings.TrimPrefix(sys.SensorVersion, "v")
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	var parts []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return false
		}
		parts = append(parts, n)
	}
	return slices.Compare(parts, release) < 0
}

// packageDirs are where only packages install: /opt, /usr/local and /snap are left out, since
// software there is installed by hand.
var packageDirs = []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/", "/lib/"}

// packagedPath reports whether a path lies where packages install and the packages collector
// did not find it unowned or modified there. That a package names the path is the sensor's to
// say (ExePackaged): the packages collector does not list owned files.
func packagedPath(p string, pkgs *system.PackagesResult) bool {
	if pkgs == nil || !slices.ContainsFunc(packageDirs, func(d string) bool { return strings.HasPrefix(p, d) }) {
		return false
	}
	if slices.Contains(pkgs.Unowned, p) || slices.ContainsFunc(pkgs.Modified, func(m system.ModifiedFile) bool { return m.Path == p }) {
		return false
	}
	return true
}

func standardBinDir(p string) bool {
	return slices.ContainsFunc([]string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/", "/lib/", "/usr/local/bin/", "/usr/local/sbin/", "/snap/", "/opt/"},
		func(d string) bool { return strings.HasPrefix(p, d) })
}
