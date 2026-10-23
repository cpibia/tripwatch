package analyze

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/system"
	"github.com/cpibia/tripwatch/internal/collector/web"
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
}

// owned reports whether only root can have caused a finding: its owner says so, never its kind
// alone.
func (f Finding) owned() bool { return f.Owner == "root" }

// rootKinds are the alert kinds whose findings are root's unless the rule names another owner. Processes, listening ports and the sensor's own alerts are left out: the web server's
// user can start a program from /tmp, bind a port, or flood the findings of a snapshot.
var rootKinds = map[string]bool{
	"accounts": true, "accounts-change": true, "ssh": true, "ssh-change": true,
	"persistence": true, "persistence-change": true, "privileged": true, "privileged-change": true,
	"packages": true, "packages-change": true,
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
		return "Contenuto cambiato senza righe nuove o tolte (ordine o spazi)."
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
		lines = append(lines[:maxDiffLines], fmt.Sprintf("(altre %d righe aggiunte e %d tolte non mostrate: il confronto completo è nella pagina dell'allarme)", hiddenAdded, hiddenRemoved))
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
	out := "proprietario " + id(f.UID) + ", gruppo " + id(f.GID) + ", modo " + f.Mode
	if f.ACL != "" {
		out += ", ACL " + f.ACL
	}
	if f.Mount != "" {
		out += ", su " + f.Mount
	}
	return out
}

// policyIDs are the system accounts and groups a policy daemon runs as. polkit's rule
// directories belong to polkitd and are mode 0700 on a standard install.
type policyIDs struct{ uids, gids map[int]bool }

var policyDaemons = map[string]bool{"polkitd": true, "polkit": true}

func policyAccounts(a *system.AccountsResult) policyIDs {
	ids := policyIDs{uids: map[int]bool{}, gids: map[int]bool{}}
	if a == nil {
		return ids
	}
	for _, acc := range a.Accounts {
		if policyDaemons[acc.Name] && acc.UID > 0 {
			ids.uids[acc.UID] = true
		}
	}
	for _, g := range a.Groups {
		if policyDaemons[g.Name] && g.GID > 0 {
			ids.gids[g.GID] = true
		}
	}
	return ids
}

// foreignWritable reports whether an account other than root can change a file: it owns it,
// it is on a user's FUSE mount, an ACL is set, or the mode lets others (or a group other than
// root's) write. polkit's own account and group are trusted on polkit's files.
func foreignWritable(f collector.File, trusted policyIDs) bool {
	polkit := strings.Contains(f.Path+"/", "/polkit-1/")
	if f.Mount != "" || f.ACL != "" {
		return true
	}
	if f.UID != nil && *f.UID != 0 && (!polkit || !trusted.uids[int(*f.UID)]) {
		return true
	}
	if len(f.Mode) < 9 {
		return false
	}
	perm := f.Mode[len(f.Mode)-9:]
	groupOK := f.GID == nil || *f.GID == 0 || polkit && trusted.gids[int(*f.GID)]
	return perm[7] == 'w' || perm[4] == 'w' && !groupOK
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
		for _, f := range st.Sudoers.Files {
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
var StateKinds = []string{"accounts", "ssh", "persistence", "processes", "packages", "privileged", "web", "apps", "sensor"}

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
		state("sensor", "error:"+name, "medium", "Collector "+name+" non completato", msg)
	}
	for _, w := range cur.Warnings {
		state("sensor", "warning:"+w, "medium", "Garanzie del sensore ridotte", w)
	}

	if a := cur.Accounts; a != nil {
		for _, acc := range a.Accounts {
			if acc.UID == 0 && acc.Name != "root" {
				state("accounts", "uid0:"+acc.Name, "critical", "Secondo account root: "+acc.Name,
					fmt.Sprintf("L'account %s ha UID 0, cioè i privilegi di root. Home %s, shell %s.", acc.Name, acc.Home, acc.Shell))
			}
			if acc.Password == "empty" && realShell(acc.Shell) {
				state("accounts", "empty-password:"+acc.Name, "high", "Account senza password: "+acc.Name, "Shell "+acc.Shell+": chiunque può entrare con questo nome.")
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
					change("accounts-change", "new:"+acc.Name, "high", "Nuovo account: "+acc.Name,
						fmt.Sprintf("UID %d, home %s, shell %s.", acc.UID, acc.Home, acc.Shell))
					continue
				}
				// An existing account given root's power by a standard command: these files are
				// root's, so the change is.
				if old.UID != acc.UID {
					change("accounts-change", "uid:"+acc.Name+"|"+fmt.Sprint(acc.UID), "high", "UID cambiato per "+acc.Name,
						fmt.Sprintf("Da %d a %d.", old.UID, acc.UID))
				}
				if old.Password != system.PasswordSet && acc.Password == system.PasswordSet {
					change("accounts-change", "password:"+acc.Name+"|"+acc.Password, "high", "Password impostata per "+acc.Name,
						"L'account prima non aveva una password utilizzabile; ora sì.")
				}
				if !realShell(old.Shell) && realShell(acc.Shell) {
					change("accounts-change", "shell:"+acc.Name+"|"+acc.Shell, "high", "Shell abilitata per "+acc.Name,
						fmt.Sprintf("Da %s a %s: l'account ora può aprire una sessione.", old.Shell, acc.Shell))
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
					change("accounts-change", "member:"+name+"|"+fmt.Sprint(gid), sev, fmt.Sprintf("%s ora nel gruppo %s", name, groupNames(a.Groups, gid)),
						fmt.Sprintf("%s appartiene ora al gruppo GID %d (%s)%s.", name, gid, groupNames(a.Groups, gid), map[bool]string{true: ", che dà accesso equivalente o vicino a quello di root", false: ""}[priv]))
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
						change("accounts-change", "group-admin:"+g.Name+"|"+m, sev, "Amministratore del gruppo "+g.Name+": "+m,
							fmt.Sprintf("%s può ora aggiungere chiunque, sé compreso, al gruppo %s (GID %d) con gpasswd.", m, g.Name, g.GID))
					}
				}
				if g.Password == system.PasswordSet && privGIDs[g.GID] && !groupPasswordSet(prev.Accounts, g.Name) {
					change("accounts-change", "group-password:"+g.Name, "critical", "Password impostata per il gruppo "+g.Name,
						"Con la password del gruppo chiunque sul server può entrarci con newgrp o sg.")
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
			state("ssh", "root-login", "medium", "SSH: login di root con password consentito", "PermitRootLogin yes.")
		}
		if s.Settings["passwordauthentication"] == "yes" {
			state("ssh", "password-auth", "medium", "SSH: autenticazione con password attiva", "PasswordAuthentication yes: le chiavi sono più difficili da indovinare.")
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
				changeBy(owner, "ssh-change", "key:"+k.User+"|"+k.Fingerprint, "high", "Nuova chiave SSH per "+k.User,
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
			stateBy("root", "persistence", "policy-writable:"+f.Path+"|"+fileAccess(f), "critical", "Politica dei privilegi modificabile da altri: "+f.Path,
				fileAccess(f)+". Chi può scriverla può concedersi i privilegi di root e toglierla prima del controllo dopo.")
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
				change("persistence-change", "policy-access:"+d.Path+"|"+fileAccess(d), "high", "Permessi cambiati sulla cartella delle politiche "+d.Path,
					"Da "+fileAccess(old)+" a "+fileAccess(d)+".")
			}
		}
		for _, f := range s.Files {
			old, ok := before[f.Path]
			delete(before, f.Path)
			if ok && fileAccess(old.File) != fileAccess(f.File) {
				change("persistence-change", "policy-access:"+f.Path+"|"+fileAccess(f.File), "high", "Permessi cambiati sulla politica "+f.Path,
					"Da "+fileAccess(old.File)+" a "+fileAccess(f.File)+". Chi può scrivere il file può concedersi i privilegi di root.")
			}
			if ok && old.SHA256 == f.SHA256 && slices.Equal(old.Rules, f.Rules) {
				continue
			}
			title := "Nuova politica " + policyName(f.Path) + ": " + f.Path
			if ok {
				title = "Politica " + policyName(f.Path) + " cambiata: " + f.Path
			}
			change("persistence-change", "policy:"+f.Path+"|"+f.SHA256, "high", title, ruleDiff(old.Rules, f.Rules))
		}
		for path, old := range before {
			change("persistence-change", "policy-removed:"+path+"|"+old.SHA256, "high", "Politica "+policyName(path)+" rimossa: "+path,
				"Togliere un file può togliere un divieto.\n"+ruleDiff(old.Rules, nil))
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
				state("persistence", "immutable-cron:"+t.Path, "critical", "Crontab protetto con chattr +i", t.Path+": il file non si può modificare né cancellare, nemmeno da root, finché non si toglie l'attributo.")
			}
			for _, e := range t.Entries {
				// A line is new to its table: the same line in another user's crontab earlier
				// does not make it known in root's.
				if known != nil && !known.has(t.Path+"\x00"+e) {
					owner := cronOwner(t.Path)
					if uid, ok := uids[owner]; ok && uid == 0 {
						owner = "root"
					}
					changeBy(owner, "persistence-change", "cron:"+t.Path+"|"+e, "high", "Nuova riga di cron", e+"\nin "+t.Path)
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
				stateBy(owner, "persistence", "default-env:"+owner+"|"+env, "critical", "Libreria iniettata in tutti i servizi", env)
			}
		}
		for _, u := range s.Units {
			if u.Immutable {
				state("persistence", "immutable-unit:"+u.Path, "critical", "Unit systemd protetta con chattr +i", u.Path)
			}
			for _, x := range u.Exec {
				if _, cmd, ok := strings.Cut(x, "="); ok && len(strings.Fields(cmd)) > 0 && suspiciousPath(strings.TrimLeft(strings.Fields(cmd)[0], "-@+!:")) {
					stateBy(unitOwner(u), "persistence", "unit-exec:"+unitOwner(u)+"|"+u.Path+":"+x, "high", "Servizio che esegue da una cartella insolita", x+"\nin "+u.Path)
				}
			}
			if knownUnits != nil && !knownUnits.has(u.Path) {
				changeBy(unitOwner(u), "persistence-change", "unit:"+unitOwner(u)+"|"+u.Path, "medium", "Nuovo servizio systemd", u.Path+"\n"+strings.Join(u.Exec, "\n"))
			}
		}
		for _, g := range s.Generators {
			if knownGenerators != nil && !knownGenerators.has(g.Path) {
				change("persistence-change", "generator:"+g.Path, "high", "Nuovo generator systemd", g.Path+": viene eseguito da root a ogni avvio.")
			}
		}
	}

	if h := cur.Hooks; h != nil {
		for _, lib := range h.Preload {
			state("persistence", "preload:"+lib, "critical", "Libreria caricata in ogni processo", lib+" è in /etc/ld.so.preload: è la tecnica dei rootkit in userspace.")
		}
	}

	if p := cur.Processes; p != nil {
		for _, pr := range p.Processes {
			switch {
			case pr.ExeDeleted:
				state("processes", "deleted:"+pr.Exe+":"+pr.ExeSHA256, "high", "Processo da un eseguibile cancellato", fmt.Sprintf("PID %d (%s) esegue %s, rimosso dal disco. Hash %s.", pr.PID, pr.Comm, pr.Exe, pr.ExeSHA256))
			case suspiciousPath(pr.Exe):
				state("processes", "exe:"+pr.Exe+":"+pr.ExeSHA256, "high", "Processo da una cartella insolita", fmt.Sprintf("PID %d (%s) esegue %s come UID %d.", pr.PID, pr.Comm, pr.Exe, pr.UID))
			}
			if pr.Preload != "" {
				state("processes", "ld-preload:"+pr.Comm+":"+pr.Preload, "high", "Processo con LD_PRELOAD", fmt.Sprintf("PID %d (%s) carica %s.", pr.PID, pr.Comm, pr.Preload))
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
				change("network-change", "listen:"+so.Proto+":"+so.Local, "medium", "Nuova porta in ascolto: "+so.Local, fmt.Sprintf("%s %s, processo %s (PID %d).", so.Proto, so.Local, so.Process, so.PID))
			}
		}
	}

	if p := cur.Packages; p != nil {
		for _, m := range p.Modified {
			if !m.Config {
				state("packages", "modified:"+m.Path, "high", "File di sistema modificato: "+m.Path, "Non corrisponde al pacchetto "+m.Package+".")
			}
		}
		for _, h := range p.Hidden {
			state("packages", "hidden:"+h, "high", "Elemento nascosto in /usr: "+h, "Nessun pacchetto installa file con il nome che comincia per punto sotto /usr.")
		}
		if prev != nil && prev.Packages != nil {
			known := set{}
			known.add(prev.Packages.Unowned...)
			for _, u := range p.Unowned {
				if !known.has(u) {
					change("packages-change", "unowned:"+u, "medium", "Nuovo eseguibile fuori dai pacchetti: "+u, "")
				}
			}
			if p.DatabaseSHA256 != prev.Packages.DatabaseSHA256 && p.Packages == prev.Packages.Packages {
				change("packages-change", "database:"+p.DatabaseSHA256, "medium", "Database dei pacchetti cambiato senza installazioni",
					"Il numero di pacchetti è lo stesso ma il database è diverso: un aggiornamento normale, oppure checksum riscritti per coprire un file sostituito.")
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
				state("privileged", "attr:"+f.Path, "high", "File protetto con chattr: "+f.Path, "Gli attributi immutable o append-only sono rari sui server e sono usati per rendere persistente un accesso.")
			case suspiciousPath(f.Path) || !standardBinDir(f.Path):
				owner := privilegedOwner(f, cur, privGIDs, groupsOf)
				stateBy(owner, "privileged", "setid:"+owner+"|"+f.Path, "critical", "Binario setuid/setgid in una cartella insolita: "+f.Path, "Modo "+f.Mode+", proprietario "+owner+", hash "+f.SHA256+".")
			}
			if known != nil && !known.has(f.Path+"\x00"+f.SHA256) {
				owner := privilegedOwner(f, cur, privGIDs, groupsOf)
				changeBy(owner, "privileged-change", "new:"+owner+"|"+f.Path+":"+f.SHA256, "high", "Nuovo file privilegiato: "+f.Path, "Modo "+f.Mode+", proprietario "+owner+".")
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
					detail += fmt.Sprintf("\n%d byte, SHA-256 %s", f.Size, f.SHA256)
				}
				if len(f.Signatures) > 0 {
					detail += "\nFirme: " + strings.Join(f.Signatures, ", ")
				}
				if f.Reachable {
					detail += "\nRaggiungibile dal web secondo la configurazione."
				}
				state("web", f.Kind+":"+f.Path, sev, title, detail)
			}
			if pa, ok := prevApps[app.Path]; ok {
				for dir, sum := range app.DirHashes {
					if old, ok := pa.DirHashes[dir]; ok && old != sum {
						change("web-change", "code:"+dir+":"+sum, "medium", "Codice cambiato in "+dir, "Se non c'è stato un deploy, qualcuno ha modificato il codice dell'applicazione "+app.Path+".")
					}
				}
			}
		}
		for _, cfg := range w.Inventory.StaleConfig {
			state("web", "stale-config:"+cfg, "medium", "Configurazione del web server cambiata dopo l'avvio", cfg)
		}
	}

	if l := cur.Weblog; l != nil {
		for _, e := range l.Events {
			if e.Severity != "critical" && e.Severity != "high" {
				continue
			}
			// Log events are new by construction (each run reads only new lines), so they count
			// from the first snapshot on.
			// The script the request reached names the alert's group: noise sent to other
			// scripts does not crowd out the one that matters.
			script := weblog.ScriptPath(path.Clean("/" + strings.SplitN(e.Evidence.Request, "?", 2)[0]))
			add(Finding{Kind: "weblog", Fingerprint: "weblog:" + e.Rule + ":" + script + "|" + e.Evidence.Request + e.Log, Severity: e.Severity, Title: "Log: " + strings.ReplaceAll(e.Rule, "_", " "), Detail: fmt.Sprintf("%s %s, status %d, %d richieste da %d indirizzi (primo %s), log %s.\nTesto della richiesta, scritto da chi l'ha inviata: %s",
				e.Method, path.Clean("/"+e.Evidence.Request), e.Status, e.Count, max(e.IPs, 1), e.IP, e.Log, e.Evidence.Request)})
		}
		// A flood that pushed serious events out of the bounded list is itself an alert: it may
		// have been sent to hide one.
		if n := l.Stats.DroppedEvents["critical"] + l.Stats.DroppedEvents["high"]; n > 0 {
			var b strings.Builder
			fmt.Fprintf(&b, "%d eventi critici o alti non sono entrati nell'elenco dei log, saturato da altri. Un'ondata di richieste rumorose può servire a nascondere quella che conta.", n)
			if len(l.Stats.DroppedSamples) > 0 {
				b.WriteString("\nAlcuni degli eventi scartati (testo scritto da chi ha fatto la richiesta):")
				for _, d := range l.Stats.DroppedSamples {
					fmt.Fprintf(&b, "\n  %s %s da %s: %s", d.Severity, strings.ReplaceAll(d.Rule, "_", " "), d.IP, d.Path)
				}
			}
			// Like the events, each run's drops are new: one alert per snapshot that had them.
			add(Finding{Kind: "weblog", Fingerprint: "weblog:dropped:" + strconv.FormatInt(cur.TakenAt.Unix(), 10), Severity: "high",
				Title: "Log: eventi gravi scartati per saturazione", Detail: b.String()})
		}
	}

	if a := cur.Apps; a != nil {
		for _, app := range a.Apps {
			for _, inj := range app.Injected {
				for _, d := range inj.Domains {
					state("apps", "script:"+app.Path+":"+inj.Where+":"+d, "high", "Script esterno salvato nel database: "+d,
						fmt.Sprintf("%s in %s (%s). Verificare che sia un servizio voluto: è il modo in cui si iniettano gli skimmer.", d, inj.Where, app.Path))
				}
			}
			for _, w := range app.Warnings {
				state("apps", "warning:"+app.Path+":"+w, "low", "Impostazione da sviluppo in "+app.Path, w)
			}
			if prev == nil || prev.Apps == nil {
				continue
			}
			for _, pa := range prev.Apps.Apps {
				if pa.Path != app.Path {
					continue
				}
				for _, ad := range app.Admins {
					if !slices.ContainsFunc(pa.Admins, func(p adminT) bool { return p.ID == ad.ID }) {
						change("apps-change", "admin:"+app.Path+":"+ad.ID, "critical", "Nuovo amministratore in "+app.Path+": "+ad.Name,
							fmt.Sprintf("Email %s, creato %s.", ad.Email, ad.Created))
					}
				}
			}
		}
	}
	return out
}

// webFinding maps a web finding kind to a severity and a title.
func webFinding(f web.Finding) (string, string) {
	switch f.Kind {
	case web.KindSignature, web.KindScriptInUploads, web.KindCodeInUploads, web.KindPolyglotImage:
		return "critical", map[string]string{
			web.KindSignature:       "Firma di webshell",
			web.KindScriptInUploads: "Script nelle cartelle di upload",
			web.KindCodeInUploads:   "Codice dentro un file caricato",
			web.KindPolyglotImage:   "Immagine con codice nascosto",
		}[f.Kind]
	case web.KindHiddenScript, web.KindSuspiciousSymlink, web.KindAppInData:
		return "high", map[string]string{
			web.KindHiddenScript:      "Script nascosto",
			web.KindSuspiciousSymlink: "Collegamento sospetto",
			web.KindAppInData:         "Applicazione dentro una cartella di upload",
		}[f.Kind]
	case web.KindOverrideInData:
		if slices.Contains(f.Signatures, "handler_directive") {
			return "critical", "Configurazione che rende eseguibili gli upload"
		}
		return "", ""
	case web.KindHiddenInData:
		return "medium", "File nascosto nelle cartelle di dati"
	}
	return "", ""
}

func standardBinDir(p string) bool {
	return slices.ContainsFunc([]string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/", "/lib/", "/usr/local/bin/", "/usr/local/sbin/", "/snap/", "/opt/"},
		func(d string) bool { return strings.HasPrefix(p, d) })
}
