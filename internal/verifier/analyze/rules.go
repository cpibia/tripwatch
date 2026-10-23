package analyze

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

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

// unitOwner is the user a systemd unit runs for: the user of a user unit, root otherwise.
func unitOwner(u unitT) string {
	if u.User != "" && u.User != "root" {
		return u.User
	}
	return homeOwner(u.Path)
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

// privilegedOwner is root for a file that grants root's or a system group's rights when run:
// setuid and owned by root, or setgid with a system group (disk, shadow, adm, sudo...). Any
// other setuid or setgid file grants only its owner's rights.
func privilegedOwner(f fileT) string {
	if strings.Contains(strings.SplitN(f.Mode, "-", 2)[0], "g") && f.GID != nil && *f.GID < 1000 {
		return "root"
	}
	return uidOwner(f.UID)
}

// homeOwner names who wrote a configuration read from the given path: root for system
// directories, otherwise the home it lies in.
func homeOwner(p string) string {
	p = "/" + strings.TrimPrefix(p, "/")
	for _, dir := range []string{"/etc/", "/run/", "/usr/", "/lib/"} {
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
			if acc.Password == "empty" && acc.Shell != "" && !strings.HasSuffix(acc.Shell, "nologin") && !strings.HasSuffix(acc.Shell, "false") {
				state("accounts", "empty-password:"+acc.Name, "high", "Account senza password: "+acc.Name, "Shell "+acc.Shell+": chiunque può entrare con questo nome.")
			}
		}
		if prev != nil && prev.Accounts != nil {
			known := setOf(prev.Accounts.Accounts, func(p accountT) string { return p.Name })
			for _, acc := range a.Accounts {
				if !known.has(acc.Name) {
					change("accounts-change", "new:"+acc.Name, "high", "Nuovo account: "+acc.Name,
						fmt.Sprintf("UID %d, home %s, shell %s.", acc.UID, acc.Home, acc.Shell))
				}
			}
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
		uids := map[string]int{}
		if cur.Accounts != nil {
			for _, acc := range cur.Accounts.Accounts {
				uids[acc.Name] = acc.UID
			}
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

	if s := cur.Sudoers; s != nil && prev != nil && prev.Sudoers != nil {
		known := set{}
		for _, p := range prev.Sudoers.Files {
			known.add(p.Rules...)
		}
		for _, f := range s.Files {
			for _, rule := range f.Rules {
				if !known.has(rule) {
					change("persistence-change", "sudo:"+f.Path+"|"+rule, "high", "Nuova regola sudo", rule+" in "+f.Path)
				}
			}
		}
	}

	if s := cur.Scheduled; s != nil {
		var known set
		if prev != nil && prev.Scheduled != nil {
			known = set{}
			for _, p := range prev.Scheduled.Tables {
				known.add(p.Entries...)
			}
		}
		for _, t := range s.Tables {
			if t.Immutable {
				state("persistence", "immutable-cron:"+t.Path, "critical", "Crontab protetto con chattr +i", t.Path+": il file non si può modificare né cancellare, nemmeno da root, finché non si toglie l'attributo.")
			}
			for _, e := range t.Entries {
				if known != nil && !known.has(e) {
					changeBy(cronOwner(t.Path), "persistence-change", "cron:"+t.Path+"|"+e, "high", "Nuova riga di cron", e+"\nin "+t.Path)
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
		var known set
		if prev != nil && prev.Privileged != nil {
			known = setOf(prev.Privileged.Files, func(q fileT) string { return q.Path + "\x00" + q.SHA256 })
		}
		for _, f := range p.Files {
			switch {
			case f.Immutable || f.AppendOnly:
				state("privileged", "attr:"+f.Path, "high", "File protetto con chattr: "+f.Path, "Gli attributi immutable o append-only sono rari sui server e sono usati per rendere persistente un accesso.")
			case suspiciousPath(f.Path) || !standardBinDir(f.Path):
				owner := privilegedOwner(f)
				stateBy(owner, "privileged", "setid:"+owner+"|"+f.Path, "critical", "Binario setuid/setgid in una cartella insolita: "+f.Path, "Modo "+f.Mode+", proprietario "+owner+", hash "+f.SHA256+".")
			}
			if known != nil && !known.has(f.Path+"\x00"+f.SHA256) {
				owner := privilegedOwner(f)
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
