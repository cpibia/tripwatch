package analyze

import (
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
	if len(findings) != 80_000 {
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
	cur := State{
		Services: &system.ServicesResult{Environment: []string{
			"LD_PRELOAD=/dev/shm/a.so (var/www/.config/environment.d/x.conf)",
			"LD_PRELOAD=/dev/shm/b.so (etc/environment.d/50-x.conf)",
		}},
		Privileged: &system.PrivilegedResult{Files: []collector.File{
			{Path: "/srv/x/disk", Mode: "grwxr-xr-x", UID: &uid33, GID: &gid6},
			{Path: "/srv/x/mine", Mode: "urwxr-xr-x", UID: &uid33, GID: &uid33},
			{Path: "/srv/x/root", Mode: "urwxr-xr-x", UID: &uid0, GID: &uid0},
		}},
	}
	owners := findingOwners(Evaluate(nil, cur))
	for fp, want := range map[string]string{
		"persistence:default-env:home /var/www|LD_PRELOAD=/dev/shm/a.so (var/www/.config/environment.d/x.conf)": "home /var/www",
		"persistence:default-env:root|LD_PRELOAD=/dev/shm/b.so (etc/environment.d/50-x.conf)":                   "root",
		"privileged:setid:root|/srv/x/disk":   "root",
		"privileged:setid:uid 33|/srv/x/mine": "uid 33",
		"privileged:setid:root|/srv/x/root":   "root",
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
