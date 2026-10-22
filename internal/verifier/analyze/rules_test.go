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
		"high ssh-change:key:svcadmin:SHA256:new",
		"critical persistence:preload:/usr/lib/libhide.so",
		"high processes:deleted:/var/www/.cache/x:",
		"critical privileged:setid:/usr/lib/.syslib/sh2",
		"high privileged-change:new:/usr/lib/.syslib/sh2:bb",
		"high persistence:unit-exec:/etc/systemd/system/sync.service:ExecStart=/var/www/.cache/sync/syncd",
		"critical web:script_in_upload_dir:/var/www/shop/pub/media/x.php",
		"critical weblog:script_in_upload_path:/media/x.php/var/log/nginx/access.log",
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
