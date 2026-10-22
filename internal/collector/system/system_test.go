package system

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
)

// attackerKey is a real ed25519 public key; its fingerprint was computed with ssh-keygen -lf.
const (
	attackerKey            = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOK598sqePdKtkm/hDKNYQN8sTuKXN0inwO5nj6cyyV svc"
	attackerKeyFingerprint = "SHA256:wkCkZ/hvJL8TOY0x1X6tvN8Jv4J+HcvtWRqDCCNbMFI"
)

func text(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s), Mode: 0o644} }

// compromisedHost reproduces common persistence techniques: a second UID 0 account with an
// SSH key, a hidden SUID shell, immutable cron and service files, a fake systemd service and
// an encoded command in www-data's crontab.
func compromisedHost() collector.Source {
	fsys := fstest.MapFS{
		"etc/passwd": text("root:x:0:0:root:/root:/bin/bash\n" +
			"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n" +
			"backupd:x:998:998::/home/backupd:/bin/sh\n" +
			"svcadmin:x:0:0::/var/lib/svcadmin:/bin/bash\n" +
			"broken:x:notanumber:0::/:/bin/sh\n"),
		"etc/shadow": text("root:$6$salt$hash:19000::::::\n" +
			"www-data:*:19000::::::\n" +
			"backupd:!:19000::::::\n" +
			"svcadmin::19000::::::\n"),
		"etc/group": text("root:x:0:\nsudo:x:27:alice,svcadmin\n"),

		"etc/ssh/sshd_config": text("# comment\nInclude /etc/ssh/sshd_config.d/*.conf\nPort 22\nPermitRootLogin yes\n" +
			"Match Address 203.0.113.7\n  PermitRootLogin yes\n  PasswordAuthentication yes\n"),
		"etc/ssh/sshd_config.d/10-local.conf": text("PermitRootLogin prohibit-password\nPasswordAuthentication no\n"),
		"root/.ssh/authorized_keys":           text("# admins\n" + attackerKey + "\n"),
		"var/lib/svcadmin/.ssh/authorized_keys": text(
			`command="/bin/sh -c 'id'",no-pty ` + attackerKey + "\nnot a key\n"),

		"etc/sudoers":          text("Defaults env_reset\n# a comment\n#includedir /etc/sudoers.d\nroot ALL=(ALL:ALL) ALL\n"),
		"etc/sudoers.d/90-ops": text("alice ALL=(ALL) NOPASSWD:ALL\n"),

		"etc/crontab":                      text("SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"),
		"var/spool/cron/crontabs/backupd":  text("# DO NOT EDIT\n*/7 * * * * /usr/lib/.syslib/fnd /tmp -maxdepth 0 -exec /bin/sh /usr/lib/.syslib/runner.sh \\;\n"),
		"var/spool/cron/crontabs/www-data": text("0 * * * * echo ZXhlYw== | base64 -d | bash # refresh\n"),
		"etc/cron.daily/logrotate":         text("#!/bin/sh\n"),

		"etc/systemd/system/network-sync.service": text("[Unit]\nDescription=Network sync\n[Service]\n" +
			"User=www-data\nExecStart=/var/www/.cache/sync/syncd\n; ExecStart=/bin/false\nRestart=always\n"),
		"etc/systemd/system/nginx.service.d/override.conf": text("[Service]\nExecStartPost=/bin/sh /tmp/x\n"),
		"etc/systemd/system/multi-user.target.wants/network-sync.service": &fstest.MapFile{
			Data: []byte("/etc/systemd/system/network-sync.service"), Mode: fs.ModeSymlink},
		"lib":                                         &fstest.MapFile{Data: []byte("usr/lib"), Mode: fs.ModeSymlink},
		"usr/lib/systemd/system/ssh.service":          text("[Service]\nExecStart=/usr/sbin/sshd -D\n"),
		"usr/lib/systemd/system/README":               text("not a unit\n"),
		"var/www/.config/systemd/user/x.timer":        text("[Timer]\nOnCalendar=hourly\n"),
		"run/systemd/transient/run-r1.service":        text("[Service]\nExecStart=/tmp/.x\n"),
		"var/www/.local/share/systemd/user/y.service": text("[Service]\nExecStart=/var/www/.y\n"),
		"etc/systemd/system-generators/net-helper":    &fstest.MapFile{Data: []byte("#!/bin/sh\n"), Mode: 0o755},
		"etc/systemd/system.conf":                     text("[Manager]\n#DefaultEnvironment=\nDefaultEnvironment=LD_PRELOAD=/usr/lib/libx.so\n"),

		"etc/ld.so.preload":  text("/usr/lib/libprocesshider.so\n"),
		"etc/profile.d/x.sh": text("export A=1\n"),
		"root/.bashrc":       text("alias ll='ls -l'\n"),

		"usr/lib/.syslib/sh2":       &fstest.MapFile{Data: []byte("bash"), Mode: 0o755 | fs.ModeSetuid},
		"usr/lib/.syslib/runner.sh": text("#!/bin/sh\n"),
		"usr/bin/passwd":            &fstest.MapFile{Data: []byte("passwd"), Mode: 0o755 | fs.ModeSetuid},
		"usr/bin/crontab":           &fstest.MapFile{Data: []byte("crontab"), Mode: 0o755 | fs.ModeSetgid},
		"usr/bin/python3":           text("python"),
		"proc/1/exe":                &fstest.MapFile{Data: []byte("init"), Mode: 0o755 | fs.ModeSetuid},
		"dev/shm/.x":                &fstest.MapFile{Data: []byte("payload"), Mode: 0o755 | fs.ModeSetuid},
	}

	attrs := map[string]collector.Attrs{
		"var/spool/cron/crontabs/backupd":         {Immutable: true},
		"etc/systemd/system/network-sync.service": {Immutable: true},
		"usr/lib/.syslib":                         {Immutable: true},
		"usr/lib/.syslib/runner.sh":               {Immutable: true},
		"usr/bin/python3":                         {Capabilities: true},
		"var/log/wtmp":                            {AppendOnly: true},
	}
	fsys["var/log/wtmp"] = text("")

	return collector.Source{
		FS: fsys,
		Attrs: func(name string) (collector.Attrs, error) {
			if name == "usr/bin/crontab" {
				return collector.Attrs{}, errors.New("operation not supported")
			}
			return attrs[name], nil
		},
	}
}

func collect[T any](t *testing.T, c collector.Collector, src collector.Source) T {
	t.Helper()
	out, err := c.Collect(context.Background(), src)
	if err != nil {
		t.Fatalf("%s: %v", c.Name(), err)
	}
	return out.(T)
}

func paths(files []collector.File) []string {
	var out []string
	for _, f := range files {
		out = append(out, f.Path)
	}
	return out
}

func TestAccounts(t *testing.T) {
	res := collect[AccountsResult](t, Accounts{}, compromisedHost())

	want := map[string]Account{
		"root":     {Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash", Password: PasswordSet},
		"www-data": {Name: "www-data", UID: 33, GID: 33, Home: "/var/www", Shell: "/usr/sbin/nologin", Password: PasswordLocked},
		"backupd":  {Name: "backupd", UID: 998, GID: 998, Home: "/home/backupd", Shell: "/bin/sh", Password: PasswordLocked},
		"svcadmin": {Name: "svcadmin", UID: 0, GID: 0, Home: "/var/lib/svcadmin", Shell: "/bin/bash", Password: PasswordEmpty},
	}
	if len(res.Accounts) != len(want) {
		t.Fatalf("got %d accounts, want %d: %+v", len(res.Accounts), len(want), res.Accounts)
	}
	for _, a := range res.Accounts {
		if a != want[a.Name] {
			t.Errorf("account %s = %+v, want %+v", a.Name, a, want[a.Name])
		}
	}
	if len(res.Issues) != 1 || !strings.Contains(res.Issues[0], "broken") {
		t.Errorf("issues = %v, want the malformed entry reported", res.Issues)
	}

	sudo := res.Groups[1]
	if sudo.Name != "sudo" || !slices.Equal(sudo.Members, []string{"alice", "svcadmin"}) {
		t.Errorf("sudo group = %+v", sudo)
	}
	if got := paths(res.Files); !slices.Equal(got, []string{"/etc/passwd", "/etc/shadow", "/etc/group"}) {
		t.Errorf("files = %v", got)
	}
	for _, f := range res.Files {
		if len(f.SHA256) != 64 {
			t.Errorf("%s has no hash", f.Path)
		}
	}
}

func TestAccountsPasswordUnknownWithoutShadow(t *testing.T) {
	src := collector.Source{FS: fstest.MapFS{"etc/passwd": text("root:x:0:0:root:/root:/bin/bash\n")}}
	res := collect[AccountsResult](t, Accounts{}, src)
	if res.Accounts[0].Password != PasswordUnknown {
		t.Errorf("password = %q, want %q", res.Accounts[0].Password, PasswordUnknown)
	}
}

func TestEmptyFilesystem(t *testing.T) {
	snap := collector.Run(context.Background(), collector.Source{FS: fstest.MapFS{}}, All(), time.Now())
	if len(snap.Errors) != 0 {
		t.Fatalf("a machine without these files must not fail the collection: %v", snap.Errors)
	}
}

func TestSSH(t *testing.T) {
	res := collect[SSHResult](t, SSH{}, compromisedHost())

	if res.Settings["permitrootlogin"] != "prohibit-password" {
		t.Errorf("PermitRootLogin = %q, want the drop-in's, included before the main file's value", res.Settings["permitrootlogin"])
	}
	wantMatch := SSHMatch{File: "/etc/ssh/sshd_config", Criteria: "Address 203.0.113.7", Lines: []string{"PermitRootLogin yes", "PasswordAuthentication yes"}}
	if len(res.Matches) != 1 || res.Matches[0].Criteria != wantMatch.Criteria || !slices.Equal(res.Matches[0].Lines, wantMatch.Lines) {
		t.Errorf("matches = %+v", res.Matches)
	}
	if res.Settings["passwordauthentication"] != "no" || res.Settings["port"] != "22" {
		t.Errorf("settings = %v", res.Settings)
	}

	if len(res.Keys) != 2 {
		t.Fatalf("keys = %+v, want 2", res.Keys)
	}
	root, hidden := res.Keys[0], res.Keys[1]
	if root.User != "root" || root.File != "/root/.ssh/authorized_keys" || root.Options != "" {
		t.Errorf("root key = %+v", root)
	}
	if hidden.User != "svcadmin" || hidden.Options != `command="/bin/sh -c 'id'",no-pty` || hidden.Comment != "svc" {
		t.Errorf("svcadmin key = %+v", hidden)
	}
	for _, k := range res.Keys {
		if k.Fingerprint != attackerKeyFingerprint || k.Type != "ssh-ed25519" {
			t.Errorf("key %s: type %s fingerprint %s", k.File, k.Type, k.Fingerprint)
		}
	}
	if !slices.Contains(paths(res.Files), "/var/lib/svcadmin/.ssh/authorized_keys") {
		t.Errorf("files = %v", paths(res.Files))
	}
}

func TestExpandKeysPath(t *testing.T) {
	a := Account{Name: "deploy", Home: "/home/deploy"}
	tests := map[string]string{
		".ssh/authorized_keys":            "home/deploy/.ssh/authorized_keys",
		"/etc/ssh/keys/%u":                "etc/ssh/keys/deploy",
		"%h/.ssh/keys":                    "home/deploy/.ssh/keys",
		"/etc/ssh/%%u/%u":                 "etc/ssh/%u/deploy",
		"/home/%u/../../etc/shadow":       "etc/shadow",
		"../../../../etc/authorized_keys": "etc/authorized_keys",
	}
	for pattern, want := range tests {
		if got := expandKeysPath(pattern, a); got != want {
			t.Errorf("expandKeysPath(%q) = %q, want %q", pattern, got, want)
		}
	}
}

func TestParseAuthorizedKeyRejectsGarbage(t *testing.T) {
	for _, line := range []string{"", "# ssh-ed25519 AAAA", "ssh-ed25519 !!notbase64!!", "from=\"x\" garbage", "ssh-rsa"} {
		if k, ok := parseAuthorizedKey(line); ok {
			t.Errorf("parseAuthorizedKey(%q) = %+v, want rejection", line, k)
		}
	}
}

func TestSudoers(t *testing.T) {
	res := collect[SudoersResult](t, Sudoers{}, compromisedHost())
	if len(res.Files) != 2 {
		t.Fatalf("files = %+v", res.Files)
	}
	want := []string{"Defaults env_reset", "#includedir /etc/sudoers.d", "root ALL=(ALL:ALL) ALL"}
	if !slices.Equal(res.Files[0].Rules, want) {
		t.Errorf("rules = %q, want %q", res.Files[0].Rules, want)
	}
	if res.Files[1].Path != "/etc/sudoers.d/90-ops" || res.Files[1].Rules[0] != "alice ALL=(ALL) NOPASSWD:ALL" {
		t.Errorf("drop-in = %+v", res.Files[1])
	}
}

func TestScheduled(t *testing.T) {
	res := collect[ScheduledResult](t, Scheduled{}, compromisedHost())

	byPath := map[string]CronTable{}
	for _, tbl := range res.Tables {
		byPath[tbl.Path] = tbl
	}
	if len(byPath) != 3 {
		t.Fatalf("tables = %v", slices.Sorted(maps.Keys(byPath)))
	}

	backupd := byPath["/var/spool/cron/crontabs/backupd"]
	if backupd.Owner != "backupd" || !backupd.Immutable || len(backupd.Entries) != 1 || !strings.Contains(backupd.Entries[0], ".syslib") {
		t.Errorf("backupd crontab = %+v", backupd)
	}
	if www := byPath["/var/spool/cron/crontabs/www-data"]; len(www.Entries) != 1 || !strings.Contains(www.Entries[0], "base64 -d") {
		t.Errorf("www-data crontab = %+v", www)
	}
	if sys := byPath["/etc/crontab"]; sys.Owner != "" || len(sys.Entries) != 2 {
		t.Errorf("system crontab = %+v", sys)
	}
	if got := paths(res.Scripts); !slices.Equal(got, []string{"/etc/cron.daily/logrotate"}) {
		t.Errorf("scripts = %v", got)
	}
}

func TestServices(t *testing.T) {
	res := collect[ServicesResult](t, Services{}, compromisedHost())

	units := map[string]Unit{}
	for _, u := range res.Units {
		units[u.Path] = u
	}

	fake := units["/etc/systemd/system/network-sync.service"]
	if !slices.Equal(fake.Exec, []string{"ExecStart=/var/www/.cache/sync/syncd"}) || fake.User != "www-data" || !fake.Immutable {
		t.Errorf("fake service = %+v", fake)
	}
	if dropIn := units["/etc/systemd/system/nginx.service.d/override.conf"]; !slices.Equal(dropIn.Exec, []string{"ExecStartPost=/bin/sh /tmp/x"}) {
		t.Errorf("drop-in = %+v", dropIn)
	}
	if _, ok := units["/var/www/.config/systemd/user/x.timer"]; !ok {
		t.Error("user timer of www-data not collected")
	}
	if _, ok := units["/usr/lib/systemd/system/README"]; ok {
		t.Error("non-unit file collected")
	}
	for _, p := range []string{"/run/systemd/transient/run-r1.service", "/var/www/.local/share/systemd/user/y.service"} {
		if _, ok := units[p]; !ok {
			t.Errorf("%s not collected", p)
		}
		delete(units, p)
	}
	if len(res.Generators) != 1 || res.Generators[0].Path != "/etc/systemd/system-generators/net-helper" {
		t.Errorf("generators = %+v", res.Generators)
	}
	if !slices.Equal(res.Environment, []string{"DefaultEnvironment=LD_PRELOAD=/usr/lib/libx.so"}) {
		t.Errorf("default environment = %v", res.Environment)
	}
	if len(units) != 4 {
		t.Errorf("units = %v; lib symlinked to usr/lib must not be walked twice", slices.Sorted(maps.Keys(units)))
	}

	want := Link{Path: "/etc/systemd/system/multi-user.target.wants/network-sync.service", Target: "/etc/systemd/system/network-sync.service"}
	if !slices.Contains(res.Links, want) {
		t.Errorf("links = %+v", res.Links)
	}
}

func TestHooks(t *testing.T) {
	res := collect[HooksResult](t, Hooks{}, compromisedHost())

	if !slices.Equal(res.Preload, []string{"/usr/lib/libprocesshider.so"}) {
		t.Errorf("preload = %v", res.Preload)
	}
	got := paths(res.Files)
	for _, want := range []string{"/etc/ld.so.preload", "/etc/profile.d/x.sh", "/root/.bashrc"} {
		if !slices.Contains(got, want) {
			t.Errorf("%s missing from %v", want, got)
		}
	}
}

func TestPrivileged(t *testing.T) {
	res := collect[PrivilegedResult](t, Privileged{Skip: DefaultSkip, Extra: DefaultExtra}, compromisedHost())

	got := paths(res.Files)
	want := []string{
		"/usr/bin/crontab",
		"/usr/bin/passwd",
		"/usr/bin/python3",
		"/usr/lib/.syslib",
		"/usr/lib/.syslib/sh2",
		"/usr/lib/.syslib/runner.sh",
		"/var/spool/cron/crontabs/backupd",
		"/etc/systemd/system/network-sync.service",
		"/var/log/wtmp",
		"/dev/shm/.x",
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("privileged files:\n got  %v\n want %v", got, want)
	}
	if res.AttrsSkipped != 1 {
		t.Errorf("attrs skipped = %d, want 1", res.AttrsSkipped)
	}
	for _, f := range res.Files {
		if f.Path == "/usr/lib/.syslib/sh2" && (f.SHA256 == "" || !strings.HasPrefix(f.Mode, "u")) {
			t.Errorf("setuid shell = %+v", f)
		}
	}
}

func TestPrivilegedStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Privileged{}).Collect(ctx, compromisedHost()); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestAll(t *testing.T) {
	snap := collector.Run(context.Background(), compromisedHost(), All(), time.Now())
	if len(snap.Errors) != 0 {
		t.Fatalf("errors = %v", snap.Errors)
	}
	for _, c := range All() {
		if _, ok := snap.Results[c.Name()]; !ok {
			t.Errorf("no result for %s", c.Name())
		}
	}
}

func TestRedactCmdline(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"/usr/bin/mysql", "-uroot", "-pS3cret", "shop"}, "/usr/bin/mysql -uroot -p[redacted] shop"},
		{[]string{"app", "--db-password=x", "--api-key", "abc", "--port", "80"}, "app --db-password=[redacted] --api-key [redacted] --port 80"},
		{[]string{"env", "AWS_SECRET_ACCESS_KEY=abc", "LANG=C"}, "env AWS_SECRET_ACCESS_KEY=[redacted] LANG=C"},
		{[]string{"curl", "https://user:pw@example.com/x"}, "curl https://user:[redacted]@example.com/x"},
		{[]string{"rsync", "--passive", "-p", "src"}, "rsync --passive -p src"},
		{[]string{"nginx: master process"}, "nginx: master process"},
	}
	for _, tt := range tests {
		if got := redactCmdline(tt.args); got != tt.want {
			t.Errorf("redactCmdline(%q) = %q, want %q", tt.args, got, tt.want)
		}
	}
}
