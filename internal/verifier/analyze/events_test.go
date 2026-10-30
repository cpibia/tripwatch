package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/watch"
)

// Every command the web server's user runs is an alert of its own: where that account also runs
// scheduled jobs, accepting one job leaves the others, and anything new, raised.
func TestWebShellAlertsPerCommand(t *testing.T) {
	uid := 1000
	start := func(parent, cmdline string, pid int) watch.Event {
		return watch.Event{Class: watch.ClassExec, Reason: watch.ReasonWebShell, Exe: "/usr/bin/dash", Parent: parent, Cwd: "/var/www/html", Cmdline: cmdline, User: &uid, PID: pid}
	}
	fingerprint := func(e watch.Event) string {
		t.Helper()
		fs := EvaluateEvents([]watch.Event{e}, false, nil)
		if len(fs) != 1 || fs[0].Severity != "critical" {
			t.Fatalf("findings %+v", fs)
		}
		return fs[0].Fingerprint
	}
	job := fingerprint(start("php", "sh -c /usr/bin/php8.3 artisan schedule:run", 10))
	if again := fingerprint(start("php", "sh -c /usr/bin/php8.3 artisan schedule:run", 99)); again != job {
		t.Errorf("the same job in another process: %s, then %s", job, again)
	}
	for _, other := range []watch.Event{
		start("cron", "/bin/sh -c /srv/jobs/mail.sh", 11),
		start("php-fpm8.4", "sh -c /usr/bin/php8.3 artisan schedule:run", 12),
		start("php", "sh -c id", 13),
	} {
		if fp := fingerprint(other); fp == job || !strings.HasPrefix(fp, "realtime:webshell:/usr/bin/dash#") {
			t.Errorf("%s: fingerprint %s, the job's %s", other.Cmdline, fp, job)
		}
	}
}

// A command fed a here-document is keyed on its head: a tool that pipes a new script, with a new
// delimiter, at every run is one alert; another head, or the same head told apart by the
// sensor's sum of the raw text, is another.
func TestWebShellKeyedOnCommandHead(t *testing.T) {
	uid := 9999
	start := func(cmdline, sum string) string {
		t.Helper()
		e := watch.Event{Class: watch.ClassExec, Reason: watch.ReasonWebShell, Exe: "/bin/busybox", Parent: "php", Cwd: "/var/www/html", Cmdline: cmdline, CommandSum: sum, User: &uid}
		fs := EvaluateEvents([]watch.Event{e}, false, nil)
		if len(fs) != 1 {
			t.Fatalf("findings %+v", fs)
		}
		return fs[0].Fingerprint
	}
	head := "sh -c timeout 300 ssh -i /srv/keys/deploy -o PasswordAuthentication=[redacted] root@host sh -s"
	first := start(head+" << \\QUJD\nuptime\nQUJD", "aaaaaaaaaaaa")
	if again := start(head+" << \\WFla\ndocker ps\nWFla", "aaaaaaaaaaaa"); again != first {
		t.Errorf("the same command with another script: %s, then %s", first, again)
	}
	if other := start(head+" << \\QUJD\nuptime\nQUJD", "bbbbbbbbbbbb"); other == first {
		t.Error("heads the redaction shows alike share a key")
	}
	if other := start("sh -c ssh root@elsewhere sh -s << X\nuptime\nX", "aaaaaaaaaaaa"); other == first {
		t.Error("another command shares the key")
	}
}

func TestEvaluateEvents(t *testing.T) {
	t0 := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	uid := 33
	keys := "/root/.ssh/authorized_keys"
	web33, dev1000, root0 := uint32(33), uint32(1000), uint32(0)
	oldKeys := "/home/ops/.ssh/authorized_keys"
	past := map[string][]watch.Event{
		keys: {
			{At: t0, Class: watch.ClassSSH, Op: watch.OpWrite, Path: keys, SHA256: "aaaa"},
			{At: t0.Add(time.Minute), Class: watch.ClassSSH, Op: watch.OpWrite, Path: keys, SHA256: "bbbb"},
			{At: t0.Add(2 * time.Minute), Class: watch.ClassSSH, Op: watch.OpWrite, Path: keys, SHA256: "aaaa"},
		},
		"/tmp/.bench-dropper":              {{At: t0, Class: watch.ClassScratch, Op: watch.OpAttrib, Path: "/tmp/.bench-dropper", Mode: "-rwxr-xr-x", UID: &root0}},
		"/etc/ld.so.conf.d/zz.conf":        {{At: t0, Class: watch.ClassHook, Op: watch.OpCreate, Path: "/etc/ld.so.conf.d/zz.conf"}},
		"/srv/app/uploads/old.php":         {{At: t0.Add(-time.Hour), Class: watch.ClassUpload, Op: watch.OpCreate, Path: "/srv/app/uploads/old.php"}},
		"/srv/app/public/health_check.php": {{At: t0.Add(-time.Minute), Class: watch.ClassWebRoot, Op: watch.OpCreate, Path: "/srv/app/public/health_check.php"}},
		// A file unchanged for months, then a key added: the sensor knew the content before it.
		oldKeys: {{At: t0.Add(time.Minute), Class: watch.ClassSSH, Op: watch.OpWrite, Path: oldKeys, SHA256: "1111", PrevSHA256: "0000"}},
	}
	history := func(p string, since time.Time) []watch.Event {
		var out []watch.Event
		for _, e := range past[p] {
			if !e.At.Before(since) {
				out = append(out, e)
			}
		}
		return out
	}
	for _, tc := range []struct {
		name           string
		event          watch.Event
		packageManager bool
		want           string // rule and severity, or "" for no alert
	}{
		{"web shell", watch.Event{Class: watch.ClassExec, Reason: watch.ReasonWebShell, Exe: "/usr/bin/bash", User: &uid}, true, "webshell critical"},
		{"exec from tmp", watch.Event{Class: watch.ClassExec, Reason: watch.ReasonUnusualPath, Exe: "/tmp/x"}, false, "unusual-exec high"},
		{"sudoers", watch.Event{Class: watch.ClassPrivilege, Op: watch.OpCreate, Path: "/etc/sudoers.d/backdoor"}, false, "privilege-config critical"},
		{"sudoers while upgrading", watch.Event{Class: watch.ClassPrivilege, Op: watch.OpWrite, Path: "/etc/sudoers"}, true, "privilege-config critical"},
		{"unit while upgrading", watch.Event{Class: watch.ClassService, Op: watch.OpCreate, Path: "/etc/systemd/system/x.service"}, true, "service medium"},
		{"preload", watch.Event{Class: watch.ClassHook, Op: watch.OpWrite, Path: "/etc/ld.so.preload"}, false, "preload critical"},
		{"home rc", watch.Event{Class: watch.ClassHook, Op: watch.OpWrite, Path: "/home/alice/.bashrc"}, false, "hook medium"},
		{"sshrc", watch.Event{Class: watch.ClassHook, Op: watch.OpCreate, Path: "/etc/ssh/sshrc"}, false, "hook high"},
		{"ssh rc of an account", watch.Event{Class: watch.ClassSSH, Op: watch.OpWrite, Path: "/home/alice/.ssh/rc"}, false, "hook medium"},
		{"network hook", watch.Event{Class: watch.ClassHook, Op: watch.OpCreate, Path: "/etc/network/if-up.d/x"}, false, "hook high"},
		{"bash completion", watch.Event{Class: watch.ClassHook, Op: watch.OpCreate, Path: "/etc/bash_completion.d/x"}, false, "hook high"},
		{"loader path", watch.Event{Class: watch.ClassHook, Op: watch.OpCreate, Path: "/etc/ld.so.conf.d/x.conf"}, false, "loader-config high"},
		{"loader path while upgrading", watch.Event{Class: watch.ClassHook, Op: watch.OpCreate, Path: "/etc/ld.so.conf.d/x.conf"}, true, "loader-config medium"},
		{"loader path put back", watch.Event{At: t0.Add(time.Minute), Class: watch.ClassHook, Op: watch.OpDelete, Path: "/etc/ld.so.conf.d/zz.conf"}, false, "loader-transient critical"},
		{"old loader path removed", watch.Event{At: t0.Add(time.Minute), Class: watch.ClassHook, Op: watch.OpDelete, Path: "/etc/ld.so.conf.d/old.conf"}, false, "removed medium"},
		{"package temp in loader dir", watch.Event{Class: watch.ClassHook, Op: watch.OpCreate, Path: "/etc/ld.so.conf.d/x.conf.dpkg-new"}, false, ""},
		{"chmod sudoers group writable", watch.Event{Class: watch.ClassPrivilege, Op: watch.OpAttrib, Path: "/etc/sudoers", Mode: "-rw-rw-r--"}, false, "privilege-config critical"},
		{"touch sudoers", watch.Event{Class: watch.ClassPrivilege, Op: watch.OpAttrib, Path: "/etc/sudoers", Mode: "-r--r-----"}, false, ""},
		{"unit removed", watch.Event{Class: watch.ClassService, Op: watch.OpDelete, Path: "/etc/systemd/system/x.service"}, false, ""},
		{"unit disabled", watch.Event{Class: watch.ClassService, Op: watch.OpDelete, Path: "/etc/systemd/system/multi-user.target.wants/auditd.service"}, false, "removed low"},
		{"sudoers.d file removed", watch.Event{Class: watch.ClassPrivilege, Op: watch.OpDelete, Path: "/etc/sudoers.d/ops"}, false, "removed medium"},
		{"atomic write temp", watch.Event{Class: watch.ClassService, Op: watch.OpCreate, Path: "/run/systemd/system/netplan-ovs-cleanup.service.MA2FX3"}, false, ""},
		{"netplan output", watch.Event{Class: watch.ClassService, Op: watch.OpCreate, Path: "/run/systemd/system/netplan-ovs-cleanup.service"}, false, ""},
		{"netplan drop-in", watch.Event{Class: watch.ClassService, Op: watch.OpCreate, Path: "/run/systemd/system/systemd-networkd-wait-online.service.d/10-netplan.conf"}, false, ""},
		{"netplan link removed", watch.Event{Class: watch.ClassService, Op: watch.OpDelete, Path: "/run/systemd/system/systemd-networkd.service.wants/netplan-ovs-cleanup.service"}, false, ""},
		{"netplan name in /etc", watch.Event{Class: watch.ClassService, Op: watch.OpCreate, Path: "/etc/systemd/system/netplan-x.service"}, false, "service high"},
		{"drop-in", watch.Event{Class: watch.ClassService, Op: watch.OpCreate, Path: "/etc/systemd/system/nginx.service.d/override.conf"}, false, "service high"},
		{"generator", watch.Event{Class: watch.ClassService, Op: watch.OpCreate, Path: "/etc/systemd/system-generators/x"}, false, "service high"},
		{"image upload", watch.Event{Class: watch.ClassUpload, Op: watch.OpCreate, Path: "/srv/app/uploads/a.jpg"}, false, ""},
		{"htaccess upload", watch.Event{Class: watch.ClassUpload, Op: watch.OpCreate, Path: "/srv/app/uploads/.htaccess"}, true, "upload-script high"},
		{"old script removed", watch.Event{At: t0, Class: watch.ClassUpload, Op: watch.OpDelete, Path: "/srv/app/uploads/old.php"}, false, ""},
		{"probe gone from the web root", watch.Event{At: t0, Class: watch.ClassWebRoot, Op: watch.OpDelete, Path: "/srv/app/public/health_check.php"}, false, "webroot-transient critical"},
		{"script deployed to the web root", watch.Event{At: t0, Class: watch.ClassWebRoot, Op: watch.OpCreate, Path: "/srv/app/public/index.php"}, false, ""},
		{"old script removed from the web root", watch.Event{At: t0, Class: watch.ClassWebRoot, Op: watch.OpDelete, Path: "/srv/app/public/old.php"}, false, ""},
		{"key put back", watch.Event{At: t0.Add(2 * time.Minute), Class: watch.ClassSSH, Op: watch.OpWrite, Path: keys, SHA256: "aaaa"}, false, "ssh-transient critical"},
		{"key added", watch.Event{At: t0.Add(time.Minute), Class: watch.ClassSSH, Op: watch.OpWrite, Path: keys, SHA256: "bbbb"}, false, "ssh-keys high"},
		{"key removed from an old file", watch.Event{At: t0.Add(2 * time.Minute), Class: watch.ClassSSH, Op: watch.OpWrite, Path: oldKeys, SHA256: "0000", PrevSHA256: "1111"}, false, "ssh-transient critical"},
		{"known hosts", watch.Event{Class: watch.ClassSSH, Op: watch.OpWrite, Path: "/root/.ssh/known_hosts"}, false, ""},
		{"executable in tmp", watch.Event{Class: watch.ClassScratch, Op: watch.OpAttrib, Path: "/tmp/.x", Mode: "-rwxr-xr-x", UID: &web33, WebUser: true}, false, "scratch-exec:uid33 high"},
		{"build output in tmp", watch.Event{Class: watch.ClassScratch, Op: watch.OpAttrib, Path: "/tmp/go-build1/a.out", Mode: "-rwxr-xr-x", UID: &dev1000}, false, "scratch-exec:uid1000 medium"},
		{"plain file in tmp", watch.Event{Class: watch.ClassScratch, Op: watch.OpCreate, Path: "/tmp/sess", Mode: "-rw-------"}, false, ""},
		{"dropper removed", watch.Event{At: t0.Add(time.Minute), Class: watch.ClassScratch, Op: watch.OpDelete, Path: "/tmp/.bench-dropper"}, false, "scratch-transient:uid0 critical"},
		{"watched root moved", watch.Event{Class: watch.ClassUpload, Op: watch.OpDelete, Path: "/srv/app/uploads", Dir: true, Root: true}, false, "watch-root:upload high"},
		{"directory", watch.Event{Class: watch.ClassSchedule, Op: watch.OpCreate, Path: "/var/spool/cron/x", Dir: true}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ""
			if fs := EvaluateEvents([]watch.Event{tc.event}, tc.packageManager, history); len(fs) == 1 {
				f := fs[0]
				fp, _, _ := strings.Cut(f.Fingerprint, " sha256:")
				fp, _, _ = strings.Cut(fp, " at:")
				fp, _, _ = strings.Cut(fp, "#")
				if strings.HasPrefix(fp, EventKind+":watch-root:") {
					fp, _, _ = strings.Cut(fp, "|")
				}
				rule := fp[len(EventKind)+1:]
				rule = rule[:len(rule)-len(tc.event.Path)-len(tc.event.Exe)-1]
				got = rule + " " + f.Severity
				if f.Kind != EventKind || f.Title == "" || f.Detail == "" {
					t.Errorf("finding %+v", f)
				}
			} else if len(fs) > 1 {
				t.Fatalf("%d findings", len(fs))
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Each account's drops in the scratch directories are a group of their own, whatever the file is
// named: a "|" in a user's file name does not land the alert in root's group.
func TestScratchGroupsByOwner(t *testing.T) {
	user, root := uint32(1000), uint32(0)
	fp := func(uid uint32, name string) string {
		f, ok := judgeEvent(watch.Event{Class: watch.ClassScratch, Op: watch.OpAttrib, Path: "/tmp/" + name, Mode: "-rwxr-xr-x", UID: &uid}, nil)
		if !ok {
			t.Fatalf("no finding for %s", name)
		}
		return f.Fingerprint
	}
	groupOf := func(f string) string { g, _, _ := strings.Cut(f, "|"); return g }
	if u, r := groupOf(fp(user, "x|uid0|y")), groupOf(fp(root, "x")); u == r || !strings.HasSuffix(u, "uid1000") || !strings.HasSuffix(r, "uid0") {
		t.Errorf("groups: user %q, root %q", u, r)
	}
}

// A hook installed while a package manager of root held its lock, the event saying so even when
// the batch left after it, is lowered; its staging names raise nothing then, and the same names
// without a package manager do.
func TestHookInstalledByAPackage(t *testing.T) {
	ev := func(p string, pm bool) watch.Event {
		return watch.Event{At: time.Now(), Class: watch.ClassHook, Op: watch.OpCreate, Path: p, SHA256: strings.Repeat("a", 64), PackageManager: pm}
	}
	got := EvaluateEvents([]watch.Event{ev("/etc/profile.d/x.sh.dpkg-new", true), ev("/etc/profile.d/x.sh", true)}, false, nil)
	if len(got) != 1 || got[0].Severity != "medium" || !strings.Contains(got[0].Fingerprint, "/etc/profile.d/x.sh ") {
		t.Errorf("with a package manager: %+v", got)
	}
	if got := EvaluateEvents([]watch.Event{ev("/etc/profile.d/x.sh.dpkg-new", false)}, false, nil); len(got) != 1 || got[0].Severity != "high" {
		t.Errorf("without one: %+v", got)
	}
}

// A package manager running does not lower another user's crontab or start-up file: the web
// server's user can read when apt holds its lock.
func TestPackageManagerLowersOnlyRootsFiles(t *testing.T) {
	web := uint32(33)
	at := time.Now()
	for name, e := range map[string]watch.Event{
		"crontab":   {At: at, Class: watch.ClassSchedule, Op: watch.OpWrite, Path: "/var/spool/cron/crontabs/www-data", SHA256: strings.Repeat("d", 64), UID: &web, Owner: "www-data"},
		"bashrc":    {At: at, Class: watch.ClassHook, Op: watch.OpWrite, Path: "/var/www/.bashrc", SHA256: strings.Repeat("e", 64), UID: &web, Owner: "www-data"},
		"user unit": {At: at, Class: watch.ClassService, Op: watch.OpCreate, Path: "/var/www/.config/systemd/user/x.service", SHA256: strings.Repeat("f", 64), UID: &web, Owner: "www-data"},
	} {
		with, without := EvaluateEvents([]watch.Event{e}, true, nil), EvaluateEvents([]watch.Event{e}, false, nil)
		if len(with) != 1 || len(without) != 1 || with[0].Severity != without[0].Severity {
			t.Errorf("%s: %+v with a package manager, %+v without", name, with, without)
		}
	}
}

// The staging names hide nothing in the scratch directories: there the web server's user, who can
// read when apt holds its lock, would drop, run and remove a program under one. Root's own files
// there are still lowered while a package manager runs.
func TestStagingNamesNotInScratch(t *testing.T) {
	web, root := uint32(33), uint32(0)
	at := time.Now()
	drop := []watch.Event{
		{At: at, Class: watch.ClassScratch, Op: watch.OpCreate, Path: "/dev/shm/.x.dpkg-new", SHA256: strings.Repeat("b", 64), Mode: "-rwxr-xr-x", UID: &web, WebUser: true, PackageManager: true},
		{At: at.Add(time.Second), Class: watch.ClassScratch, Op: watch.OpDelete, Path: "/dev/shm/.x.dpkg-new", PackageManager: true},
	}
	history := func(string, time.Time) []watch.Event { return drop[:1] }
	got := EvaluateEvents(drop, true, history)
	if len(got) == 0 || got[0].Severity == "low" {
		t.Errorf("the web user's drop under a staging name: %+v", got)
	}
	mine := watch.Event{At: at, Class: watch.ClassScratch, Op: watch.OpCreate, Path: "/tmp/apt.conf.x", SHA256: strings.Repeat("c", 64), Mode: "-rwxr-xr-x", UID: &root, PackageManager: true}
	theirs := mine
	theirs.UID, theirs.WebUser = &web, true
	a, b := EvaluateEvents([]watch.Event{mine}, true, nil), EvaluateEvents([]watch.Event{theirs}, true, nil)
	lowered := func(f []Finding) bool {
		return len(f) == 1 && strings.Contains(f[0].Detail, "A package manager was running")
	}
	if !lowered(a) || lowered(b) {
		t.Errorf("root's file lowered %v, the web user's %v", lowered(a), lowered(b))
	}
}
