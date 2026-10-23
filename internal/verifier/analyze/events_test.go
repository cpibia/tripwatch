package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/watch"
)

func TestEvaluateEvents(t *testing.T) {
	t0 := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	uid := 33
	keys := "/root/.ssh/authorized_keys"
	oldKeys := "/home/ops/.ssh/authorized_keys"
	past := map[string][]watch.Event{
		keys: {
			{At: t0, Class: watch.ClassSSH, Op: watch.OpWrite, Path: keys, SHA256: "aaaa"},
			{At: t0.Add(time.Minute), Class: watch.ClassSSH, Op: watch.OpWrite, Path: keys, SHA256: "bbbb"},
			{At: t0.Add(2 * time.Minute), Class: watch.ClassSSH, Op: watch.OpWrite, Path: keys, SHA256: "aaaa"},
		},
		"/tmp/.bench-dropper":      {{At: t0, Class: watch.ClassScratch, Op: watch.OpAttrib, Path: "/tmp/.bench-dropper", Mode: "-rwxr-xr-x"}},
		"/srv/app/uploads/old.php": {{At: t0.Add(-time.Hour), Class: watch.ClassUpload, Op: watch.OpCreate, Path: "/srv/app/uploads/old.php"}},
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
		{"chmod sudoers group writable", watch.Event{Class: watch.ClassPrivilege, Op: watch.OpAttrib, Path: "/etc/sudoers", Mode: "-rw-rw-r--"}, false, "privilege-config critical"},
		{"touch sudoers", watch.Event{Class: watch.ClassPrivilege, Op: watch.OpAttrib, Path: "/etc/sudoers", Mode: "-r--r-----"}, false, ""},
		{"unit removed", watch.Event{Class: watch.ClassService, Op: watch.OpDelete, Path: "/etc/systemd/system/x.service"}, false, ""},
		{"unit disabled", watch.Event{Class: watch.ClassService, Op: watch.OpDelete, Path: "/etc/systemd/system/multi-user.target.wants/auditd.service"}, false, "removed low"},
		{"sudoers.d file removed", watch.Event{Class: watch.ClassPrivilege, Op: watch.OpDelete, Path: "/etc/sudoers.d/ops"}, false, "removed medium"},
		{"atomic write temp", watch.Event{Class: watch.ClassService, Op: watch.OpCreate, Path: "/run/systemd/system/netplan-ovs-cleanup.service.MA2FX3"}, false, ""},
		{"drop-in", watch.Event{Class: watch.ClassService, Op: watch.OpCreate, Path: "/etc/systemd/system/nginx.service.d/override.conf"}, false, "service high"},
		{"generator", watch.Event{Class: watch.ClassService, Op: watch.OpCreate, Path: "/etc/systemd/system-generators/x"}, false, "service high"},
		{"image upload", watch.Event{Class: watch.ClassUpload, Op: watch.OpCreate, Path: "/srv/app/uploads/a.jpg"}, false, ""},
		{"htaccess upload", watch.Event{Class: watch.ClassUpload, Op: watch.OpCreate, Path: "/srv/app/uploads/.htaccess"}, true, "upload-script high"},
		{"old script removed", watch.Event{At: t0, Class: watch.ClassUpload, Op: watch.OpDelete, Path: "/srv/app/uploads/old.php"}, false, ""},
		{"key put back", watch.Event{At: t0.Add(2 * time.Minute), Class: watch.ClassSSH, Op: watch.OpWrite, Path: keys, SHA256: "aaaa"}, false, "ssh-transient critical"},
		{"key added", watch.Event{At: t0.Add(time.Minute), Class: watch.ClassSSH, Op: watch.OpWrite, Path: keys, SHA256: "bbbb"}, false, "ssh-keys high"},
		{"key removed from an old file", watch.Event{At: t0.Add(2 * time.Minute), Class: watch.ClassSSH, Op: watch.OpWrite, Path: oldKeys, SHA256: "0000", PrevSHA256: "1111"}, false, "ssh-transient critical"},
		{"known hosts", watch.Event{Class: watch.ClassSSH, Op: watch.OpWrite, Path: "/root/.ssh/known_hosts"}, false, ""},
		{"executable in tmp", watch.Event{Class: watch.ClassScratch, Op: watch.OpAttrib, Path: "/tmp/.x", Mode: "-rwxr-xr-x"}, false, "scratch-exec high"},
		{"plain file in tmp", watch.Event{Class: watch.ClassScratch, Op: watch.OpCreate, Path: "/tmp/sess", Mode: "-rw-------"}, false, ""},
		{"dropper removed", watch.Event{At: t0.Add(time.Minute), Class: watch.ClassScratch, Op: watch.OpDelete, Path: "/tmp/.bench-dropper"}, false, "scratch-transient critical"},
		{"directory", watch.Event{Class: watch.ClassSchedule, Op: watch.OpCreate, Path: "/var/spool/cron/x", Dir: true}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ""
			if fs := EvaluateEvents([]watch.Event{tc.event}, tc.packageManager, history); len(fs) == 1 {
				f := fs[0]
				fp, _, _ := strings.Cut(f.Fingerprint, " sha256:")
				fp, _, _ = strings.Cut(fp, " at:")
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
