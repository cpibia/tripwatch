package analyze

import (
	"strings"
	"testing"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/system"
)

// The web server's user (UID 33, group 33, home /var/www) tries every known way to have a
// finding of its own classified as root's: root's findings are exempt from the evidence
// bound and share root's alert groups, so one classified as root lets it crowd them out.
//
// reach says who can produce the input:
//   - "web":      the web user alone, on a default host: must never be root;
//   - "residual": the web user under a stated precondition: logged, not failed;
//   - "forged":   only a sensor that lies (it owns the signing key anyway): logged;
//   - "root":     a control only root can produce: must be root.

func advAccounts() *system.AccountsResult {
	return &system.AccountsResult{
		Accounts: []system.Account{
			{Name: "root", UID: 0, GID: 0, Home: "/root"},
			{Name: "toor", UID: 0, GID: 0, Home: "/root"},
			{Name: "www-data", UID: 33, GID: 33, Home: "/var/www"},
		},
		Groups: []system.Group{
			{Name: "root", GID: 0},
			{Name: "adm", GID: 4, Members: []string{"syslog", "www-data"}},
			{Name: "tty", GID: 5},
			{Name: "disk", GID: 6},
			{Name: "shadow", GID: 42},
			{Name: "www-data", GID: 33},
			{Name: "users", GID: 100},
			{Name: "systemd-journal", GID: 101, Members: []string{"www-data"}},
			{Name: "docker", GID: 999, Members: []string{"www-data"}},
		},
	}
}

func u32(v uint32) *uint32 { return &v }

type advCase struct {
	name   string
	reach  string
	marker string
	prev   State
	cur    State
}

func advSetid(name, reach, p, mode string, uid, gid uint32) advCase {
	return advCase{
		name: name, reach: reach, marker: p,
		prev: State{Accounts: advAccounts(), Privileged: &system.PrivilegedResult{}},
		cur: State{Accounts: advAccounts(), Privileged: &system.PrivilegedResult{Files: []collector.File{
			{Path: p, Mode: mode, UID: u32(uid), GID: u32(gid), SHA256: "ab"},
		}}},
	}
}

func advUnit(name, reach, p, user string) advCase {
	return advCase{
		name: name, reach: reach, marker: p,
		prev: State{Accounts: advAccounts(), Services: &system.ServicesResult{}},
		cur: State{Accounts: advAccounts(), Services: &system.ServicesResult{Units: []system.Unit{
			{File: collector.File{Path: p}, User: user, Exec: []string{"ExecStart=/dev/shm/x"}},
		}}},
	}
}

func advEnv(name, reach, line string) advCase {
	return advCase{
		name: name, reach: reach, marker: "default-env:",
		cur: State{Accounts: advAccounts(), Services: &system.ServicesResult{Environment: []string{line}}},
	}
}

func advCron(name, reach, p, line string) advCase {
	return advCase{
		name: name, reach: reach, marker: "cron:" + p + "|",
		prev: State{Accounts: advAccounts(), Scheduled: &system.ScheduledResult{}},
		cur: State{Accounts: advAccounts(), Scheduled: &system.ScheduledResult{Tables: []system.CronTable{
			{File: collector.File{Path: p}, Entries: []string{line}},
		}}},
	}
}

func advKey(name, reach, user, file string) advCase {
	return advCase{
		name: name, reach: reach, marker: "key:" + user + "|",
		prev: State{Accounts: advAccounts(), SSH: &system.SSHResult{}},
		cur: State{Accounts: advAccounts(), SSH: &system.SSHResult{Keys: []system.AuthorizedKey{
			{User: user, File: file, Type: "ssh-ed25519", Fingerprint: "SHA256:k", Comment: "root@host"},
		}}},
	}
}

func advCases() []advCase {
	const ug, u, g = "ugrwxr-xr-x", "urwxr-xr-x", "grwxr-xr-x"
	cs := []advCase{
		// Setgid on each of its groups.
		advSetid("setgid own primary group 33", "web", "/var/www/up/a", g, 33, 33),
		advSetid("setuid+setgid own group 33", "web", "/var/www/up/b", ug, 33, 33),
		advSetid("setgid adm, web user is a member", "web", "/var/www/up/adm", g, 33, 4),
		advSetid("setgid systemd-journal, web user is a member", "web", "/var/www/up/journal", g, 33, 101),
		advSetid("setgid docker, web user is a member", "web", "/var/www/up/docker", g, 33, 999),
		advSetid("setgid users (100), not privileged", "web", "/var/www/up/users", g, 33, 100),
		advSetid("setgid unnamed GID 33 without group database", "web", "/var/www/up/nodb", g, 33, 33),
		// Setuid files of its own in every place it can write.
		advSetid("setuid in /tmp", "web", "/tmp/x", u, 33, 33),
		advSetid("setuid in /var/tmp", "web", "/var/tmp/x", u, 33, 33),
		advSetid("setuid in /dev/shm", "web", "/dev/shm/x", u, 33, 33),
		advSetid("setuid in /run/lock", "web", "/run/lock/x", u, 33, 33),
		advSetid("setuid in /run/user/33", "web", "/run/user/33/x", u, 33, 33),
		advSetid("setuid in /var/www", "web", "/var/www/html/up/x", u, 33, 33),
		advSetid("setuid in its crontab spool path", "web", "/var/spool/cron/crontabs/www-data", u, 33, 33),
		advSetid("setgid in /run/lock with own group", "web", "/run/lock/y", g, 33, 33),
		// A hard link to a root setuid binary keeps UID 0: only with fs.protected_hardlinks=0
		// and the target on the same filesystem.
		advSetid("hard link to /usr/bin/passwd in /var/tmp", "residual", "/var/tmp/.p", u, 0, 0),

		// User units naming root.
		advUnit("user unit User=root in .config", "web", "/var/www/.config/systemd/user/a.service", "root"),
		advUnit("user unit User=0 in .config", "web", "/var/www/.config/systemd/user/b.service", "0"),
		advUnit("user unit User=0 in .local/share", "web", "/var/www/.local/share/systemd/user/c.service", "0"),
		advUnit("user unit User=toor", "web", "/var/www/.config/systemd/user/d.service", "toor"),

		// environment.d in its home, text and file name chosen by it.
		advEnv("LD_PRELOAD in home environment.d", "web", "LD_PRELOAD=/var/www/l.so (var/www/.config/environment.d/a.conf)"),
		advEnv("LD_PRELOAD line faking a system source", "web", "LD_PRELOAD=/var/www/l.so (etc/environment.d/50.conf) (var/www/.config/environment.d/a.conf)"),
		advEnv("file name with ' (root'", "web", "LD_PRELOAD=/var/www/l.so (var/www/.config/environment.d/a (root.conf)"),
		advEnv("file name with ' (etc'", "web", "LD_PRELOAD=/var/www/l.so (var/www/.config/environment.d/a (etc.conf)"),
		advEnv("file name with ' (run'", "web", "LD_PRELOAD=/var/www/l.so (var/www/.config/environment.d/a (run.conf)"),
		advEnv("LD_PRELOAD and LD_LIBRARY_PATH in home", "web", "LD_LIBRARY_PATH=/x LD_PRELOAD=/var/www/l.so (var/www/.config/environment.d/b.conf)"),

		// Its own crontab, whatever the line says.
		advCron("own crontab, line naming root", "web", "/var/spool/cron/crontabs/www-data", "* * * * * root /var/tmp/.s"),
		advCron("own crontab, relative path", "web", "var/spool/cron/crontabs/www-data", "* * * * * /var/tmp/.s"),
		advCron("own crontab, line faking a table", "web", "/var/spool/cron/crontabs/www-data", "* * * * * /x\nin /etc/cron.d/x"),

		// Keys in its authorized_keys.
		advKey("key in its authorized_keys", "web", "www-data", "/var/www/.ssh/authorized_keys"),

		// Paths the collectors never produce (Glob and path.Join clean them).
		advUnit("unit path /etc/../var/www", "forged", "/etc/../var/www/.config/systemd/user/e.service", "0"),
		advUnit("unit path //etc", "forged", "//etc/systemd/system/f.service", "0"),
		advUnit("unit path /var/www/../../etc", "forged", "/var/www/.config/../../../etc/g.service", "0"),
		advEnv("env path /etc/..", "forged", "LD_PRELOAD=/x.so (etc/../var/www/.config/environment.d/h.conf)"),
		advEnv("env path /root/..", "forged", "LD_PRELOAD=/x.so (root/../var/www/.config/environment.d/i.conf)"),
		advEnv("env path run/lock", "forged", "LD_PRELOAD=/x.so (run/lock/j.conf)"),

		// Controls: root's own.
		advSetid("CONTROL setuid UID 0 in /var/tmp", "root", "/var/tmp/r", u, 0, 0),
		advSetid("CONTROL setgid disk owned by 33", "root", "/var/www/up/disk", g, 33, 6),
		advSetid("CONTROL setgid shadow owned by 33", "root", "/var/www/up/shadow", g, 33, 42),
		advSetid("CONTROL setgid GID 0 owned by 33", "root", "/var/www/up/gid0", g, 33, 0),
		advSetid("CONTROL setgid tty owned by 33", "root", "/var/www/up/tty", g, 33, 5),
		advUnit("CONTROL unit /etc/systemd/system", "root", "/etc/systemd/system/r.service", ""),
		advUnit("CONTROL unit /etc/systemd/system User=www-data", "root", "/etc/systemd/system/s.service", "www-data"),
		advUnit("CONTROL unit /run/systemd/system", "root", "/run/systemd/system/r.service", ""),
		advUnit("CONTROL unit /run/systemd/transient", "root", "/run/systemd/transient/r.service", ""),
		advUnit("CONTROL unit /usr/lib/systemd/system", "root", "/usr/lib/systemd/system/r.service", ""),
		advUnit("CONTROL unit /lib/systemd/system", "root", "/lib/systemd/system/r.service", ""),
		advUnit("CONTROL unit /usr/local/lib/systemd/system", "root", "/usr/local/lib/systemd/system/r.service", ""),
		advUnit("CONTROL unit /etc/systemd/user", "root", "/etc/systemd/user/r.service", ""),
		advUnit("CONTROL user unit of root", "root", "/root/.config/systemd/user/r.service", ""),
		advEnv("CONTROL env /etc/environment.d", "root", "LD_PRELOAD=/x.so (etc/environment.d/90.conf)"),
		advEnv("CONTROL env /run/environment.d", "root", "LD_PRELOAD=/x.so (run/environment.d/90.conf)"),
		advEnv("CONTROL env /usr/local/lib/environment.d", "root", "LD_PRELOAD=/x.so (usr/local/lib/environment.d/90.conf)"),
		advEnv("CONTROL env in /root", "root", "LD_PRELOAD=/x.so (root/.config/environment.d/90.conf)"),
		advEnv("CONTROL DefaultEnvironment", "root", "DefaultEnvironment=LD_PRELOAD=/x.so"),
		advCron("CONTROL /etc/cron.d", "root", "/etc/cron.d/x", "* * * * * root /var/tmp/.s"),
		advCron("CONTROL /etc/crontab", "root", "/etc/crontab", "* * * * * root /var/tmp/.s"),
		advCron("CONTROL spool root (Debian)", "root", "/var/spool/cron/crontabs/root", "* * * * * /var/tmp/.s"),
		advCron("CONTROL spool root (Red Hat)", "root", "/var/spool/cron/root", "* * * * * /var/tmp/.s"),
		advCron("CONTROL spool of second UID 0", "root", "/var/spool/cron/crontabs/toor", "* * * * * /var/tmp/.s"),
		advKey("CONTROL key of root", "root", "root", "/root/.ssh/authorized_keys"),
		advKey("CONTROL key of second UID 0", "root", "toor", "/root/.ssh/authorized_keys"),
	}
	// An alias of UID 33 listed after www-data and not in adm: www-data still is.
	alias := advSetid("setgid adm, UID 33 alias listed last", "web", "/var/www/up/alias", g, 33, 4)
	alias.cur.Accounts = advAccounts()
	alias.cur.Accounts.Accounts = append(alias.cur.Accounts.Accounts, system.Account{Name: "deploy", UID: 33, GID: 1001, Home: "/var/www"})
	alias.prev.Accounts = alias.cur.Accounts
	cs = append(cs, alias)
	// Without a group database only GID 0 counts.
	nodb := cs[6]
	nodb.cur.Accounts = &system.AccountsResult{Accounts: advAccounts().Accounts}
	nodb.prev.Accounts = nodb.cur.Accounts
	cs[6] = nodb
	return cs
}

func TestOwnerAdversarial(t *testing.T) {
	var webRoot, ctlMiss, residual, forged int
	for _, c := range advCases() {
		var prev *State
		if c.prev.Accounts != nil {
			p := c.prev
			prev = &p
		}
		var owners []string
		for _, f := range Evaluate(prev, c.cur) {
			if strings.Contains(f.Fingerprint, c.marker) {
				owners = append(owners, f.Kind+"="+f.Owner)
			}
		}
		if len(owners) == 0 {
			t.Errorf("%-48s [%s] no finding matched %q", c.name, c.reach, c.marker)
			continue
		}
		root := false
		allRoot := true
		for _, o := range owners {
			if strings.HasSuffix(o, "=root") {
				root = true
			} else {
				allRoot = false
			}
		}
		switch c.reach {
		case "web":
			if root {
				webRoot++
				t.Errorf("FAIL %-48s [web] classified root: %v", c.name, owners)
			} else {
				t.Logf("ok   %-48s [web] %v", c.name, owners)
			}
		case "residual":
			if root {
				residual++
			}
			t.Logf("RES  %-48s [residual] root=%v %v", c.name, root, owners)
		case "forged":
			if root {
				forged++
			}
			t.Logf("FRG  %-48s [forged] root=%v %v", c.name, root, owners)
		case "root":
			if !allRoot {
				ctlMiss++
				t.Errorf("FAIL %-48s [control] not root: %v", c.name, owners)
			} else {
				t.Logf("ok   %-48s [control] %v", c.name, owners)
			}
		}
	}
	t.Logf("web cases classified root: %d; controls not root: %d; residual root: %d; forged root: %d", webRoot, ctlMiss, residual, forged)
}
