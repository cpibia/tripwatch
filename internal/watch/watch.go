// Package watch reports, as they happen, the changes that snapshots taken an hour apart can
// miss: a key added and removed, a script dropped in an upload directory and deleted after use.
// It only observes and reports; the verifier judges.
package watch

import (
	"errors"
	"path"
	"strings"
	"time"
)

// Classes of watched paths, which the verifier's rules key on.
const (
	ClassAccounts  = "accounts"
	ClassSSH       = "ssh"
	ClassPrivilege = "privilege"
	ClassSchedule  = "schedule"
	ClassService   = "service"
	ClassHook      = "hook"
	ClassUpload    = "upload"
)

// Operations on a watched path.
const (
	OpCreate = "create"
	OpWrite  = "write"
	OpDelete = "delete"
	OpAttrib = "attrib"
)

// Event is one change seen on a watched path. Paths are absolute in the observed root; size,
// hash, owner and mode are read after the change, through the same confined view of the
// filesystem the collectors use, and only for regular files within the hashing limit.
type Event struct {
	At     time.Time `json:"at"`
	Class  string    `json:"class"`
	Op     string    `json:"op"`
	Path   string    `json:"path"`
	Dir    bool      `json:"dir,omitempty"`
	Size   int64     `json:"size,omitempty"`
	SHA256 string    `json:"sha256,omitempty"`
	UID    *uint32   `json:"uid,omitempty"`
	Mode   string    `json:"mode,omitempty"`
}

// Target is a directory to watch. Names, when set, keeps only the entries with those names;
// Recursive also watches the subdirectories, those created later included, down to MaxDepth.
// Spawn gives the target of a named subdirectory that may be created later, such as a home's
// .ssh.
type Target struct {
	Dir       string
	Class     string
	Names     []string
	Recursive bool
	Spawn     map[string]Target
}

// Bounds: watches cost kernel memory, and upload trees can be deep and wide.
const (
	MaxWatches = 8192
	MaxDepth   = 4
)

// ErrUnsupported is returned where the kernel interfaces the watcher needs do not exist.
var ErrUnsupported = errors.New("watch: real-time events need Linux")

// Home is an account's home directory, for the files in it that grant or keep access.
type Home struct {
	User string
	Dir  string
}

// rcFiles are the shell start-up files of a home: code put there runs at each login.
var rcFiles = []string{".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".cshrc", ".tcshrc"}

// Targets lists what to watch on a host: the system's fixed places, the homes of its accounts
// and the upload directories of its web applications.
func Targets(homes []Home, uploads []string) []Target {
	t := []Target{
		{Dir: "/etc", Class: ClassAccounts, Names: []string{"passwd", "shadow", "group", "gshadow"}},
		{Dir: "/etc", Class: ClassPrivilege, Names: []string{"sudoers", "doas.conf"}},
		{Dir: "/etc", Class: ClassHook, Names: []string{"ld.so.preload", "rc.local", "profile", "bash.bashrc", "environment"}},
		{Dir: "/etc", Class: ClassSchedule, Names: []string{"crontab", "anacrontab"}},
		{Dir: "/etc/sudoers.d", Class: ClassPrivilege},
		{Dir: "/etc/polkit-1", Class: ClassPrivilege, Recursive: true},
		{Dir: "/usr/share/polkit-1/rules.d", Class: ClassPrivilege},
		{Dir: "/etc/ssh", Class: ClassSSH, Names: []string{"sshd_config"}},
		{Dir: "/etc/ssh/sshd_config.d", Class: ClassSSH},
		{Dir: "/etc/cron.d", Class: ClassSchedule},
		{Dir: "/etc/cron.hourly", Class: ClassSchedule},
		{Dir: "/etc/cron.daily", Class: ClassSchedule},
		{Dir: "/etc/cron.weekly", Class: ClassSchedule},
		{Dir: "/etc/cron.monthly", Class: ClassSchedule},
		{Dir: "/var/spool/cron", Class: ClassSchedule, Recursive: true},
		{Dir: "/var/spool/at", Class: ClassSchedule, Recursive: true},
		{Dir: "/etc/systemd/system", Class: ClassService, Recursive: true},
		{Dir: "/run/systemd/system", Class: ClassService, Recursive: true},
		{Dir: "/etc/systemd/system-generators", Class: ClassService},
		{Dir: "/usr/local/lib/systemd/system-generators", Class: ClassService},
		{Dir: "/etc/profile.d", Class: ClassHook},
		{Dir: "/etc/pam.d", Class: ClassHook},
		{Dir: "/etc/update-motd.d", Class: ClassHook},
	}
	seen := map[string]bool{}
	for _, h := range homes {
		dir := path.Clean(h.Dir)
		if dir == "/" || dir == "." || !strings.HasPrefix(dir, "/") || seen[dir] || strings.HasPrefix(dir, "/nonexistent") {
			continue
		}
		seen[dir] = true
		ssh := Target{Dir: dir + "/.ssh", Class: ClassSSH}
		t = append(t,
			Target{Dir: dir, Class: ClassHook, Names: append(append([]string{}, rcFiles...), ".ssh"), Spawn: map[string]Target{".ssh": ssh}},
			ssh)
	}
	for _, u := range uploads {
		dir := path.Clean(u)
		if !strings.HasPrefix(dir, "/") || seen[dir] {
			continue
		}
		seen[dir] = true
		t = append(t, Target{Dir: dir, Class: ClassUpload, Recursive: true})
	}
	return t
}
