// Package watch reports, as they happen, the changes that snapshots taken an hour apart can
// miss: a key added and removed, a script dropped in an upload directory and deleted after use.
// It only observes and reports; the verifier judges.
package watch

import (
	"errors"
	"path"
	"slices"
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
	// ClassWebRoot is the directory an application serves, watched without its subdirectories:
	// only a script that appears there and goes is reported.
	ClassWebRoot = "webroot"
	ClassExec    = "exec"
	// ClassScratch is the world-writable scratch directories, where only executable files are
	// reported: a dropper written there, run and deleted lives too briefly for its process to
	// be read, but its file is seen.
	ClassScratch = "scratch"
	// ClassContainer is containers with power over the host, started or removed.
	ClassContainer = "container"
)

// Reasons a process start is reported. Only these are: a busy server starts thousands of
// processes an hour, and the verifier needs the few that mean something.
const (
	// ReasonWebShell: the web server's user started a shell or a network tool, what a webshell
	// in use does.
	ReasonWebShell = "web_user_tool"
	// ReasonDeleted: the executable was removed from disk after it started.
	ReasonDeleted = "deleted_executable"
	// ReasonUnusualPath: the executable sits where programs are not installed.
	ReasonUnusualPath = "unusual_path"
	// ReasonPrivilege: a process gained root through a set-user-ID program outside the system's
	// binary directories.
	ReasonPrivilege = "privilege_gain"
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
	// PrevSHA256 is the content the sensor last knew the file to have, for system paths: a key
	// added and then removed by rewriting a file that existed long before shows as a return to it.
	PrevSHA256 string `json:"prev_sha256,omitempty"`
	// Root marks the root of a watched place moved away or removed: until it is back, nothing
	// in it is seen.
	Root bool `json:"root,omitempty"`
	// WebUser marks a file in a scratch directory owned by the web server's user.
	WebUser bool `json:"web_user,omitempty"`
	// Owner names the account other than root whose home or crontab the path is in: that
	// account can change it at will, so its events are not root's evidence.
	Owner string  `json:"owner,omitempty"`
	UID   *uint32 `json:"uid,omitempty"`
	Mode  string  `json:"mode,omitempty"`
	// Process events: why the process was reported, and what it is.
	Reason  string `json:"reason,omitempty"`
	PID     int    `json:"pid,omitempty"`
	PPID    int    `json:"ppid,omitempty"`
	User    *int   `json:"user,omitempty"`
	EUser   *int   `json:"euser,omitempty"`
	Exe     string `json:"exe,omitempty"`
	Script  string `json:"script,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
	// CommandSum is a short hash of the command line before redaction, set when the redaction
	// hid part of it: two commands shown alike are told apart.
	CommandSum string `json:"command_sum,omitempty"`
	Comm       string `json:"comm,omitempty"`
	Parent     string `json:"parent,omitempty"`
	Cwd        string `json:"cwd,omitempty"`
	// Repeats counts the identical starts left out since the previous report of this one, within
	// RepeatWindow.
	Repeats int `json:"repeats,omitempty"`
	// Container is the container a container event is about.
	Container *ContainerInfo `json:"container,omitempty"`
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
	// Depth, when set, replaces MaxDepth for this target.
	Depth int
	// Ephemeral marks a directory that comes and goes with what created it (a service's
	// private /tmp): its removal is no event and is not watched for again.
	Ephemeral bool
}

// Bounds: watches cost kernel memory, and upload trees can be deep and wide.
const (
	MaxWatches = 8192
	MaxDepth   = 4
	// The scratch directories get at most MaxScratchWatches of the watches, ScratchDepth deep.
	MaxScratchWatches = 512
	// The uploads get at most MaxUploadWatches, leaving the rest to the system and the homes.
	MaxUploadWatches = 6144
	ScratchDepth     = 2
	// UploadDepth reaches the derivatives CMSs keep deep in their file trees (Drupal's
	// styles/<style>/public/<dir>/...): MaxUploadWatches, not the depth, bounds what they cost.
	UploadDepth = 8
)

// maxWebRootTargets bounds the web roots watched.
const maxWebRootTargets = 512

// ErrUnsupported is returned where the kernel interfaces the watcher needs do not exist.
var ErrUnsupported = errors.New("watch: real-time events need Linux")

// Home is an account's home directory, for the files in it that grant or keep access.
type Home struct {
	User string
	Dir  string
	UID  int
}

// rcFiles are the shell start-up files of a home: code put there runs at each login.
var rcFiles = []string{".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".cshrc", ".tcshrc"}

// Targets lists what to watch on a host: the system's fixed places, the homes of its accounts
// and the upload directories of its web applications.
func Targets(homes []Home, uploads []string, webRoots ...string) []Target {
	t := []Target{
		{Dir: "/etc", Class: ClassAccounts, Names: []string{"passwd", "shadow", "group", "gshadow"}},
		{Dir: "/etc", Class: ClassPrivilege, Names: []string{"sudoers", "doas.conf"}},
		// bash_completion.d is sourced into every interactive bash: one created later is watched too.
		{Dir: "/etc", Class: ClassHook, Names: []string{"ld.so.preload", "ld.so.conf", "rc.local", "profile", "bash.bashrc", "environment", "bash_completion.d"},
			Spawn: map[string]Target{"bash_completion.d": {Dir: "/etc/bash_completion.d", Class: ClassHook}}},
		{Dir: "/etc", Class: ClassSchedule, Names: []string{"crontab", "anacrontab"}},
		{Dir: "/etc/sudoers.d", Class: ClassPrivilege},
		{Dir: "/etc/polkit-1", Class: ClassPrivilege, Recursive: true},
		{Dir: "/usr/share/polkit-1/rules.d", Class: ClassPrivilege},
		{Dir: "/etc/ssh", Class: ClassSSH, Names: []string{"sshd_config"}},
		{Dir: "/etc/ssh", Class: ClassHook, Names: []string{"sshrc"}},
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
		{Dir: "/etc/bash_completion.d", Class: ClassHook},
		// The loader's search path: a directory added here and baked into ld.so.cache by ldconfig
		// stays in effect after the file is gone.
		{Dir: "/etc/ld.so.conf.d", Class: ClassHook},
		// Scripts root runs when a network interface changes state, with ifupdown,
		// NetworkManager, networkd-dispatcher and dhclient; /etc/network's interfaces files hold
		// commands too.
		{Dir: "/etc/network", Class: ClassHook, Recursive: true, Depth: 1},
		{Dir: "/etc/NetworkManager/dispatcher.d", Class: ClassHook, Recursive: true, Depth: 1},
		{Dir: "/etc/networkd-dispatcher", Class: ClassHook, Recursive: true, Depth: 1},
		{Dir: "/etc/dhcp/dhclient-enter-hooks.d", Class: ClassHook},
		{Dir: "/etc/dhcp/dhclient-exit-hooks.d", Class: ClassHook},
	}
	seen := map[string]bool{}
	for _, h := range homes {
		dir := path.Clean(h.Dir)
		// Service accounts often have /bin or /usr/sbin as home: watching those for shell start-up
		// files would only bring every package upgrade's changes to be filtered out.
		if dir == "/" || dir == "." || !strings.HasPrefix(dir, "/") || seen[dir] || strings.HasPrefix(dir, "/nonexistent") ||
			slices.ContainsFunc(slices.Concat(systemBinDirs, []string{"/dev/", "/proc/", "/sys/"}), func(d string) bool { return strings.HasPrefix(dir+"/", d) }) {
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
		t = append(t, Target{Dir: dir, Class: ClassUpload, Recursive: true, Depth: UploadDepth})
	}
	roots := 0
	for _, r := range webRoots {
		dir := path.Clean(r)
		if !strings.HasPrefix(dir, "/") || seen[dir] || roots == maxWebRootTargets {
			continue
		}
		seen[dir] = true
		roots++
		t = append(t, Target{Dir: dir, Class: ClassWebRoot})
	}
	// Last, and with a small budget of their own: anyone can fill these with directories, which
	// must never take the watches of the places above.
	// The private /tmp of services and snaps sit below root-only directories, but their own
	// processes write there as in /tmp: each is watched as a scratch directory of its own.
	for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm", "/run/lock", "/tmp/systemd-private-*/tmp", "/tmp/snap-private-tmp/*/tmp", "/var/tmp/systemd-private-*/tmp"} {
		t = append(t, Target{Dir: d, Class: ClassScratch, Recursive: true, Depth: ScratchDepth})
	}
	return t
}

// Status says, in each snapshot, whether the real-time watchers run: without them the verifier
// sees only what snapshots show.
type Status struct {
	Files     bool `json:"files"`
	Processes bool `json:"processes"`
	Watches   int  `json:"watches"`
	// Unwatched lists places of the system, the homes or the uploads the bounds left without a
	// watch: the verifier raises them, since anyone able to create directories could cause it.
	Unwatched []string `json:"unwatched,omitempty"`
	Issues    []string `json:"issues,omitempty"`
}

// Executable reports whether a mode, as Go prints it, is a regular file anyone may execute.
func Executable(mode string) bool {
	if len(mode) < 10 || strings.ContainsAny(mode[:len(mode)-9], "dLDpSc") {
		return false
	}
	perm := mode[len(mode)-9:]
	return strings.ContainsAny(string([]byte{perm[2], perm[5], perm[8]}), "xs")
}
