package system

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

// CronTable is a crontab-like file. Owner is the user the jobs run as when the file itself
// does not say (per-user spool files).
type CronTable struct {
	collector.File
	Owner   string   `json:"owner,omitempty"`
	Entries []string `json:"entries"`
}

type ScheduledResult struct {
	Tables  []CronTable      `json:"tables"`
	Scripts []collector.File `json:"scripts"`
	Issues  collector.Issues `json:"issues,omitempty"`
}

// Scheduled collects cron tables, run-parts scripts and pending at jobs. Systemd timers are
// covered by the Services collector.
type Scheduled struct{}

func (Scheduled) Name() string { return "scheduled" }

func (Scheduled) Collect(ctx context.Context, src collector.Source) (any, error) {
	var res ScheduledResult

	system := append([]string{"etc/crontab", "etc/anacrontab"}, collector.Glob(src.FS, "etc/cron.d/*")...)
	for _, name := range system {
		res.addTable(src, name, "")
	}

	// Debian keeps user crontabs in var/spool/cron/crontabs, Red Hat in var/spool/cron.
	for _, dir := range []string{"var/spool/cron/crontabs", "var/spool/cron"} {
		for _, name := range collector.Glob(src.FS, dir+"/*") {
			res.addTable(src, name, path.Base(name))
		}
	}

	for _, dir := range []string{"etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly", "var/spool/at", "var/spool/cron/atjobs"} {
		for _, name := range collector.Glob(src.FS, dir+"/*") {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			res.Scripts = appendDescribed(res.Scripts, &res.Issues, src, name)
		}
	}
	return res, nil
}

func (res *ScheduledResult) addTable(src collector.Source, name, owner string) {
	f, err := collector.Describe(src, name)
	res.Issues.Add(err)
	if f.Path == "" {
		return
	}
	lines, err := collector.ReadLines(src.FS, name)
	res.Issues.Add(err)
	res.Tables = append(res.Tables, CronTable{File: f, Owner: owner, Entries: directives(lines)})
}

// directives returns the non-empty lines that are not # comments.
func directives(lines []string) []string {
	out := []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

type Sudoers struct{}

type SudoersFile struct {
	collector.File
	Rules []string `json:"rules"`
}

type SudoersResult struct {
	Files []SudoersFile `json:"files"`
	// Dirs are the directories holding the policy files: whoever can write one can add a
	// policy, and polkit, unlike sudo, does not check who owns its rules.
	Dirs   []collector.File `json:"dirs,omitempty"`
	Issues collector.Issues `json:"issues,omitempty"`
}

func (Sudoers) Name() string { return "sudoers" }

// privilegePolicies are the other files that grant root's power to users: polkit rules (which
// systemd-run and pkexec obey) and their older .pkla form, and doas.
var privilegePolicies = []string{
	"etc/polkit-1/rules.d/*", "run/polkit-1/rules.d/*", "usr/share/polkit-1/rules.d/*", "usr/local/share/polkit-1/rules.d/*",
	"etc/polkit-1/localauthority/*/*", "var/lib/polkit-1/localauthority/*/*",
	"etc/doas.conf", "usr/local/etc/doas.conf",
}

// policyDirs are described even when empty: a writable empty rules.d is a grant waiting.
var policyDirs = []string{
	"etc/sudoers.d", "etc/polkit-1/rules.d", "run/polkit-1/rules.d", "usr/share/polkit-1/rules.d", "usr/local/share/polkit-1/rules.d",
	"etc/polkit-1/localauthority", "var/lib/polkit-1/localauthority",
}

// maxSudoersFiles bounds the files followed through includes, and maxPolicyFiles the other
// policy files, so a directory filled on purpose cannot hold the collector past its deadline.
const (
	maxSudoersFiles = 500
	maxPolicyFiles  = 500
)

// Collect reads the sudoers policy, following its include and includedir lines wherever they
// point, and the other privilege policies. Files sudo would skip in sudoers.d (names with a dot
// or ending in ~) are reported too: the verifier decides whether they matter.
func (Sudoers) Collect(_ context.Context, src collector.Source) (any, error) {
	var res SudoersResult
	queue := append([]string{"etc/sudoers"}, collector.Glob(src.FS, "etc/sudoers.d/*")...)
	seen := map[string]bool{}
	var dirs []string
	for len(queue) > 0 {
		if len(seen) >= maxSudoersFiles {
			res.Issues = append(res.Issues, fmt.Sprintf("sudoers: more than %d files through includes, the rest not read", maxSudoersFiles))
			break
		}
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		f, err := collector.Describe(src, name)
		res.Issues.Add(err)
		if errors.Is(err, fs.ErrNotExist) && name != "etc/sudoers" {
			// sudo stops on an include it cannot find; a rule written there later would
			// otherwise appear with no alert.
			res.Issues = append(res.Issues, "sudoers: included file not found: /"+name)
		}
		if f.Path == "" {
			continue
		}
		dirs = append(dirs, path.Dir(name))
		lines, err := collector.ReadLines(src.FS, name)
		res.Issues.Add(err)
		rules := sudoersRules(lines)
		res.Files = append(res.Files, SudoersFile{File: f, Rules: rules})
		for _, r := range rules {
			directive, target, _ := strings.Cut(r, " ")
			target = includeTarget(name, target)
			switch directive {
			case "#include", "@include":
				// %h is the host name, unknown here: every file it could name is read.
				if strings.Contains(target, "%h") {
					queue = append(queue, collector.Glob(src.FS, strings.ReplaceAll(target, "%h", "*"))...)
				} else {
					queue = append(queue, target)
				}
			case "#includedir", "@includedir":
				queue = append(queue, collector.Glob(src.FS, path.Join(target, "*"))...)
			}
		}
	}
	read := 0
	for _, pattern := range privilegePolicies {
		for _, name := range collector.Glob(src.FS, pattern) {
			if read == maxPolicyFiles {
				res.Issues = append(res.Issues, fmt.Sprintf("privilege policies: more than %d files, the rest not read", maxPolicyFiles))
				break
			}
			read++
			f, err := collector.Describe(src, name)
			res.Issues.Add(err)
			if f.Path == "" {
				continue
			}
			dirs = append(dirs, path.Dir(name))
			lines, err := collector.ReadLines(src.FS, name)
			res.Issues.Add(err)
			res.Files = append(res.Files, SudoersFile{File: f, Rules: sudoersRules(lines)})
		}
	}
	dirs = append(dirs, policyDirs...)
	dirs = append(dirs, collector.Glob(src.FS, "etc/polkit-1/localauthority/*")...)
	dirs = append(dirs, collector.Glob(src.FS, "var/lib/polkit-1/localauthority/*")...)
	slices.Sort(dirs)
	for _, name := range slices.Compact(dirs) {
		f, err := collector.Describe(src, name)
		res.Issues.Add(err)
		if f.Path != "" && f.Mode != "" && f.Mode[0] == 'd' {
			res.Dirs = append(res.Dirs, f)
		}
	}
	return res, nil
}

// sudoEscape undoes the backslash escapes sudo allows in an include path.
var sudoEscape = strings.NewReplacer(`\ `, " ", `\\`, `\`, `\"`, `"`, `\,`, ",", `\:`, ":", `\=`, "=")

// includeTarget resolves an include line's path as sudo does: quotes and escapes removed, and
// relative to the directory of the file that includes it.
func includeTarget(from, target string) string {
	target = strings.Trim(strings.TrimSpace(target), `"`)
	target = sudoEscape.Replace(target)
	if !strings.HasPrefix(target, "/") {
		target = path.Join("/", path.Dir(from), target)
	}
	return strings.TrimPrefix(path.Clean(target), "/")
}

// sudoersRules drops comments but keeps #include and #includedir, which look like comments
// and pull in more policy, and #<number>, which sudo reads as a UID (#33 ALL=... is a rule).
func sudoersRules(lines []string) []string {
	out := []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		uid := len(line) > 1 && line[0] == '#' && line[1] >= '0' && line[1] <= '9'
		if strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#include") && !uid || strings.HasPrefix(line, "//") {
			continue
		}
		out = append(out, line)
	}
	return out
}
