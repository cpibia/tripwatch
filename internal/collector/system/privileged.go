package system

import (
	"context"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

// DefaultSkip lists pseudo filesystems and container storage. Container layers are full of
// legitimate setuid binaries; comparing them with their images is the job of the container
// collector on the roadmap, and until then container storage is not covered here.
var DefaultSkip = []string{"proc", "sys", "dev", "run", "var/lib/docker", "var/lib/containerd", "var/lib/containers"}

// DefaultExtra lists paths inside skipped trees that unprivileged users can write to, and so
// attackers use: they are walked even though their parents are skipped.
var DefaultExtra = []string{"dev/shm", "run/lock", "run/shm", "run/user"}

const maxWalkIssues = 50

type PrivilegedResult struct {
	Files        []collector.File `json:"files"`
	Scanned      int              `json:"scanned"`
	AttrsSkipped int              `json:"attrs_skipped,omitempty"`
	Issues       collector.Issues `json:"issues,omitempty"`
}

// Privileged walks the whole filesystem for files that grant or protect privileges: setuid,
// setgid, Linux capabilities, and the immutable or append-only flags attackers set to keep
// their files from being removed.
type Privileged struct {
	Skip  []string
	Extra []string
}

func (Privileged) Name() string { return "privileged" }

func (p Privileged) Collect(ctx context.Context, src collector.Source) (any, error) {
	var res PrivilegedResult
	mounts := readUserMounts(src)
	skip := map[string]bool{}
	for _, s := range p.Skip {
		skip[s] = true
	}

	walk := func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			if len(res.Issues) < maxWalkIssues {
				res.Issues.Add(err)
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() && skip[name] {
			return fs.SkipDir
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		res.Scanned++

		var attrs collector.Attrs
		if src.Attrs != nil {
			a, err := src.Attrs(name)
			if err != nil {
				res.AttrsSkipped++
			}
			attrs = a
		}

		setid := false
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return nil
			}
			setid = info.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0
		}
		if !setid && !attrs.Any() {
			return nil
		}

		f, err := collector.DescribeEntry(src, name, d)
		if err != nil && len(res.Issues) < maxWalkIssues {
			res.Issues.Add(err)
		}
		if f.Path != "" {
			f.Mount = mounts.userMount(f.Path)
			res.Files = append(res.Files, f)
		}
		return nil
	}

	for _, root := range append([]string{"."}, p.Extra...) {
		if err := fs.WalkDir(src.FS, root, walk); err != nil {
			return nil, err
		}
	}
	if len(res.Issues) >= maxWalkIssues {
		res.Issues = append(res.Issues, fmt.Sprintf("further errors omitted after %d", maxWalkIssues))
	}
	return res, nil
}

// userMounts are the filesystems an unprivileged user mounted, by mount point.
type userMounts map[string]string

// readUserMounts reads the mount table of the host's init process (the observed root's, when the
// sensor runs in a container with the host mounted) and keeps the FUSE mounts of a user other
// than root. A missing table only means no file gets marked.
func readUserMounts(src collector.Source) userMounts {
	out := userMounts{}
	lines, err := collector.ReadLines(src.FS, "proc/1/mountinfo")
	if err != nil {
		return out
	}
	for _, line := range lines {
		left, right, ok := strings.Cut(line, " - ")
		fields, tail := strings.Fields(left), strings.Fields(right)
		if !ok || len(fields) < 5 || len(tail) < 3 {
			continue
		}
		fstype := tail[0]
		if fstype != "fuseblk" && fstype != "fuse" && !strings.HasPrefix(fstype, "fuse.") {
			continue
		}
		uid := ""
		for _, opt := range strings.Split(tail[2], ",") {
			if v, ok := strings.CutPrefix(opt, "user_id="); ok {
				uid = v
			}
		}
		if uid != "" && uid != "0" {
			out[unescapeMount(fields[4])] = fstype + " uid " + uid
		}
	}
	return out
}

// unescapeMount decodes the octal escapes mountinfo uses for spaces and the like.
func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// userMount returns the user mount a path lies on, the deepest one, or "".
func (m userMounts) userMount(p string) string {
	best, kind := "", ""
	for point, k := range m {
		if (p == point || strings.HasPrefix(p, strings.TrimSuffix(point, "/")+"/")) && len(point) > len(best) {
			best, kind = point, k
		}
	}
	return kind
}
