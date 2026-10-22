package system

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/cpibia/tripwatch/internal/collector"
)

// DefaultSkip lists pseudo filesystems and container storage. Container layers are full of
// legitimate setuid binaries and are checked against their image by a dedicated collector.
var DefaultSkip = []string{"proc", "sys", "dev", "run", "var/lib/docker", "var/lib/containerd", "var/lib/containers"}

// DefaultExtra lists paths inside skipped trees that attackers use and must still be walked.
var DefaultExtra = []string{"dev/shm"}

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
