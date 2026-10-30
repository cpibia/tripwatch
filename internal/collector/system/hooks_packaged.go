package system

import (
	"fmt"
	"io/fs"
	"slices"

	"github.com/cpibia/tripwatch/internal/collector"
)

// Bounds on reading dpkg's file lists: a system holds a few thousand packages and a few hundred
// thousand files.
const (
	maxPackageLists    = 20000
	maxPackageListRows = 4 << 20
)

// packagedHooks returns the hooks that dpkg's file lists name, and whether the lists were read
// whole. Without them (rpm and apk keep theirs in binary databases) nothing is said.
func packagedHooks(fsys fs.FS, hooks []collector.File, issues *collector.Issues) ([]string, bool) {
	lists := collector.Glob(fsys, "var/lib/dpkg/info/*.list")
	if len(lists) == 0 {
		return nil, false
	}
	if len(lists) > maxPackageLists {
		issues.Add(fmt.Errorf("var/lib/dpkg/info: %d file lists, more than %d: hooks not matched to packages", len(lists), maxPackageLists))
		return nil, false
	}
	wanted := make(map[string]bool, len(hooks))
	for _, h := range hooks {
		wanted[h.Path] = true
	}
	found := map[string]bool{}
	rows := 0
	for _, name := range lists {
		cut, err := collector.EachLine(fsys, name, 4096, maxPackageListRows-rows, func(line string) {
			rows++
			if wanted[line] {
				found[line] = true
			}
		})
		if err != nil {
			issues.Add(fmt.Errorf("hooks not matched to packages: %w", err))
			return nil, false
		}
		if cut {
			issues.Add(fmt.Errorf("var/lib/dpkg/info: file lists past %d lines: hooks not matched to packages", maxPackageListRows))
			return nil, false
		}
	}
	out := make([]string, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	slices.Sort(out)
	return out, true
}
