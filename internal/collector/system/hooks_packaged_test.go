package system

import (
	"slices"
	"testing"
	"testing/fstest"

	"github.com/cpibia/tripwatch/internal/collector"
)

// Hooks a dpkg file list names are packaged; without lists nothing is said.
func TestPackagedHooks(t *testing.T) {
	hooks := []collector.File{{Path: "/etc/profile.d/bash_completion.sh"}, {Path: "/etc/profile.d/x.sh"}}
	fsys := fstest.MapFS{
		"var/lib/dpkg/info/bash-completion.list": {Data: []byte("/.\n/etc\n/etc/profile.d\n/etc/profile.d/bash_completion.sh\n")},
		"var/lib/dpkg/info/coreutils.list":       {Data: []byte("/usr/bin/ls\n")},
	}
	var issues collector.Issues
	got, read := packagedHooks(fsys, hooks, &issues)
	if !read || !slices.Equal(got, []string{"/etc/profile.d/bash_completion.sh"}) || len(issues) != 0 {
		t.Errorf("packaged %v, read %v, issues %q", got, read, issues)
	}
	if got, read := packagedHooks(fstest.MapFS{}, hooks, &issues); read || got != nil {
		t.Errorf("without lists: %v %v", got, read)
	}
}
