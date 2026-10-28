package store

import (
	"slices"
	"testing"
)

// A host's applications read in one line: one group per framework and version with how many,
// stacks before the directories recognised by a generic file, the most numerous first.
func TestAppGroups(t *testing.T) {
	f := HostFacts{Apps: []AppFact{
		{Path: "/usr/share/nginx/html", Framework: "static"},
		{Path: "/home/app/c22", Framework: "laravel", Version: "10.48.28"},
		{Path: "/var/www/html", Framework: "static", Sites: []string{"_"}},
		{Path: "/home/app/demo", Framework: "laravel", Version: "10.48.28"},
		{Path: "/home/app/events", Framework: "laravel", Version: "10.48.19"},
		{Path: "/var/www/blog", Framework: "wordpress", Version: "6.6.2", Sites: []string{"blog.example.com"}},
	}}
	want := []AppGroup{{"laravel", "10.48.28", 2}, {"laravel", "10.48.19", 1}, {"wordpress", "6.6.2", 1}, {"static", "", 2}}
	if got := f.AppGroups(); !slices.Equal(got, want) {
		t.Errorf("groups = %v, want %v", got, want)
	}
	if sorted := f.SortedApps(); sorted[0].Path != "/var/www/html" || sorted[1].Path != "/var/www/blog" || len(sorted) != len(f.Apps) {
		t.Errorf("sorted = %v", sorted)
	}
}
