package store

import (
	"context"
	"slices"
	"testing"
	"time"
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

// The version shown is the one the sensor started with, not the one of its last snapshot: an
// update shows before the first snapshot of the new version is collected.
func TestFactsVersionFromLatestStart(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.SetFacts(ctx, "web-01", HostFacts{SensorVersion: "0.1.16", SeenAt: t0}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFacts(ctx, "web-02", HostFacts{SensorVersion: "0.1.16", SeenAt: t0}); err != nil {
		t.Fatal(err)
	}
	if err := s.Started(ctx, "web-01", "b1", "0.1.19", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	facts, err := s.Facts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := facts["web-01"].SensorVersion; v != "0.1.19" {
		t.Errorf("updated sensor shows %q", v)
	}
	if v := facts["web-02"].SensorVersion; v != "0.1.16" {
		t.Errorf("sensor without a recorded start shows %q", v)
	}
}
