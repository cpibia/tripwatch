package store

import (
	"context"
	"testing"
	"time"
)

func TestRetentionValidate(t *testing.T) {
	for _, c := range []struct {
		name string
		r    Retention
		ok   bool
	}{
		{"default", DefaultRetention, true},
		{"a year of everything", Retention{Snapshots: 365 * day, Events: 365 * day, Resolved: 365 * day, MinorResolved: 365 * day}, true},
		{"snapshots under the dense window", Retention{Snapshots: day, Events: day, Resolved: day, MinorResolved: day}, false},
		{"events under a day", Retention{Snapshots: 30 * day, Events: time.Hour, Resolved: 90 * day, MinorResolved: 7 * day}, false},
		{"minor kept longer", Retention{Snapshots: 30 * day, Events: 7 * day, Resolved: 7 * day, MinorResolved: 30 * day}, false},
		{"past ten years", Retention{Snapshots: 4000 * day, Events: 7 * day, Resolved: 90 * day, MinorResolved: 7 * day}, false},
	} {
		if err := c.r.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// A shorter retention set before serving is what pruning follows.
func TestResolvedPrunedByConfiguredRetention(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	r := DefaultRetention
	r.Resolved, r.MinorResolved = 10*day, 3*day
	if err := s.SetRetention(r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Raise(ctx, Alert{HostID: "h", Fingerprint: "a:x:1", Severity: "high", Kind: "a", Title: "x"}, t0); err != nil {
		t.Fatal(err)
	}
	all, _ := s.Alerts(ctx, AlertFilter{})
	_ = s.Resolve(ctx, all[0].ID, "ops@example.net", t0)
	if err := s.PruneResolved(ctx, t0.Add(9*day)); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.Alerts(ctx, AlertFilter{}); len(left) != 1 {
		t.Fatal("pruned before its retention")
	}
	if err := s.PruneResolved(ctx, t0.Add(11*day)); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.Alerts(ctx, AlertFilter{}); len(left) != 0 {
		t.Fatalf("kept past its retention: %+v", left)
	}
}
