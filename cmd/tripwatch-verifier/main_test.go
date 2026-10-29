package main

import (
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

func TestRetentionFromEnvironment(t *testing.T) {
	if r, err := retention(); err != nil || r != store.DefaultRetention {
		t.Fatalf("defaults: %+v, %v", r, err)
	}
	t.Setenv("TRIPWATCH_KEEP_EVENTS_DAYS", "30")
	t.Setenv("TRIPWATCH_KEEP_RESOLVED_DAYS", "365")
	if r, err := retention(); err != nil || r.Events != 30*24*time.Hour || r.Resolved != 365*24*time.Hour || r.Snapshots != store.DefaultRetention.Snapshots {
		t.Fatalf("configured: %+v, %v", r, err)
	}
	for _, bad := range []string{"7d", "0", "-3", "99999999999"} {
		t.Setenv("TRIPWATCH_KEEP_EVENTS_DAYS", bad)
		if _, err := retention(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	t.Setenv("TRIPWATCH_KEEP_EVENTS_DAYS", "30")
	t.Setenv("TRIPWATCH_KEEP_RESOLVED_MINOR_DAYS", "400")
	if _, err := retention(); err == nil {
		t.Error("minor alerts kept longer than the others accepted")
	}
}
