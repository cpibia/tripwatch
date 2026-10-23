package store

import (
	"context"
	"testing"
	"time"
)

// A host started before the run record exists is known from its latest start alert.
func TestRunFallsBackOnStartAlerts(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	for i, boot := range []string{"0b9e6f3c-0000-4000-8000-000000000001", "0b9e6f3c-0000-4000-8000-000000000002"} {
		if _, err := s.Raise(ctx, Alert{HostID: "web-01", Fingerprint: "sensor:started:" + string(rune('1'+i)), Severity: "high", Kind: "sensor-event",
			Title: "Sensor started", Detail: "The sensor started (version 0.1.8, system boot " + boot + "). If the server..."}, t0.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Run(ctx, "web-01")
	if err != nil || r.BootID != "0b9e6f3c-0000-4000-8000-000000000002" || r.Version != "0.1.8" || !r.StoppedAt.IsZero() {
		t.Fatalf("run = %+v, %v", r, err)
	}
	if err := s.Stopped(ctx, "web-01", t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Run(ctx, "web-01"); r.BootID != "0b9e6f3c-0000-4000-8000-000000000002" || !r.StoppedAt.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("after a stop: %+v", r)
	}
	if err := s.Started(ctx, "web-01", "b2", "0.1.10"); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Run(ctx, "web-01"); r.BootID != "b2" || r.Version != "0.1.10" || !r.StoppedAt.IsZero() {
		t.Fatalf("after a start: %+v", r)
	}
}
