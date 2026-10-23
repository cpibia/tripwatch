package store

import (
	"context"
	"testing"
	"time"
)

// Past the daily quota events are not stored, so the first ones stay; past the retention they go.
func TestEventsQuotaAndRetention(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	batch := func(n int, at time.Time) []Event {
		out := make([]Event, n)
		for i := range out {
			out[i] = Event{HostID: "web-01", Seq: 1, At: at, Class: "upload", Op: "create", Path: "/srv/u/f", Data: []byte(`{}`)}
		}
		return out
	}
	if n, err := s.AddEvents(ctx, batch(MaxEventsPerDay-1, t0), t0); err != nil || n != MaxEventsPerDay-1 {
		t.Fatalf("stored %d, %v", n, err)
	}
	if n, err := s.AddEvents(ctx, batch(5, t0), t0.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("over the quota: stored %d, %v", n, err)
	}
	if n, _ := s.AddEvents(ctx, batch(2, t0.Add(25*time.Hour)), t0.Add(25*time.Hour)); n != 2 {
		t.Fatalf("a day later: stored %d", n)
	}
	if _, err := s.AddEvents(ctx, batch(1, t0.Add(EventRetention+2*time.Hour)), t0.Add(EventRetention+2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	left, err := s.HostEvents(ctx, "web-01", MaxEventsPerDay)
	if err != nil || len(left) != 3 {
		t.Fatalf("after the retention: %d events, %v", len(left), err)
	}
}
