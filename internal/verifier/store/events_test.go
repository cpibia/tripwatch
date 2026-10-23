package store

import (
	"context"
	"testing"
	"time"
)

func stored(kept []bool) int {
	n := 0
	for _, k := range kept {
		if k {
			n++
		}
	}
	return n
}

// Past the daily quota events are not stored, so the first ones stay; past the retention they go.
// Noise in the uploads has a budget of its own and leaves root's changes theirs.
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
	if k, err := s.AddEvents(ctx, batch(MaxEventsPerDay-1, t0), t0); err != nil || stored(k) != MaxEventsPerDay-1 {
		t.Fatalf("stored %d, %v", stored(k), err)
	}
	if k, err := s.AddEvents(ctx, batch(5, t0), t0.Add(time.Hour)); err != nil || stored(k) != 1 {
		t.Fatalf("over the quota: stored %d, %v", stored(k), err)
	}
	root := []Event{{HostID: "web-01", Seq: 2, At: t0, Class: "ssh", Op: "create", Path: "/root/.ssh/authorized_keys", Data: []byte(`{}`)}}
	if k, _ := s.AddEvents(ctx, root, t0.Add(time.Hour)); !k[0] {
		t.Fatal("upload noise used up the budget of root's changes")
	}
	if k, _ := s.AddEvents(ctx, batch(2, t0.Add(25*time.Hour)), t0.Add(25*time.Hour)); stored(k) != 2 {
		t.Fatalf("a day later: stored %d", stored(k))
	}
	if _, err := s.AddEvents(ctx, batch(1, t0.Add(EventRetention+2*time.Hour)), t0.Add(EventRetention+2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	left, err := s.HostEvents(ctx, "web-01", MaxEventsPerDay)
	if err != nil || len(left) != 3 {
		t.Fatalf("after the retention: %d events, %v", len(left), err)
	}
}
