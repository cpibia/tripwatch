package store

import (
	"context"
	"strconv"
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

// An account flooding its own home uses up its own budget, never root's nor another account's.
func TestEventsBudgetPerOwner(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	home := func(owner string, n int) []Event {
		out := make([]Event, n)
		for i := range out {
			out[i] = Event{HostID: "web-01", Seq: 1, At: t0, Class: "ssh", Op: "create", Path: "/home/" + owner + "/.ssh/k", Owner: owner, Data: []byte(`{}`)}
		}
		return out
	}
	if k, err := s.AddEvents(ctx, home("alice", MaxOwnerEventsPerDay+50), t0); err != nil || stored(k) != MaxOwnerEventsPerDay {
		t.Fatalf("stored %d of one account's flood, %v", stored(k), err)
	}
	if k, _ := s.AddEvents(ctx, home("alice", 1), t0.Add(time.Minute)); stored(k) != 0 {
		t.Fatal("the account's budget is not kept across batches")
	}
	if k, _ := s.AddEvents(ctx, home("bob", 1), t0.Add(time.Minute)); stored(k) != 1 {
		t.Fatal("one account used up another's budget")
	}
	root := []Event{{HostID: "web-01", Seq: 2, At: t0, Class: "ssh", Op: "create", Path: "/root/.ssh/authorized_keys", Data: []byte(`{}`)}}
	for i := 0; i < MaxEventsPerDay/MaxOwnerEventsPerDay; i++ {
		if _, err := s.AddEvents(ctx, home("user"+string(rune('a'+i)), MaxOwnerEventsPerDay), t0.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if k, _ := s.AddEvents(ctx, root, t0.Add(time.Minute)); !k[0] {
		t.Fatal("the accounts' events used up the budget of root's changes")
	}
}

// A batch naming more accounts than a host has keeps the events of the first few only.
func TestEventsOwnersPerBatch(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	events := make([]Event, 1000)
	for i := range events {
		owner := "uid " + strconv.Itoa(i)
		events[i] = Event{HostID: "web-01", Seq: 1, At: t0, Class: "schedule", Op: "create", Path: "/var/spool/cron/crontabs/x", Owner: owner, Data: []byte(`{}`)}
	}
	k, err := s.AddEvents(ctx, events, t0)
	if err != nil || stored(k) != maxBatchOwners {
		t.Fatalf("stored %d of 1000 accounts, %v", stored(k), err)
	}
	if k, _ := s.AddEvents(ctx, events[:1], t0.Add(time.Minute)); stored(k) != 1 {
		t.Fatal("an account seen earlier in the day is refused")
	}
}
