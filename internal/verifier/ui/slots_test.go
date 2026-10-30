package ui

import (
	"context"
	"testing"
	"time"
)

// With every shared password check taken by a flood of made-up emails, a browser the user signed
// in from before still gets the slot kept for it, while one more anonymous attempt waits until its
// time is up.
func TestKnownBrowserKeepsItsCheckSlot(t *testing.T) {
	s := &server{checks: make(chan struct{}, 3), knownCheck: make(chan struct{}, 1)}
	ctx := context.Background()
	var held []func()
	for range cap(s.checks) {
		release, ok := s.checkSlot(ctx, false)
		if !ok {
			t.Fatal("a shared slot was refused while free")
		}
		held = append(held, release)
	}
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, ok := s.checkSlot(short, false); ok {
		t.Fatal("an anonymous attempt got past the full shared slots")
	}
	start := time.Now()
	release, ok := s.checkSlot(ctx, true)
	if !ok || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("a known browser waited %v behind the flood", time.Since(start))
	}
	release()
	for _, r := range held {
		r()
	}
}
