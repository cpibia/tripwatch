package collector

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"testing/fstest"
	"time"
)

// hostileTree builds files an unprivileged user can plant to block or exhaust a reader.
func hostileTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustMkdir(t, filepath.Join(dir, "home/web/.ssh"))
	if err := syscall.Mkfifo(filepath.Join(dir, "home/web/.ssh/authorized_keys"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/zero", filepath.Join(dir, "home/web/.ssh/authorized_keys2")); err != nil {
		t.Fatal(err)
	}
	sparse := filepath.Join(dir, "home/web/version.php")
	if err := os.WriteFile(sparse, []byte("<?php"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(sparse, 50<<30); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "home/web/ok.txt"), []byte("fine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
}

// withDeadline fails the test instead of hanging it when a read blocks.
func withDeadline(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked: a hostile file stalled the reader")
	}
}

func TestRootFSRefusesHostileFiles(t *testing.T) {
	src := NewSource(hostileTree(t))

	// The link to /dev/zero is refused as a device, or, on Linux where links resolve inside
	// the root, as missing: either way the read ends at once.
	tests := []struct {
		name string
		want []error
	}{
		{"home/web/.ssh/authorized_keys", []error{ErrNotRegular}},
		{"home/web/.ssh/authorized_keys2", []error{ErrNotRegular, fs.ErrNotExist}},
		{"home/web/version.php", []error{ErrTooLarge}},
	}
	for _, tt := range tests {
		withDeadline(t, func() {
			_, err := fs.ReadFile(src.FS, tt.name)
			if !slices.ContainsFunc(tt.want, func(w error) bool { return errors.Is(err, w) }) {
				t.Errorf("ReadFile(%s) err = %v, want one of %v", tt.name, err, tt.want)
			}
		})
	}

	withDeadline(t, func() {
		lines, err := ReadLines(src.FS, "home/web/.ssh/authorized_keys")
		if err == nil || lines != nil {
			t.Errorf("ReadLines on a FIFO = %v, %v; want an error", lines, err)
		}
	})

	data, err := fs.ReadFile(src.FS, "home/web/ok.txt")
	if err != nil || string(data) != "fine\n" {
		t.Errorf("regular file: %q, %v", data, err)
	}
	entries, err := fs.ReadDir(src.FS, "home/web")
	if err != nil || len(entries) != 3 {
		t.Errorf("ReadDir = %v, %v", entries, err)
	}
	if info, err := fs.Stat(src.FS, "home/web/.ssh/authorized_keys"); err != nil || info.Mode()&fs.ModeNamedPipe == 0 {
		t.Errorf("Stat must still describe the FIFO: %v, %v", info, err)
	}
	if target, err := fs.ReadLink(src.FS, "home/web/.ssh/authorized_keys2"); err != nil || target != "/dev/zero" {
		t.Errorf("ReadLink = %q, %v", target, err)
	}
	if _, err := fs.ReadFile(src.FS, "home/web"); err == nil {
		t.Error("reading a directory must fail")
	}
	if _, err := src.FS.Open("../etc/passwd"); !errors.Is(err, fs.ErrInvalid) {
		t.Errorf("invalid path err = %v", err)
	}
}

func TestDescribeDoesNotBlockOnFIFO(t *testing.T) {
	src := NewSource(hostileTree(t))
	withDeadline(t, func() {
		f, err := Describe(src, "home/web/.ssh/authorized_keys")
		if err != nil || f.SHA256 != "" {
			t.Errorf("FIFO described as %+v, %v", f, err)
		}
	})
}

type blockingCollector struct{}

func (blockingCollector) Name() string { return "blocking" }

func (blockingCollector) Collect(ctx context.Context, _ Source) (any, error) {
	<-ctx.Done()
	time.Sleep(time.Second) // ignores cancellation for a while, as a stuck syscall would
	return nil, ctx.Err()
}

func TestRunTimesOutStuckCollectors(t *testing.T) {
	prevTimeout, prevGrace := Timeout, Grace
	Timeout, Grace = 50*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { Timeout, Grace = prevTimeout, prevGrace })

	start := time.Now()
	snap := Run(context.Background(), Source{FS: fstest.MapFS{}}, []Collector{
		blockingCollector{},
		stubCollector{name: "after", result: 1},
	}, time.Now())

	if time.Since(start) > 500*time.Millisecond {
		t.Errorf("Run waited %s for a stuck collector", time.Since(start))
	}
	if snap.Errors["blocking"] == "" {
		t.Errorf("errors = %v", snap.Errors)
	}
	if string(snap.Results["after"]) != "1" {
		t.Error("the collector after the stuck one did not run")
	}
}

type partialCollector struct{}

func (partialCollector) Name() string { return "partial" }

func (partialCollector) Collect(ctx context.Context, _ Source) (any, error) {
	<-ctx.Done()
	return "partial result", nil
}

// A collector that stops at its deadline and returns what it has keeps that result.
func TestRunKeepsPartialResults(t *testing.T) {
	prevTimeout, prevGrace := Timeout, Grace
	Timeout, Grace = 20*time.Millisecond, time.Second
	t.Cleanup(func() { Timeout, Grace = prevTimeout, prevGrace })

	snap := Run(context.Background(), Source{FS: fstest.MapFS{}}, []Collector{partialCollector{}}, time.Now())
	if string(snap.Results["partial"]) != `"partial result"` || len(snap.Errors) != 0 {
		t.Errorf("results %s, errors %v", snap.Results["partial"], snap.Errors)
	}
}
