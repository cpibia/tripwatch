package watch

import (
	"context"
	"encoding/json"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"
)

// BatchEvent names the payload of an event envelope that carries watched changes.
const BatchEvent = "watch"

// Batch is the payload of one event envelope: the changes seen since the previous batch, and how
// many were lost on the way.
type Batch struct {
	Event  string            `json:"event"`
	Events []json.RawMessage `json:"events"`
	// Dropped counts the events lost since the previous batch: the kernel's queue overflowed, or
	// the sensor could not keep up or hold them while the verifier was unreachable. Skipped counts
	// the processes not inspected because too many started at once.
	Dropped int64 `json:"dropped,omitempty"`
	Skipped int64 `json:"skipped,omitempty"`
	// PackageManager is set when a package manager was running as the batch was sent: what it
	// installs touches the same places an intruder does.
	PackageManager bool `json:"package_manager,omitempty"`
}

// Bounds of the batcher. A batch stays well below what the verifier accepts for an event
// envelope (256 KB), and what waits while the verifier is unreachable is capped.
const (
	MaxBatchBytes = 192 << 10
	MaxQueued     = 4096
	Window        = 2 * time.Second
	maxBackoff    = time.Minute
)

// Batcher gathers events and sends them in batches at most Window apart.
type Batcher struct {
	In <-chan Event
	// Send seals and delivers a payload. It returns an error only when the payload was not
	// sealed, so it has to be sent again.
	Send func(ctx context.Context, payload []byte) error
	// Lost returns how many events and process inspections the sources have lost so far, in all.
	Lost func() (dropped, skipped int64)
	// PackageManager reports whether a package manager is running.
	PackageManager func() bool
	Now            func() time.Time

	queue            []json.RawMessage
	dropped, skipped int64
	seenD, seenS     int64
	failures         int
	retryAt          time.Time
}

// Run sends batches until ctx ends.
func (b *Batcher) Run(ctx context.Context) {
	if b.Now == nil {
		b.Now = time.Now
	}
	tick := time.NewTicker(Window)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-b.In:
			b.add(e)
		case <-tick.C:
			b.Flush(ctx)
		}
	}
}

func (b *Batcher) add(e Event) {
	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	if len(b.queue) >= MaxQueued {
		b.queue = slices.Delete(b.queue, 0, 1)
		b.dropped++
	}
	b.queue = append(b.queue, raw)
}

// Flush sends what is queued, in as many batches as it takes, unless an earlier failure asks to
// wait a little longer.
func (b *Batcher) Flush(ctx context.Context) {
	if b.Lost != nil {
		d, s := b.Lost()
		b.dropped += d - b.seenD
		b.skipped += s - b.seenS
		b.seenD, b.seenS = d, s
	}
	now := b.Now()
	if now.Before(b.retryAt) {
		return
	}
	for len(b.queue) > 0 || b.dropped > 0 || b.skipped > 0 {
		batch, n := b.next()
		payload, err := json.Marshal(batch)
		if err != nil {
			return
		}
		if err := b.Send(ctx, payload); err != nil {
			b.failures++
			wait := min(Window<<min(b.failures, 6), maxBackoff)
			b.retryAt = now.Add(wait)
			return
		}
		b.failures, b.retryAt = 0, time.Time{}
		b.queue = b.queue[n:]
		b.dropped, b.skipped = 0, 0
	}
	if len(b.queue) == 0 {
		b.queue = nil
	}
}

// next builds the batch at the head of the queue and says how many events it takes.
func (b *Batcher) next() (Batch, int) {
	batch := Batch{Event: BatchEvent, Events: []json.RawMessage{}, Dropped: b.dropped, Skipped: b.skipped}
	size := 0
	n := 0
	for _, raw := range b.queue {
		if n > 0 && size+len(raw) > MaxBatchBytes {
			break
		}
		size += len(raw) + 1
		n++
	}
	batch.Events = b.queue[:n]
	if b.PackageManager != nil {
		batch.PackageManager = b.PackageManager()
	}
	return batch, n
}

// packageManagers are the process names of package managers and of the tools that drive them.
var packageManagers = []string{"dpkg", "apt", "apt-get", "aptitude", "unattended-upgr", "rpm", "dnf", "yum", "microdnf", "zypper", "apk", "pacman", "snapd", "packagekitd"}

// PackageManagerRunning reports whether a package manager is running, from the process names
// under proc in fsys.
func PackageManagerRunning(fsys fs.FS) bool {
	entries, err := fs.ReadDir(fsys, "proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		comm, err := fs.ReadFile(fsys, "proc/"+e.Name()+"/comm")
		if err != nil {
			continue
		}
		if slices.Contains(packageManagers, strings.TrimSpace(string(comm))) {
			return true
		}
	}
	return false
}
