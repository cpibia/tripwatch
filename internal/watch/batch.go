package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/web"
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
	// DroppedSystem counts, among the dropped, the events on system paths (accounts, SSH,
	// privilege, services, scheduled tasks, start-up scripts) the queue had to let go: noise in
	// the uploads goes first, so these are lost only when the queue holds nothing else.
	DroppedSystem int64 `json:"dropped_system,omitempty"`
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
	// Done, when set, is closed once Run has sent what was left at the end.
	Done chan struct{}

	queue            []queued
	dropped, skipped int64
	droppedSystem    int64
	seenD, seenS     int64
	failures         int
	retryAt          time.Time
}

// queued is an event waiting to be sent, with its priority when the queue is full.
type queued struct {
	raw    json.RawMessage
	low    bool
	system bool
}

// finalFlush bounds the last attempt to send what is queued when the sensor stops.
const finalFlush = 5 * time.Second

// Run sends batches until ctx ends, then sends what is left: the last events before a stop are
// often the ones that matter.
func (b *Batcher) Run(ctx context.Context) {
	if b.Now == nil {
		b.Now = time.Now
	}
	tick := time.NewTicker(Window)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			b.finish(ctx)
			return
		case e := <-b.In:
			b.add(e)
		case <-tick.C:
			b.Flush(ctx)
		}
	}
}

func (b *Batcher) finish(ctx context.Context) {
	if b.Done != nil {
		defer close(b.Done)
	}
drain:
	for {
		select {
		case e := <-b.In:
			b.add(e)
		default:
			break drain
		}
	}
	final, cancel := context.WithTimeout(context.WithoutCancel(ctx), finalFlush)
	defer cancel()
	b.retryAt = time.Time{}
	b.Flush(final)
}

func (b *Batcher) add(e Event) {
	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	if len(b.queue) >= MaxQueued {
		// Low-priority noise goes first, then anything but system paths, then the oldest.
		i := slices.IndexFunc(b.queue, func(q queued) bool { return q.low })
		if i < 0 {
			i = slices.IndexFunc(b.queue, func(q queued) bool { return !q.system })
		}
		if i < 0 {
			i = 0
		}
		if b.queue[i].system {
			b.droppedSystem++
		}
		b.queue = slices.Delete(b.queue, i, i+1)
		b.dropped++
	}
	b.queue = append(b.queue, queued{raw: raw, low: lowPriority(e), system: systemClass(e.Class)})
}

// lowPriority are the events a web user can produce at will that no rule raises an alert on:
// files other than scripts and server configuration in the uploads, attribute changes there.
func lowPriority(e Event) bool {
	if e.Class != ClassUpload {
		return false
	}
	return e.Dir || e.Op == OpAttrib || (!web.IsScript(e.Path) && !web.IsOverride(e.Path))
}

func systemClass(class string) bool {
	switch class {
	case ClassAccounts, ClassSSH, ClassPrivilege, ClassSchedule, ClassService, ClassHook:
		return true
	}
	return false
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
		b.dropped, b.skipped, b.droppedSystem = 0, 0, 0
	}
	if len(b.queue) == 0 {
		b.queue = nil
	}
}

// next builds the batch at the head of the queue and says how many events it takes.
func (b *Batcher) next() (Batch, int) {
	batch := Batch{Event: BatchEvent, Events: []json.RawMessage{}, Dropped: b.dropped, Skipped: b.skipped, DroppedSystem: b.droppedSystem}
	size := 0
	n := 0
	for _, q := range b.queue {
		if n > 0 && size+len(q.raw) > MaxBatchBytes {
			break
		}
		size += len(q.raw) + 1
		n++
		batch.Events = append(batch.Events, q.raw)
	}
	if b.PackageManager != nil {
		batch.PackageManager = b.PackageManager()
	}
	return batch, n
}

// packageLocks are the lock files package managers hold while they change the system. They are
// root's and not writable by others, so only root can hold a lock on them: unlike a process name,
// which any user can set to "dpkg", the lock cannot be faked by the users the sensor guards
// against.
var packageLocks = []string{
	"var/lib/dpkg/lock-frontend", "var/lib/dpkg/lock", "var/lib/rpm/.rpm.lock",
	"usr/lib/sysimage/rpm/.rpm.lock", "lib/apk/db/lock",
}

// lockIdentity returns the owner of a lock file and its device and inode the way /proc/locks
// writes them (hexadecimal major and minor, decimal inode); tests replace it, since an fstest
// file has neither.
var lockIdentity = func(info fs.FileInfo) (uint32, string, bool) {
	uid, ok := collector.Owner(info)
	if !ok {
		return 0, "", false
	}
	id, ok := collector.FileID(info)
	if !ok {
		return 0, "", false
	}
	devText, ino, _ := strings.Cut(id, ":")
	dev, err := strconv.ParseUint(devText, 10, 64)
	if err != nil {
		return 0, "", false
	}
	// The kernel's dev_t encoding, as in glibc's gnu_dev_major and gnu_dev_minor.
	major := (dev>>8)&0xfff | (dev>>32)&^uint64(0xfff)
	minor := dev&0xff | (dev>>12)&^uint64(0xff)
	return uid, fmt.Sprintf("%02x:%02x:%s", major, minor, ino), true
}

// PackageManagerRunning reports whether a process of root holds a package manager's lock, from
// /proc/locks.
func PackageManagerRunning(fsys fs.FS) bool {
	inodes := map[string]bool{}
	for _, p := range packageLocks {
		info, err := fs.Stat(fsys, p)
		if err != nil || info.Mode().Perm()&0o022 != 0 {
			continue
		}
		if uid, ino, ok := lockIdentity(info); ok && uid == 0 {
			inodes[ino] = true
		}
	}
	if len(inodes) == 0 {
		return false
	}
	locks, err := fs.ReadFile(fsys, "proc/locks")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(locks), "\n") {
		// "1: POSIX ADVISORY WRITE 4242 08:01:1312 0 EOF"; waiters carry an extra "->" field.
		f := strings.Fields(line)
		for i := 1; i < len(f); i++ {
			if !inodes[f[i]] {
				continue
			}
			if pid, err := strconv.Atoi(f[i-1]); err == nil && rootProcess(fsys, pid) {
				return true
			}
		}
	}
	return false
}

func rootProcess(fsys fs.FS, pid int) bool {
	status, err := fs.ReadFile(fsys, "proc/"+strconv.Itoa(pid)+"/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			f := strings.Fields(v)
			return len(f) > 0 && f[0] == "0"
		}
	}
	return false
}
