package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
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
	// DroppedSystem counts, among the dropped, the events on root's system paths (accounts, SSH,
	// privilege, services, scheduled tasks, start-up scripts) the queue had to let go: everything
	// else goes first, so these are lost only when root itself floods the queue.
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
	// MaxQueuedPerOwner bounds the events of one account's home or crontab that rank above the
	// uploads; past it, that account's events are noise until the queue drains.
	MaxQueuedPerOwner = 64
	// MaxWait is how long an event other than noise can be passed over by later ones of a higher
	// rank before it goes first.
	MaxWait = 15 * time.Second
)

// Batcher gathers events and sends them in batches at most Window apart.
type Batcher struct {
	In <-chan Event
	// Urgent carries the events of root's system paths, apart from the rest: a flood the users
	// can make fills In, never this, and Run reads it first.
	Urgent <-chan Event
	// Send seals and delivers a payload. It returns an error only when the payload was not
	// sealed, so it has to be sent again.
	Send func(ctx context.Context, payload []byte) error
	// Lost returns how many events and process inspections the sources have lost so far, in all.
	Lost func() (dropped, skipped int64)
	// LostSystem returns how many of root's system events the sources have lost so far.
	LostSystem func() int64
	// PackageManager reports whether a package manager is running.
	PackageManager func() bool
	Now            func() time.Time
	// Done, when set, is closed once Run has sent what was left at the end.
	Done chan struct{}

	// queue holds the events in arrival order; an evicted one stays as a hole (rank -1) until the
	// next batch, so that eviction costs the same whatever the queue holds. order lists the
	// positions of each rank, oldest first; live counts the events that are not holes.
	queue            []queued
	order            [ranks][]int
	live             int
	pending          []queued // the queue without the batch being sent
	dropped, skipped int64
	droppedSystem    int64
	seenD, seenS     int64
	seenSystem       int64
	failures         int
	retryAt          time.Time
	homes            atomic.Pointer[map[string]string]
	perOwner         map[string]int
	spoolUIDs        map[string]uint32
}

// queued is an event waiting to be sent, with its rank and when it came.
type queued struct {
	raw   json.RawMessage
	rank  int
	owner string
	since time.Time
}

// Ranks of queued events, first sent and last evicted first: root's system paths, which only
// root can change; the homes and crontabs of the other accounts, within a quota each; the rest;
// the noise no rule raises an alert on.
const (
	rankRoot = iota
	rankUser
	rankOther
	rankLow
	ranks
)

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
		// Root's events first, whatever else is ready.
		select {
		case e := <-b.Urgent:
			b.add(e)
			continue
		default:
		}
		select {
		case <-ctx.Done():
			b.finish(ctx)
			return
		case e := <-b.Urgent:
			b.add(e)
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
		case e := <-b.Urgent:
			b.add(e)
		case e := <-b.In:
			b.add(e)
		default:
			break drain
		}
	}
	final, cancel := context.WithTimeout(context.WithoutCancel(ctx), finalFlush)
	defer cancel()
	// The verifier allows a burst: spend part of it, then report what could not go as lost,
	// so nothing disappears without a count.
	for i := 0; i < maxFinalBatches && final.Err() == nil; i++ {
		b.retryAt = time.Time{}
		b.Flush(final)
		if b.live == 0 {
			break
		}
	}
	for _, q := range b.queue {
		if q.rank < 0 {
			continue
		}
		b.dropped++
		if q.rank == rankRoot {
			b.droppedSystem++
		}
	}
	b.reset(nil)
	b.perOwner = nil
	if b.dropped > 0 || b.skipped > 0 {
		b.retryAt = time.Time{}
		b.Flush(final)
	}
}

// maxFinalBatches is the part of the verifier's burst a stopping sensor spends.
const maxFinalBatches = 40

func (b *Batcher) add(e Event) {
	e.Owner = b.owner(e)
	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	if b.perOwner == nil {
		b.perOwner = map[string]int{}
	}
	if b.live >= MaxQueued {
		// The oldest of the lowest rank goes.
		r := ranks - 1
		for len(b.order[r]) == 0 {
			r--
		}
		i := b.order[r][0]
		b.order[r] = b.order[r][1:]
		if r == rankRoot {
			b.droppedSystem++
		}
		b.release(b.queue[i])
		b.queue[i] = queued{rank: -1}
		b.live--
		b.dropped++
	}
	// Holes are dropped once they outnumber the events, if no batch has gone for a while.
	if len(b.queue) >= 2*MaxQueued {
		b.reset(slices.DeleteFunc(b.queue, func(q queued) bool { return q.rank < 0 }))
	}
	q := queued{raw: raw, owner: e.Owner, since: b.now()}
	switch {
	case e.Owner != "" && b.perOwner[e.Owner] < MaxQueuedPerOwner:
		q.rank = rankUser
		b.perOwner[e.Owner]++
	case e.Owner != "" || lowPriority(e):
		q.rank = rankLow
	case systemClass(e.Class):
		q.rank = rankRoot
	default:
		q.rank = rankOther
	}
	b.order[q.rank] = append(b.order[q.rank], len(b.queue))
	b.queue = append(b.queue, q)
	b.live++
}

// reset makes q, which holds no holes, the queue.
func (b *Batcher) reset(q []queued) {
	b.queue, b.live = q, len(q)
	for r := range b.order {
		b.order[r] = b.order[r][:0]
	}
	for i, e := range q {
		b.order[e.rank] = append(b.order[e.rank], i)
	}
}

func (b *Batcher) now() time.Time {
	if b.Now == nil {
		return time.Now()
	}
	return b.Now()
}

// release forgets a queued event in its owner's quota.
func (b *Batcher) release(q queued) {
	if q.rank != rankUser {
		return
	}
	if b.perOwner[q.owner]--; b.perOwner[q.owner] <= 0 {
		delete(b.perOwner, q.owner)
	}
}

// SetHomes tells the batcher which accounts other than root own which homes; it may be called
// while Run runs.
func (b *Batcher) SetHomes(homes []Home) {
	m := make(map[string]string, len(homes))
	rootHomes := map[string]bool{}
	for _, h := range homes {
		dir := path.Clean(h.Dir)
		if dir == "/" || !strings.HasPrefix(dir, "/") {
			continue
		}
		if h.UID == 0 {
			rootHomes[dir] = true
		} else if _, ok := m[dir]; !ok {
			m[dir] = h.User
		}
	}
	// A home shared with an account of UID 0 is root's.
	for dir := range rootHomes {
		delete(m, dir)
	}
	b.homes.Store(&m)
}

// owner returns the account other than root that can change the path of a system event at will:
// its home's start-up files and SSH keys, and its files in the cron and at spools.
func (b *Batcher) owner(e Event) string {
	if e.Path == "" {
		return ""
	}
	dir, name := path.Split(e.Path)
	dir = path.Clean(dir)
	switch e.Class {
	case ClassSSH, ClassHook:
		return b.homeOwner(e.Class, dir, name)
	case ClassSchedule:
		if !e.Root && strings.HasPrefix(e.Path, "/var/spool/") {
			return b.spoolOwner(e, name)
		}
	}
	return ""
}

// homeOwner returns the account other than root whose home holds a start-up file or SSH key.
// Only the names watched in a home count: an account whose home is /etc must not take
// /etc/profile from root. The .ssh directory itself, created, removed or moved away, is its
// home's: an account can do that in a loop.
func (b *Batcher) homeOwner(class, dir, name string) string {
	homes := b.homes.Load()
	if homes == nil {
		return ""
	}
	switch {
	case name == ".ssh":
		return (*homes)[dir]
	case class == ClassSSH && path.Base(dir) == ".ssh":
		return (*homes)[path.Dir(dir)]
	case class == ClassHook && slices.Contains(rcFiles, name):
		return (*homes)[dir]
	}
	return ""
}

// RootEvent reports, for the watchers, whether an event is one of root's system paths, for the
// lane no other account can fill. It may be called from any goroutine. In the spools only files
// of UID 0, and root's crontab, are root's: a removal there is not, unless it is that crontab.
func (b *Batcher) RootEvent(e Event) bool {
	if !systemClass(e.Class) || e.Path == "" {
		return false
	}
	dir, name := path.Split(e.Path)
	dir = path.Clean(dir)
	switch e.Class {
	case ClassSSH, ClassHook:
		return b.homeOwner(e.Class, dir, name) == ""
	case ClassSchedule:
		if !e.Root && strings.HasPrefix(e.Path, "/var/spool/") {
			return (e.UID != nil && *e.UID == 0) || (e.UID == nil && name == "root")
		}
	}
	return true
}

// maxSpoolOwners bounds the owners of spool files remembered for their removal.
const maxSpoolOwners = 1024

// spoolOwner names the owner of a file in the cron or at spools by its UID, never by its name:
// crontab writes temporary files with random names there, and anyone allowed to use it can
// make thousands. A removal carries no UID, so the one seen when the file appeared is used.
func (b *Batcher) spoolOwner(e Event, name string) string {
	uid, known := b.spoolUIDs[e.Path]
	if e.UID != nil {
		uid, known = *e.UID, true
	}
	switch {
	case e.Op == OpDelete:
		delete(b.spoolUIDs, e.Path)
	case e.UID != nil:
		if b.spoolUIDs == nil || len(b.spoolUIDs) >= maxSpoolOwners {
			b.spoolUIDs = map[string]uint32{}
		}
		b.spoolUIDs[e.Path] = *e.UID
	}
	switch {
	case known && uid == 0:
		return ""
	case known:
		return "uid " + strconv.FormatUint(uint64(uid), 10)
	case name == "root":
		// Only root's crontab has this name.
		return ""
	}
	// Gone before it could be read, as crontab's temporary files are: one quota for all of them.
	return "spool"
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
	if b.LostSystem != nil {
		d := b.LostSystem()
		b.droppedSystem += d - b.seenSystem
		b.seenSystem = d
	}
	now := b.Now()
	if now.Before(b.retryAt) {
		return
	}
	// One batch per call, so at most one every Window: the verifier refuses envelopes that come
	// faster, and a refused one would hold up the snapshot behind it.
	if b.live > 0 || b.dropped > 0 || b.skipped > 0 {
		batch := b.next()
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
		b.reset(b.pending)
		clear(b.perOwner)
		for _, q := range b.queue {
			if q.rank == rankUser {
				b.perOwner[q.owner]++
			}
		}
		b.dropped, b.skipped, b.droppedSystem = 0, 0, 0
	}
	if b.live == 0 {
		b.reset(nil)
	}
}

// next builds the next batch, the system events first; pending holds the queue without them
// until the batch is sent.
func (b *Batcher) next() Batch {
	batch := Batch{Event: BatchEvent, Events: []json.RawMessage{}, Dropped: b.dropped, Skipped: b.skipped, DroppedSystem: b.droppedSystem}
	// Root's system events first, then whatever has waited MaxWait, then each rank in turn, each
	// in the order it came: a change to root's keys must not wait behind a flood in the uploads
	// or in a user's home, and a webshell must not wait behind a flood forever.
	size, n := 0, 0
	taken := make([]bool, len(b.queue))
	stale := b.now().Add(-MaxWait)
	for pass := -1; pass < ranks; pass++ {
		for i, q := range b.queue {
			first := pass == -1 && q.rank == rankRoot
			aged := pass == rankRoot && q.rank > rankRoot && q.rank != rankLow && q.since.Before(stale)
			if q.rank < 0 || taken[i] || (pass == -1 && !first) || (pass == rankRoot && !aged) || (pass > rankRoot && q.rank != pass) {
				continue
			}
			if n > 0 && size+len(q.raw) > MaxBatchBytes {
				break
			}
			size += len(q.raw) + 1
			n++
			taken[i] = true
			batch.Events = append(batch.Events, q.raw)
		}
	}
	rest := b.queue[:0:0]
	for i, q := range b.queue {
		if !taken[i] && q.rank >= 0 {
			rest = append(rest, q)
		}
	}
	b.pending = rest
	if b.PackageManager != nil {
		batch.PackageManager = b.PackageManager()
	}
	return batch
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
