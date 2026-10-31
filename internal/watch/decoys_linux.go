//go:build linux

package watch

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/system"
)

// A read of a decoy is judged against what the same process read around it in the decoy's
// directory: SweepFiles other files within SweepWindow before the read, or within DecoyHold after
// it, make it part of a sweep (a backup, an indexer, a scanner going through the directory).
const (
	SweepWindow = 5 * time.Second
	DecoyHold   = 2 * time.Second
	SweepFiles  = 8
)

// Bounds on what is remembered of the opens in the decoys' directories: a process that opens
// files there endlessly costs a fixed amount, and so do many processes.
const (
	maxSweepProcs   = 1024
	maxSweepFiles   = 64
	maxPendingReads = 256
)

// Decoys reports the reads of decoy files through fanotify, which names the process: each decoy
// is marked, and so is its directory for the opens of its other files, to tell a sweep from a
// read aimed at the decoy. The sensor's own opens are never reported; the descriptors fanotify
// hands over are opened by the kernel without notifying anyone, and closed at once.
type Decoys struct {
	fd  int
	src collector.Source
	// proc is where the processes are read, the observed root's unless a test says otherwise.
	proc fs.FS
	out  chan<- Event
	now  func() time.Time
	self int

	mu sync.Mutex
	// files are the decoys by identity, with their path.
	files map[fileKey]string
	// recent are the opens of each process in the decoys' directories, by directory and file.
	recent  map[int]*procOpens
	pending []decoyRead

	// Dropped counts reads not delivered because the consumer did not keep up; Overflow, the
	// times the kernel's queue overflowed and events were lost.
	Dropped  atomic.Int64
	Overflow atomic.Int64
}

type fileKey struct{ dev, ino uint64 }

type procOpens struct {
	last  time.Time
	files map[fileKey]dirOpen
}

type dirOpen struct {
	dir string
	at  time.Time
}

type decoyRead struct {
	at   time.Time
	pid  int
	path string
	dir  string
	ev   Event
}

// NewDecoys starts fanotify. It needs CAP_SYS_ADMIN.
func NewDecoys(src collector.Source, out chan<- Event) (*Decoys, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC|unix.O_NOATIME)
	if err != nil {
		return nil, err
	}
	return &Decoys{fd: fd, src: src, proc: src.FS, out: out, now: time.Now, self: os.Getpid(), files: map[fileKey]string{}, recent: map[int]*procOpens{}}, nil
}

func (d *Decoys) Close() error { return unix.Close(d.fd) }

// Set marks the decoys named by paths (absolute in the observed root) and their directories,
// replacing the marks before: a decoy put back by another file is that file. It returns the
// paths that could not be marked.
func (d *Decoys) Set(paths []string) []string {
	files := map[fileKey]string{}
	var failed []string
	if err := unix.FanotifyMark(d.fd, unix.FAN_MARK_FLUSH, 0, unix.AT_FDCWD, ""); err != nil {
		failed = append(failed, "flush: "+err.Error())
	}
	dirs := map[string]bool{}
	for _, p := range paths {
		rel := collector.Rel(p)
		if err := d.mark(rel, unix.FAN_OPEN|unix.FAN_ACCESS); err != nil {
			failed = append(failed, p+": "+err.Error())
			continue
		}
		if info, err := collector.OpenPath(d.src, rel); err == nil {
			var st unix.Stat_t
			if unix.Fstat(int(info.Fd()), &st) == nil { //nolint:gosec // a descriptor fits in int
				files[fileKey{dev: uint64(st.Dev), ino: st.Ino}] = p //nolint:unconvert,gosec // Dev's type differs between platforms
			}
			_ = info.Close()
		}
		dirs[path.Dir(rel)] = true
	}
	for dir := range dirs {
		if err := d.mark(dir, unix.FAN_OPEN|unix.FAN_EVENT_ON_CHILD); err != nil {
			failed = append(failed, "/"+dir+": "+err.Error())
		}
	}
	d.mu.Lock()
	d.files = files
	d.mu.Unlock()
	return failed
}

// mark marks name through an O_PATH descriptor resolved inside the observed root, so a link on
// the way cannot point the mark outside it.
func (d *Decoys) mark(name string, mask uint64) error {
	f, err := collector.OpenPath(d.src, name)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	// fanotify does not take an O_PATH descriptor itself, but follows its /proc link to the
	// same inode.
	return unix.FanotifyMark(d.fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(int(f.Fd()))) //nolint:gosec // a descriptor fits in int
}

// Run reads the events until ctx ends.
func (d *Decoys) Run(ctx context.Context) error {
	buf := make([]byte, 64<<10)
	fds := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}} //nolint:gosec // a descriptor fits in int32
	for ctx.Err() == nil {
		if _, err := unix.Poll(fds, 250); err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		for {
			n, err := unix.Read(d.fd, buf)
			if errors.Is(err, unix.EAGAIN) || n <= 0 {
				break
			}
			if err != nil && !errors.Is(err, unix.EINTR) {
				return err
			}
			d.events(buf[:n])
		}
		d.decide(d.now(), false)
	}
	d.decide(d.now(), true)
	return nil
}

func (d *Decoys) events(b []byte) {
	const size = int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for len(b) >= size {
		m := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&b[0])) //nolint:gosec // the kernel writes whole records
		if m.Event_len < uint32(size) || int(m.Event_len) > len(b) {
			return
		}
		b = b[m.Event_len:]
		if m.Mask&unix.FAN_Q_OVERFLOW != 0 {
			d.Overflow.Add(1)
		}
		if m.Fd < 0 {
			continue
		}
		d.event(int(m.Fd), int(m.Pid))
		_ = unix.Close(int(m.Fd))
	}
}

func (d *Decoys) event(fd, pid int) {
	if pid == d.self {
		return
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		return
	}
	key := fileKey{dev: uint64(st.Dev), ino: st.Ino} //nolint:unconvert,gosec // Dev's type differs between platforms
	full, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return
	}
	dir := path.Dir(full)
	now := d.now()
	d.mu.Lock()
	decoy, isDecoy := d.files[key]
	d.mu.Unlock()
	if !isDecoy {
		d.opened(pid, key, dir, now)
		return
	}
	for _, r := range d.pending {
		if r.pid == pid && r.path == decoy {
			return
		}
	}
	if len(d.pending) >= maxPendingReads {
		d.Dropped.Add(1)
		return
	}
	// The process is read now: it may be gone by the time the read is judged.
	e := Event{At: now.UTC(), Class: ClassDecoy, Op: "read", Path: decoy, PID: pid}
	if p, ok := system.ReadProcess(d.proc, pid); ok {
		uid, euid := p.UID, p.EUID
		e.User, e.EUser, e.PPID = &uid, &euid, p.PPID
		e.Exe, e.Comm, e.Cmdline, e.CommandSum, e.Cwd = clipText(p.Exe), clipText(p.Comm), clipCmdline(p.Cmdline), commandSum(p), clipText(p.Cwd)
		if parent, ok := system.ReadProcess(d.proc, p.PPID); ok {
			e.Parent = clipText(parent.Comm)
		}
	}
	d.pending = append(d.pending, decoyRead{at: now, pid: pid, path: decoy, dir: dir, ev: e})
}

// opened remembers an open of another file in a decoy's directory, within the bounds: the oldest
// process forgotten first, and a process's files beyond maxSweepFiles not counted, which is past
// the threshold anyway.
func (d *Decoys) opened(pid int, key fileKey, dir string, now time.Time) {
	p := d.recent[pid]
	if p == nil {
		if len(d.recent) >= maxSweepProcs {
			oldest, at := 0, now
			for id, o := range d.recent {
				if o.last.Before(at) {
					oldest, at = id, o.last
				}
			}
			delete(d.recent, oldest)
		}
		p = &procOpens{files: map[fileKey]dirOpen{}}
		d.recent[pid] = p
	}
	p.last = now
	if _, ok := p.files[key]; ok || len(p.files) < maxSweepFiles {
		p.files[key] = dirOpen{dir: dir, at: now}
	}
}

// decide sends the reads held for DecoyHold, or all of them when the watcher stops, and forgets
// the opens older than SweepWindow and DecoyHold together.
func (d *Decoys) decide(now time.Time, all bool) {
	kept := d.pending[:0]
	for _, r := range d.pending {
		if !all && now.Sub(r.at) < DecoyHold {
			kept = append(kept, r)
			continue
		}
		if d.sweep(r) {
			r.ev.Reason = ReasonSweep
		}
		select {
		case d.out <- r.ev:
		default:
			d.Dropped.Add(1)
		}
	}
	d.pending = kept
	for pid, p := range d.recent {
		if now.Sub(p.last) > SweepWindow+DecoyHold {
			delete(d.recent, pid)
			continue
		}
		for k, o := range p.files {
			if now.Sub(o.at) > SweepWindow+DecoyHold {
				delete(p.files, k)
			}
		}
	}
}

// sweep reports whether the process that read r opened SweepFiles other files of the decoy's
// directory within SweepWindow before the read or DecoyHold after it.
func (d *Decoys) sweep(r decoyRead) bool {
	p := d.recent[r.pid]
	if p == nil {
		return false
	}
	n := 0
	for _, o := range p.files {
		if o.dir == r.dir && !o.at.Before(r.at.Add(-SweepWindow)) && !o.at.After(r.at.Add(DecoyHold)) {
			n++
		}
	}
	return n >= SweepFiles
}
