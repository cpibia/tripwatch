//go:build linux

package watch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cpibia/tripwatch/internal/collector"
)

// watchMask is what each watched directory reports. IN_DONT_FOLLOW and IN_ONLYDIR keep a
// planted symlink from turning a watch onto another directory.
const watchMask = unix.IN_CREATE | unix.IN_CLOSE_WRITE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO |
	unix.IN_ATTRIB | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_ONLYDIR | unix.IN_DONT_FOLLOW | unix.IN_EXCL_UNLINK

// watched is one directory under watch, with the targets it serves: several targets can share a
// directory (/etc for accounts, privilege and hooks), and the kernel gives them one descriptor.
type watched struct {
	dir     string
	targets []Target
	depth   int
}

// Files watches the targets' directories with inotify and sends what changes in them.
type Files struct {
	root   string
	src    collector.Source
	out    chan<- Event
	now    func() time.Time
	fd     int
	mu     sync.Mutex
	byWD   map[int]*watched
	byDir  map[string]int
	issues collector.Issues
	// scratchSeen are the executables reported in the scratch directories, whose removal is
	// reported too. Only the goroutine reading the kernel's queue touches it.
	scratchSeen map[string]bool
	// known is the last content seen of files outside the uploads, by path, for PrevSHA256.
	known map[string]string
	// gaps are the places left unwatched by the bounds since the sensor started, kept across
	// Set: a directory too deep or too full stays a gap until someone looks at it.
	gaps []string
	// hashed counts the bytes hashed in the current second against hashBudget, apart for files
	// of root and of other users: a user cannot create files of root, so cannot spend their
	// budget and leave root's changes without a hash.
	hashed   [2]int64
	hashedAt time.Time
	// Dropped counts events lost because the consumer did not keep up.
	Dropped atomic.Int64
}

// NewFiles opens an inotify instance for the filesystem at root, read through src.
func NewFiles(root string, src collector.Source, out chan<- Event) (*Files, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	return &Files{root: path.Clean(root), src: src, out: out, now: time.Now, fd: fd, byWD: map[int]*watched{}, byDir: map[string]int{}, known: map[string]string{}, scratchSeen: map[string]bool{}}, nil
}

// Close releases the inotify instance and every watch with it.
func (f *Files) Close() error { return unix.Close(f.fd) }

// Issues returns what could not be watched, such as the kernel's watch limit.
func (f *Files) Issues() collector.Issues {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append(append(collector.Issues(nil), f.issues...), f.gaps...)
}

// maxGaps bounds the unwatched places remembered: past it, the count says enough.
const maxGaps = 20

// gap records a place the bounds leave unwatched. Callers hold f.mu.
func (f *Files) gap(msg string) {
	if slices.Contains(f.gaps, msg) {
		return
	}
	if len(f.gaps) == maxGaps {
		f.gaps[maxGaps-1] = "watch: more places are not watched, past the bounds"
		return
	}
	f.gaps = append(f.gaps, msg)
}

// Watches is how many directories are under watch.
func (f *Files) Watches() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.byWD)
}

// Set watches the targets' directories that exist, and stops watching the directories no
// target names any more. It is called again after each snapshot, so homes and upload
// directories that appeared since are picked up.
func (f *Files) Set(targets []Target) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issues = nil
	keep := map[string][]Target{}
	depths := map[string]int{}
	for _, t := range targets {
		f.expand(t, t.Dir, 0, keep, depths)
	}
	for dir, wd := range f.byDir {
		if _, ok := keep[dir]; !ok {
			_, _ = unix.InotifyRmWatch(f.fd, uint32(wd)) //nolint:gosec // watch descriptors the kernel returned are never negative
			delete(f.byDir, dir)
			delete(f.byWD, wd)
		}
	}
	for dir, ts := range keep {
		f.add(dir, ts, depths[dir])
	}
	// The keys files' content as the watch starts, so that a key added and removed later is
	// recognised even if the file has not changed in months.
	for dir, ts := range keep {
		for _, t := range ts {
			if t.Class != ClassSSH {
				continue
			}
			for _, name := range []string{"authorized_keys", "authorized_keys2"} {
				p := path.Join(dir, name)
				if info, err := fs.Lstat(f.src.FS, collector.Rel(p)); err == nil && info.Mode().IsRegular() && info.Size() <= maxEventHash {
					if file, err := collector.DescribeNoFollow(f.src, collector.Rel(p)); err == nil && file.SHA256 != "" {
						f.remember(p, file.SHA256)
					}
				}
			}
		}
	}
}

// maxKnown bounds the contents remembered.
const maxKnown = 4096

// remember records the content of a file outside the uploads and returns the one before.
// Callers hold f.mu.
func (f *Files) remember(p, sha string) string {
	prev := f.known[p]
	switch {
	case sha == "":
		delete(f.known, p)
	case prev != "" || len(f.known) < maxKnown:
		f.known[p] = sha
	}
	return prev
}

// expand collects dir for target t and, for a recursive target, its subdirectories.
func (f *Files) expand(t Target, dir string, depth int, keep map[string][]Target, depths map[string]int) {
	if len(keep) >= MaxWatches {
		f.gap(fmt.Sprintf("watch: more than %d directories to watch: %s and others are not watched", MaxWatches, dir))
		return
	}
	info, err := fs.Lstat(f.src.FS, collector.Rel(dir))
	if err != nil || !info.IsDir() {
		return
	}
	keep[dir] = append(keep[dir], t)
	depths[dir] = depth
	if !t.Recursive {
		return
	}
	entries, err := fs.ReadDir(f.src.FS, collector.Rel(dir))
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if depth >= MaxDepth {
			f.gap(fmt.Sprintf("watch: %s has directories deeper than %d levels below %s, not watched", dir, MaxDepth, t.Dir))
			break
		}
		f.expand(t, path.Join(dir, e.Name()), depth+1, keep, depths)
	}
}

// add places or refreshes the watch on dir. Callers hold f.mu.
func (f *Files) add(dir string, targets []Target, depth int) {
	if _, ok := f.byDir[dir]; !ok && len(f.byWD) >= MaxWatches {
		f.gap(fmt.Sprintf("watch: more than %d directories to watch: %s and others are not watched", MaxWatches, dir))
		return
	}
	wd, err := unix.InotifyAddWatch(f.fd, f.abs(dir), watchMask)
	if err != nil {
		if errors.Is(err, unix.ENOSPC) {
			f.issues.Add(errors.New("watch: the kernel's inotify watch limit is reached (fs.inotify.max_user_watches): " + dir + " is not watched"))
		}
		return
	}
	f.byDir[dir] = wd
	f.byWD[wd] = &watched{dir: dir, targets: targets, depth: depth}
}

func (f *Files) abs(dir string) string {
	if f.root == "/" {
		return dir
	}
	return f.root + dir
}

// Run reads the kernel's notifications until ctx ends.
func (f *Files) Run(ctx context.Context) error {
	buf := make([]byte, 64<<10)
	fds := []unix.PollFd{{Fd: int32(f.fd), Events: unix.POLLIN}} //nolint:gosec // a file descriptor fits in the int32 poll takes
	for ctx.Err() == nil {
		n, err := unix.Poll(fds, 500)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if n <= 0 {
			continue
		}
		read, err := unix.Read(f.fd, buf)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		f.handle(buf[:read])
	}
	return nil
}

// handle parses a buffer of inotify events.
func (f *Files) handle(b []byte) {
	for len(b) >= unix.SizeofInotifyEvent {
		raw := (*unix.InotifyEvent)(unsafe.Pointer(&b[0])) //nolint:gosec // the kernel writes inotify_event records into this buffer; the length is checked before use
		size := unix.SizeofInotifyEvent + int(raw.Len)
		if size > len(b) {
			return
		}
		name := strings.TrimRight(string(b[unix.SizeofInotifyEvent:size]), "\x00")
		f.event(int(raw.Wd), raw.Mask, name)
		b = b[size:]
	}
	if len(b) > 0 && f.out != nil {
		f.Dropped.Add(1)
	}
}

func (f *Files) event(wd int, mask uint32, name string) {
	if mask&unix.IN_Q_OVERFLOW != 0 {
		f.Dropped.Add(1)
		return
	}
	f.mu.Lock()
	w := f.byWD[wd]
	if w != nil && mask&(unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_IGNORED) != 0 && name == "" {
		delete(f.byWD, wd)
		delete(f.byDir, w.dir)
	}
	f.mu.Unlock()
	if w == nil || name == "" {
		return
	}
	full := path.Join(w.dir, name)
	isDir := mask&unix.IN_ISDIR != 0
	op := ""
	switch {
	case mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0:
		op = OpCreate
	case mask&unix.IN_CLOSE_WRITE != 0:
		op = OpWrite
	case mask&(unix.IN_DELETE|unix.IN_MOVED_FROM) != 0:
		op = OpDelete
	case mask&unix.IN_ATTRIB != 0:
		op = OpAttrib
	default:
		return
	}
	for _, t := range w.targets {
		if spawned, ok := t.Spawn[name]; ok && isDir {
			if op == OpCreate {
				f.watchNew(full, spawned, 0)
			}
			f.emit(f.describe(spawned.Class, op, full, isDir))
			continue
		}
		if !t.wants(name) {
			continue
		}
		if isDir && op == OpCreate && t.Recursive {
			if w.depth < MaxDepth {
				f.watchNew(full, t, w.depth+1)
			} else {
				f.mu.Lock()
				f.gap(fmt.Sprintf("watch: %s has directories deeper than %d levels below %s, not watched", w.dir, MaxDepth, t.Dir))
				f.mu.Unlock()
			}
		}
		f.emit(f.describe(t.Class, op, full, isDir))
	}
}

// maxNewEntries bounds what is reported of a directory found already filled when it is created.
const maxNewEntries = 64

// watchNew watches a directory created under a recursive target, then reports what is already
// in it: a file can land there before the watch exists.
func (f *Files) watchNew(dir string, t Target, depth int) {
	f.mu.Lock()
	f.add(dir, []Target{t}, depth)
	f.mu.Unlock()
	entries, err := fs.ReadDir(f.src.FS, collector.Rel(dir))
	if err != nil {
		return
	}
	for i, e := range entries {
		if i == maxNewEntries {
			f.mu.Lock()
			f.gap(fmt.Sprintf("watch: %s held more than %d entries when it was created: the rest were not reported", dir, maxNewEntries))
			f.mu.Unlock()
			break
		}
		if !t.wants(e.Name()) {
			continue
		}
		child := path.Join(dir, e.Name())
		f.emit(f.describe(t.Class, OpCreate, child, e.IsDir()))
		// mkdir -p makes the whole chain before the first watch is placed.
		if e.IsDir() && t.Recursive {
			if depth >= MaxDepth {
				f.mu.Lock()
				f.gap(fmt.Sprintf("watch: %s has directories deeper than %d levels below %s, not watched", dir, MaxDepth, t.Dir))
				f.mu.Unlock()
				continue
			}
			f.watchNew(child, t, depth+1)
		}
	}
}

// Hashing bounds: events are described on the goroutine that reads the kernel's queue, so a
// large file touched in a loop must not stall it. Larger files, and any once the second's budget
// is spent, are reported with their metadata only.
const (
	maxEventHash = 1 << 20
	hashBudget   = 16 << 20
)

// describe builds the event, with what a regular file holds after the change. A link is
// reported as a link and never followed: one planted in an upload directory must not make the
// sensor read, or open, what it points to.
func (f *Files) describe(class, op, p string, isDir bool) Event {
	e := Event{At: f.now().UTC(), Class: class, Op: op, Path: p, Dir: isDir}
	if op == OpDelete && systemClass(class) {
		f.mu.Lock()
		e.PrevSHA256 = f.remember(p, "")
		f.mu.Unlock()
	}
	if op == OpDelete || isDir {
		return e
	}
	info, err := fs.Lstat(f.src.FS, collector.Rel(p))
	if err != nil {
		return e
	}
	meta := collector.Metadata(collector.Rel(p), info)
	e.Mode, e.UID = meta.Mode, meta.UID
	if !info.Mode().IsRegular() {
		return e
	}
	e.Size = info.Size()
	// Most of what is written in /tmp is not executable and is dropped: no need to read it.
	if class == ClassScratch && !Executable(e.Mode) {
		return e
	}
	// Root's budget is for root's files on system paths: in the uploads and the scratch
	// directories the web server's user can rename a file of root left behind in a loop and
	// spend it.
	if info.Size() > maxEventHash || !f.spend(info.Size(), systemClass(class) && e.UID != nil && *e.UID == 0 && f.rootDir(path.Dir(p))) {
		return e
	}
	file, err := collector.DescribeNoFollow(f.src, collector.Rel(p))
	if err != nil {
		return e
	}
	e.Size, e.SHA256, e.UID, e.Mode = file.Size, file.SHA256, file.UID, file.Mode
	if systemClass(class) {
		f.mu.Lock()
		e.PrevSHA256 = f.remember(p, e.SHA256)
		f.mu.Unlock()
	}
	return e
}

// rootDir reports whether only root can change the entries of a directory: there a file of
// root cannot have been renamed in by another user.
func (f *Files) rootDir(dir string) bool {
	info, err := fs.Lstat(f.src.FS, collector.Rel(dir))
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	uid, ok := collector.Owner(info)
	return ok && uid == 0
}

// spend takes n bytes from this second's hashing budget, root's or the other users'.
func (f *Files) spend(n int64, root bool) bool {
	now := f.now()
	if now.Sub(f.hashedAt) >= time.Second {
		f.hashed, f.hashedAt = [2]int64{}, now
	}
	i := 0
	if root {
		i = 1
	}
	if f.hashed[i]+n > hashBudget {
		return false
	}
	f.hashed[i] += n
	return true
}

// maxScratchSeen bounds the executables remembered in the scratch directories.
const maxScratchSeen = 1024

// emit sends an event, keeping of the scratch directories only executable files, and the
// removal of those it reported: the rest of what happens in /tmp is noise.
func (f *Files) emit(e Event) {
	if e.Class == ClassScratch {
		switch {
		case e.Dir:
			return
		case e.Op == OpDelete:
			if !f.scratchSeen[e.Path] {
				return
			}
			delete(f.scratchSeen, e.Path)
		case !Executable(e.Mode):
			return
		case len(f.scratchSeen) < maxScratchSeen:
			f.scratchSeen[e.Path] = true
		}
	}
	f.send(e)
}

func (f *Files) send(e Event) {
	select {
	case f.out <- e:
	default:
		f.Dropped.Add(1)
	}
}

// wants reports whether a target keeps an entry name.
func (t Target) wants(name string) bool {
	if len(t.Names) == 0 {
		return true
	}
	for _, n := range t.Names {
		if n == name {
			return true
		}
	}
	return false
}
