//go:build linux

package watch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/web"
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
	scratchSeen map[string]time.Time
	// webUsers are the web server's UIDs, whose files in the scratch directories are marked.
	webUsers map[int]bool
	// classEvents counts the events of the scratch directories and of the uploads handled this
	// second, against maxClassEvents, and scratchByUID those of each owner in the scratch
	// directories, against maxScratchPerUID.
	classEvents   map[string]int
	scratchByUID  map[uint32]int
	scratchSecond time.Time
	// scratchRepeats are the events of the scratch directories handled this second; a repeat
	// is put in deferred, path to operation, and looked at once a second later, at no cost to
	// the budget meanwhile.
	scratchRepeats map[string]string
	deferred       map[string]string
	deferredAt     time.Time
	// known is the last content seen of files outside the uploads, by path, for PrevSHA256.
	known map[string]string
	// targets are the last ones Set was given; replanAt, when set, is when Run sets them again,
	// after a watched root moved away or the kernel's queue overflowed; missing are the roots
	// that existed and are gone, with the retries left.
	targets  []Target
	replanAt time.Time
	missing  map[string]int
	// roots is the identity of each target's root directory when its watch was placed, and
	// rootsCheckedAt when Run last compared them with the paths: a watch follows the inode, so a
	// root replaced under the same name, or one whose rename the kernel reported out of order,
	// would stay unwatched without that check.
	roots          map[string]fileID
	rootsCheckedAt time.Time
	// moves are renames of watched directories waiting for their second half, by cookie;
	// renamed marks the watches whose records already follow a rename.
	moves   map[uint32]move
	renamed map[int]bool
	// gaps are the places left unwatched by the bounds since the sensor started, kept across
	// Set: a directory too deep or too full stays a gap until someone looks at it.
	gaps []string
	// unwatched are the gaps outside the scratch directories, which the verifier raises.
	unwatched []string
	// classWatches counts the watches serving a single class, for the classes with a budget.
	classWatches map[string]int
	// hashed counts the bytes hashed in the current second against hashBudget, apart for files
	// of root and of other users: a user cannot create files of root, so cannot spend their
	// budget and leave root's changes without a hash.
	hashed   [2]int64
	hashedAt time.Time
	// Dropped counts events lost because the consumer did not keep up; DroppedSystem those of
	// them that were root's; DroppedBudget those let go over the per-second budget of the places
	// anyone writes in, the scratch directories and the uploads.
	Dropped       atomic.Int64
	DroppedSystem atomic.Int64
	DroppedBudget atomic.Int64
	// Urgent, when set before Run, takes the events IsRootEvent says are root's, so that a flood
	// another account makes in its home or the uploads never fills their way.
	Urgent      chan<- Event
	IsRootEvent func(Event) bool
}

// NewFiles opens an inotify instance for the filesystem at root, read through src.
func NewFiles(root string, src collector.Source, out chan<- Event) (*Files, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	return &Files{root: path.Clean(root), src: src, out: out, now: time.Now, fd: fd, byWD: map[int]*watched{}, byDir: map[string]int{}, known: map[string]string{}, scratchSeen: map[string]time.Time{}, moves: map[uint32]move{}, renamed: map[int]bool{}, missing: map[string]int{}, roots: map[string]fileID{}, classWatches: map[string]int{}, scratchByUID: map[uint32]int{}, classEvents: map[string]int{}, scratchRepeats: map[string]string{}, deferred: map[string]string{}}, nil
}

// fileID tells one inode from another.
type fileID struct {
	dev, ino uint64
}

// rootOnly reports whether only root can enter dir: a root-owned directory that grants its group
// and everyone else no search permission (an ACL entry shows in the group bits). Nothing below it
// can be created or reached by another user, so directories deeper than the watch there, like
// the private /tmp snapd keeps for a snap, are not a way to hide from it.
func (f *Files) rootOnly(dir string) bool {
	info, err := fs.Lstat(f.src.FS, collector.Rel(dir))
	if err != nil || !info.IsDir() {
		return false
	}
	uid, ok := collector.Owner(info)
	return ok && uid == 0 && info.Mode().Perm()&0o011 == 0
}

// identity is the inode behind dir in the observed filesystem, or false when there is no
// directory there.
func (f *Files) identity(dir string) (fileID, bool) {
	info, err := fs.Lstat(f.src.FS, collector.Rel(dir))
	if err != nil || !info.IsDir() {
		return fileID{}, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}
	return fileID{dev: uint64(st.Dev), ino: st.Ino}, true //nolint:unconvert // Dev is already 64 bits wide on linux/amd64 and arm64, not on every port
}

// isRoot says whether dir is the root of one of the targets it is watched for.
func isRoot(dir string, targets []Target) bool {
	for _, t := range targets {
		if t.Dir == dir {
			return true
		}
	}
	return false
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
// maxGapsPerClass bounds those listed for each class, so the places anyone can fill (scratch)
// never crowd out those that matter (uploads, system).
const (
	maxGaps         = 20
	maxGapsPerClass = 5
)

// Unwatched returns the places of the system, the homes and the uploads left unwatched.
func (f *Files) Unwatched() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.unwatched...)
}

// gap records a place the bounds leave unwatched. Callers hold f.mu.
func (f *Files) gap(class, msg string) {
	if entry := class + ": " + msg; !slices.Contains(f.unwatched, entry) {
		listed := 0
		for _, u := range f.unwatched {
			if strings.HasPrefix(u, class+": ") {
				listed++
			}
		}
		switch {
		case listed < maxGapsPerClass-1:
			f.unwatched = append(f.unwatched, entry)
		case listed == maxGapsPerClass-1:
			f.unwatched = append(f.unwatched, class+": watch: more places of class "+class+" are not watched, past the bounds")
		}
	}
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
	targets = f.globTargets(targets)
	f.targets = append([]Target(nil), targets...)
	f.issues, f.unwatched = nil, nil
	keep := map[string][]Target{}
	depths := map[string]int{}
	planned := map[string]int{}
	for _, t := range targets {
		f.expand(t, t.Dir, 0, keep, depths, planned)
	}
	for dir, wd := range f.byDir {
		if _, ok := keep[dir]; !ok {
			_, _ = unix.InotifyRmWatch(f.fd, uint32(wd)) //nolint:gosec // watch descriptors the kernel returned are never negative
			f.forget(wd)
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
func (f *Files) expand(t Target, dir string, depth int, keep map[string][]Target, depths map[string]int, planned map[string]int) {
	if len(keep) >= MaxWatches {
		f.gap(t.Class, fmt.Sprintf("watch: more than %d directories to watch: %s and others are not watched", MaxWatches, dir))
		return
	}
	info, err := fs.Lstat(f.src.FS, collector.Rel(dir))
	if err != nil || !info.IsDir() {
		if tries, gone := f.missing[dir]; gone && dir == t.Dir {
			f.gap(t.Class, fmt.Sprintf("watch: %s was moved away or removed and is not back", dir))
			if tries > 0 {
				f.missing[dir] = tries - 1
				f.replanAt = f.now().Add(replanDelay)
			}
		}
		return
	}
	if dir == t.Dir {
		delete(f.missing, dir)
	}
	if _, seen := keep[dir]; !seen {
		if limit := classBudget[t.Class]; limit > 0 {
			if planned[t.Class] >= limit {
				f.gap(t.Class, fmt.Sprintf("watch: more than %d directories of class %s: %s and others are not watched", limit, t.Class, dir))
				return
			}
			planned[t.Class]++
		}
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
		if depth >= t.depth() {
			if !f.rootOnly(dir) {
				f.gap(t.Class, fmt.Sprintf("watch: %s has directories deeper than %d levels below %s, not watched", dir, t.depth(), t.Dir))
			}
			break
		}
		f.expand(t, path.Join(dir, e.Name()), depth+1, keep, depths, planned)
	}
}

// add places or refreshes the watch on dir. Callers hold f.mu.
func (f *Files) add(dir string, targets []Target, depth int) {
	class := targets[0].Class
	cls := classOf(targets)
	_, existing := f.byDir[dir]
	if !existing && len(f.byWD) >= MaxWatches {
		f.gap(class, fmt.Sprintf("watch: more than %d directories to watch: %s and others are not watched", MaxWatches, dir))
		return
	}
	if limit := classBudget[cls]; !existing && limit > 0 && f.classWatches[cls] >= limit {
		f.gap(class, fmt.Sprintf("watch: more than %d directories of class %s: %s and others are not watched", limit, cls, dir))
		return
	}
	root := isRoot(dir, targets)
	wd, err := unix.InotifyAddWatch(f.fd, f.abs(dir), watchMask)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOSPC):
			f.issues.Add(errors.New("watch: the kernel's inotify watch limit is reached (fs.inotify.max_user_watches): " + dir + " is not watched"))
		case root && !slices.ContainsFunc(targets, func(t Target) bool { return t.Dir == dir && t.Ephemeral }):
			// The directory was there a moment ago, when the plan listed it: a root moved
			// away again is tried again, like one whose move the kernel reported.
			f.rootLost(dir, class)
		}
		return
	}
	if w := f.byWD[wd]; w != nil {
		f.classWatches[classOf(w.targets)]--
	}
	f.byDir[dir] = wd
	f.byWD[wd] = &watched{dir: dir, targets: targets, depth: depth}
	f.classWatches[cls]++
	if root {
		if id, ok := f.identity(dir); ok {
			f.roots[dir] = id
		}
	}
}

// forget drops the record of a watch the kernel removed or Set no longer wants. Callers hold
// f.mu.
func (f *Files) forget(wd int) {
	w := f.byWD[wd]
	if w == nil {
		return
	}
	f.classWatches[classOf(w.targets)]--
	delete(f.renamed, wd)
	delete(f.byWD, wd)
	delete(f.byDir, w.dir)
	delete(f.roots, w.dir)
}

// Replanning after a watched root went away: soon, and for a minute at most.
const (
	replanDelay   = 2 * time.Second
	replanRetries = 30
)

// rootGone reports the root of a watched place moved away or removed, as an event and as a
// gap, and plans its watch again: moved back, or recreated, it is watched within seconds.
// Callers hold f.mu.
func (f *Files) rootGone(w *watched) {
	for _, t := range w.targets {
		if t.Dir == w.dir {
			if !t.Ephemeral {
				f.rootLost(w.dir, t.Class)
			}
			return
		}
	}
}

// rootLost is rootGone for a root known by path. Callers hold f.mu.
func (f *Files) rootLost(dir, class string) {
	f.gap(class, fmt.Sprintf("watch: %s was moved away or removed", dir))
	f.missing[dir] = replanRetries
	f.replanAt = f.now().Add(replanDelay)
	f.send(Event{At: f.now().UTC(), Class: class, Op: OpDelete, Path: dir, Dir: true, Root: true})
}

// replanSoon plans the watches again once a burst of renames settles: a plan made in the
// middle of one, with half its events still queued, would be undone by the other half.
// Callers hold f.mu.
func (f *Files) replanSoon() {
	if at := f.now().Add(time.Second); f.replanAt.IsZero() || f.replanAt.Before(at) {
		f.replanAt = at
	}
}

// replanIfDue sets the targets again once a replan is due.
func (f *Files) replanIfDue() {
	f.mu.Lock()
	due := !f.replanAt.IsZero() && !f.now().Before(f.replanAt)
	targets := f.targets
	if due {
		f.replanAt = time.Time{}
	}
	f.mu.Unlock()
	if due {
		f.Set(targets)
	}
}

// rootsCheckEvery is how often the roots are compared with the paths they were watched at.
const rootsCheckEvery = 2 * time.Second

// checkRoots finds the roots the kernel's events could not report: one replaced under its name
// by another directory (an ancestor moved aside and recreated), one whose watch could not be
// placed, or one back after the retries ran out. Each is a few dozen Lstat every few seconds.
func (f *Files) checkRoots() {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	if now.Sub(f.rootsCheckedAt) < rootsCheckEvery {
		return
	}
	f.rootsCheckedAt = now
	for _, t := range f.targets {
		id, exists := f.identity(t.Dir)
		wd, watched := f.byDir[t.Dir]
		switch {
		case watched && !exists:
			f.rootGone(f.byWD[wd])
			f.unwatchTree(t.Dir)
		case watched && f.roots[t.Dir] != id:
			// The old inode's watches would keep reporting under a path that is now another
			// directory's: they go, and the directory now at the path is watched afresh.
			f.rootGone(f.byWD[wd])
			f.unwatchTree(t.Dir)
		case !watched && exists:
			if _, gone := f.missing[t.Dir]; gone && f.replanAt.IsZero() {
				f.replanAt = now
			}
		}
	}
}

// maxMoves bounds the renames waiting for their second half.
const maxMoves = 1024

// moved follows a watched directory renamed within the perimeter: the first half of a rename
// records its old path by cookie, the second moves the records of the directory and of every
// directory below it to the new path, so their events keep coming under the right names.
// Callers hold f.mu.
func (f *Files) moved(mask, cookie uint32, full string, parent *watched) bool {
	if mask&unix.IN_MOVED_FROM != 0 {
		if wd, watched := f.byDir[full]; watched {
			if len(f.moves) >= maxMoves {
				clear(f.moves)
			}
			f.moves[cookie] = move{from: full, wd: wd}
		}
		return false
	}
	m, ok := f.moves[cookie]
	if !ok {
		return false
	}
	delete(f.moves, cookie)
	old, wd := m.from, m.wd
	if cur, ok := f.byWD[wd]; !ok || cur.dir != old {
		return false
	}
	// Two directories swapped in one call (renameat2 with RENAME_EXCHANGE): both paths change
	// meaning at once, and planning the watches again is simpler than following both.
	if other, taken := f.byDir[full]; taken && other != wd {
		// Both inodes stay watched: their MOVE_SELF must not unwatch them.
		f.renamed[wd], f.renamed[other] = true, true
		f.replanSoon()
		return true
	}
	// A move into another kind of place (from the uploads to /tmp) is a new directory there:
	// the old watches go now, and the event that follows places new ones. The root of a
	// target moved within its parent (/etc/sudoers.d to /etc/s.x) is reported here: its own
	// MOVE_SELF comes after and finds no record.
	if moving := f.byWD[wd]; moving == nil || !sameTargets(moving.targets, parent.targets) {
		if moving != nil {
			f.rootGone(moving)
		}
		f.unwatchTree(old)
		return false
	}
	for dir, d := range f.byDir {
		if dir != old && !strings.HasPrefix(dir, old+"/") {
			continue
		}
		renamed := full + strings.TrimPrefix(dir, old)
		delete(f.byDir, dir)
		f.byDir[renamed] = d
		if rec := f.byWD[d]; rec != nil {
			rec.dir = renamed
		}
	}
	f.renamed[wd] = true
	return true
}

// move is the first half of a rename of a watched directory.
type move struct {
	from string
	wd   int
}

// unwatchTree removes from the kernel and from the records the watches of dir and of every
// directory below it. Callers hold f.mu.
func (f *Files) unwatchTree(dir string) {
	for d, wd := range f.byDir {
		if d == dir || strings.HasPrefix(d, dir+"/") {
			_, _ = unix.InotifyRmWatch(f.fd, uint32(wd)) //nolint:gosec // watch descriptors the kernel returned are never negative
			f.forget(wd)
		}
	}
}

func sameTargets(a, b []Target) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Dir != b[i].Dir || a[i].Class != b[i].Class {
			return false
		}
	}
	return true
}

// classBudget caps the watches of the classes anyone can fill with directories, so that they
// never take the watches of the system and the homes, at startup or later.
var classBudget = map[string]int{ClassScratch: MaxScratchWatches, ClassUpload: MaxUploadWatches}

// classOf is the class all of a watch's targets share, or "" when they differ.
func classOf(targets []Target) string {
	if len(targets) == 0 {
		return ""
	}
	for _, t := range targets[1:] {
		if t.Class != targets[0].Class {
			return ""
		}
	}
	return targets[0].Class
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
		f.checkRoots()
		f.replanIfDue()
		f.flushDeferred()
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
		f.event(int(raw.Wd), raw.Mask, raw.Cookie, name)
		b = b[size:]
	}
	if len(b) > 0 && f.out != nil {
		f.Dropped.Add(1)
	}
}

func (f *Files) event(wd int, mask uint32, cookie uint32, name string) {
	if mask&unix.IN_Q_OVERFLOW != 0 {
		// Events were lost, renames among them: the records may no longer match the kernel's
		// watches, so they are planned again from the targets.
		f.Dropped.Add(1)
		f.mu.Lock()
		// A replan already planned is not put off: under overflows a second apart it would
		// never come, and a root moved meanwhile would stay blind for the whole flood.
		if f.replanAt.IsZero() {
			f.replanAt = f.now().Add(time.Second)
		}
		f.mu.Unlock()
		return
	}
	f.mu.Lock()
	w := f.byWD[wd]
	if w != nil && name == "" {
		switch {
		case mask&(unix.IN_DELETE_SELF|unix.IN_IGNORED) != 0:
			if mask&unix.IN_DELETE_SELF != 0 {
				f.rootGone(w)
			}
			f.forget(wd)
		case mask&unix.IN_MOVE_SELF != 0:
			// The kernel reports the moved directory after both sides of the rename: if the
			// new side was in the perimeter its records already follow it; otherwise it left,
			// and its watches, kept by the kernel on the inode, are removed with it.
			if f.renamed[wd] {
				delete(f.renamed, wd)
			} else {
				f.rootGone(w)
				f.unwatchTree(w.dir)
				// A move not followed may be half of a burst of renames still in the queue.
				f.replanSoon()
			}
		}
	}
	f.mu.Unlock()
	if w == nil || name == "" {
		return
	}
	full := path.Join(w.dir, name)
	isDir := mask&unix.IN_ISDIR != 0
	// A rename followed within the watched places already carries its watches: listing the
	// directory again would report its whole content as new.
	followed := false
	if isDir && mask&(unix.IN_MOVED_FROM|unix.IN_MOVED_TO) != 0 {
		f.mu.Lock()
		followed = f.moved(mask, cookie, full, w)
		f.mu.Unlock()
	}
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
	// A directory two targets of one class reach (a service's private /tmp, also below /tmp)
	// reports each event once.
	classes := map[string]bool{}
	for _, t := range w.targets {
		if spawned, ok := t.Spawn[name]; ok && isDir {
			if op == OpCreate {
				f.watchNew(full, spawned, 0)
			}
			f.emit(f.describe(spawned.Class, op, full, isDir))
			continue
		}
		if !t.wants(name) || classes[t.Class] {
			continue
		}
		classes[t.Class] = true
		// A scratch file is looked at once, for its owner and its mode: each account spends its
		// own share of the second first, so the junk one account writes by the thousand cannot
		// use up what another account's program needs, and a program spends no common budget.
		ownBudget := false
		if t.Class == ClassScratch && !isDir {
			var info fs.FileInfo
			if op != OpDelete {
				info, _ = fs.Lstat(f.src.FS, collector.Rel(full))
			}
			if f.deferRepeat(op, full, info) {
				continue
			}
			if info != nil {
				if uid, ok := collector.Owner(info); ok {
					f.rollSecond()
					if !f.scratchOwnerBudget(uid) {
						continue
					}
					ownBudget = info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
				}
			}
		}
		// In the uploads only scripts and server configuration files are judged: images and
		// junk written by the thousand must not spend the budget a script then lacks.
		if (t.Class == ClassUpload || t.Class == ClassWebRoot) && !isDir && !web.IsScript(name) && !web.IsOverride(name) {
			continue
		}
		if t.Class == ClassWebRoot && isDir {
			continue
		}
		if (t.Class == ClassScratch || t.Class == ClassUpload || t.Class == ClassWebRoot) && !ownBudget && !f.classEventBudget(t.Class) {
			if isDir && op == OpCreate {
				f.mu.Lock()
				f.gap(t.Class, fmt.Sprintf("watch: %s was created while events of class %s were over budget: not watched", full, t.Class))
				f.mu.Unlock()
			}
			continue
		}
		if isDir && op == OpCreate && t.Recursive && !followed {
			if w.depth < t.depth() {
				f.watchNew(full, t, w.depth+1)
			} else if !f.rootOnly(w.dir) {
				f.mu.Lock()
				f.gap(t.Class, fmt.Sprintf("watch: %s has directories deeper than %d levels below %s, not watched", w.dir, t.depth(), t.Dir))
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
			f.gap(t.Class, fmt.Sprintf("watch: %s held more than %d entries when it was created: the rest were not reported", dir, maxNewEntries))
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
			if depth >= t.depth() {
				if !f.rootOnly(dir) {
					f.mu.Lock()
					f.gap(t.Class, fmt.Sprintf("watch: %s has directories deeper than %d levels below %s, not watched", dir, t.depth(), t.Dir))
					f.mu.Unlock()
				}
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
		e.Mode = ""
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

// rootDir reports whether only root can change the entries of a directory and of every
// directory above it: there a file of root cannot have been renamed in by another user, nor a
// directory of root moved in by the owner of a parent.
func (f *Files) rootDir(dir string) bool {
	for {
		info, err := fs.Lstat(f.src.FS, collector.Rel(dir))
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return false
		}
		if uid, ok := collector.Owner(info); !ok || uid != 0 {
			return false
		}
		if dir == "/" || dir == "." {
			return true
		}
		dir = path.Dir(dir)
	}
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

// pruneScratch forgets the executables seen in the scratch directories more than an hour ago,
// and the older half if that is not enough: their removal is no longer a short-lived drop.
func (f *Files) pruneScratch() {
	cutoff := f.now().Add(-time.Hour)
	for p, at := range f.scratchSeen {
		if at.Before(cutoff) {
			delete(f.scratchSeen, p)
		}
	}
	if len(f.scratchSeen) < maxScratchSeen {
		return
	}
	times := make([]time.Time, 0, len(f.scratchSeen))
	for _, at := range f.scratchSeen {
		times = append(times, at)
	}
	slices.SortFunc(times, func(a, b time.Time) int { return a.Compare(b) })
	median := times[len(times)/2]
	for p, at := range f.scratchSeen {
		if !at.After(median) {
			delete(f.scratchSeen, p)
		}
	}
}

// Budgets of the scratch directories, each second: anyone can write in /tmp in a loop. The total
// bounds the sensor's work; the share of each owner keeps one account's files from hiding
// another's. What is over is counted as lost, so the flood shows.
const (
	maxClassEvents   = 20000
	maxScratchPerUID = 1000
)

// classEventBudget takes one event from this second's budget of a class anyone can write in,
// the scratch directories or the uploads. In the scratch directories each owner's share is
// taken first, and a program of an owner within its share spends none of it.
func (f *Files) classEventBudget(class string) bool {
	f.rollSecond()
	if f.classEvents[class] >= maxClassEvents {
		f.Dropped.Add(1)
		f.DroppedBudget.Add(1)
		return false
	}
	f.classEvents[class]++
	return true
}

// rollSecond starts the budgets of a new second.
func (f *Files) rollSecond() {
	if now := f.now(); now.Sub(f.scratchSecond) >= time.Second {
		clear(f.classEvents)
		clear(f.scratchByUID)
		clear(f.scratchRepeats)
		f.scratchSecond = now
	}
}

// maxDeferred bounds the scratch files waiting to be looked at again.
const maxDeferred = 4096

// deferRepeat reports whether an event of a scratch file repeats one already handled this
// second, and puts it off: rewriting the same few files in a loop costs the attacker nothing
// and would otherwise spend the budget every other account's files share. The file is looked
// at once a second later, in the state it is then. With no room left the event goes through
// the budget as usual.
func (f *Files) deferRepeat(op, full string, info fs.FileInfo) bool {
	f.rollSecond()
	// A repeat is the same operation on the same file: a name warmed up with a harmless file
	// must not hide the program written under it next within the second, which is another
	// inode or another mode.
	key, file := op+"\x00"+full, ""
	if info != nil {
		file = info.Mode().String()
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			file += ":" + strconv.FormatUint(st.Ino, 10)
		}
	}
	if seen, ok := f.scratchRepeats[key]; !ok || seen != file {
		if ok || len(f.scratchRepeats) < maxClassEvents {
			f.scratchRepeats[key] = file
		}
		return false
	}

	if _, waiting := f.deferred[full]; !waiting && len(f.deferred) >= maxDeferred {
		return false
	}
	if len(f.deferred) == 0 {
		f.deferredAt = f.now()
	}
	f.deferred[full] = op
	return true
}

// flushDeferred looks at the scratch files put off by deferRepeat once a second has passed.
func (f *Files) flushDeferred() {
	if len(f.deferred) == 0 || f.now().Sub(f.deferredAt) < time.Second {
		return
	}
	pending := f.deferred
	f.deferred = map[string]string{}
	for p, op := range pending {
		if !f.classEventBudget(ClassScratch) {
			continue
		}
		f.emit(f.describe(ClassScratch, op, p, false))
	}
}

// scratchOwnerBudget takes one event from this second's share of the file's owner. The number of
// owners is bounded by the accounts the system has: only root makes files of another UID.
func (f *Files) scratchOwnerBudget(uid uint32) bool {
	if f.scratchByUID[uid] >= maxScratchPerUID {
		f.Dropped.Add(1)
		f.DroppedBudget.Add(1)
		return false
	}
	f.scratchByUID[uid]++
	return true
}

// SetWebUsers replaces the web server's UIDs.
// maxGlobTargets bounds the directories one target with a pattern stands for.
const maxGlobTargets = 64

// globTargets replaces a target whose directory is a pattern by one target per directory it
// matches now: the private /tmp systemd and snapd give each service, found again at each Set.
func (f *Files) globTargets(targets []Target) []Target {
	out := make([]Target, 0, len(targets))
	for _, t := range targets {
		if !strings.ContainsAny(t.Dir, "*?[") {
			out = append(out, t)
			continue
		}
		matches, _ := fs.Glob(f.src.FS, collector.Rel(t.Dir))
		for i, m := range matches {
			if i == maxGlobTargets {
				break
			}
			if info, err := fs.Lstat(f.src.FS, m); err == nil && info.IsDir() {
				t := t
				t.Dir, t.Ephemeral = "/"+m, true
				out = append(out, t)
			}
		}
	}
	return out
}

func (f *Files) SetWebUsers(uids []int) {
	m := make(map[int]bool, len(uids))
	for _, u := range uids {
		m[u] = true
	}
	f.mu.Lock()
	f.webUsers = m
	f.mu.Unlock()
}

// emit sends an event, keeping of the scratch directories only executable files, and the
// removal of those it reported: the rest of what happens in /tmp is noise.
func (f *Files) emit(e Event) {
	if e.Class == ClassScratch {
		switch {
		case e.Dir:
			return
		case e.Op == OpDelete:
			if _, seen := f.scratchSeen[e.Path]; !seen {
				return
			}
			delete(f.scratchSeen, e.Path)
		case !Executable(e.Mode):
			return
		default:
			if len(f.scratchSeen) >= maxScratchSeen {
				f.pruneScratch()
			}
			f.scratchSeen[e.Path] = f.now()
		}
		if e.UID != nil {
			f.mu.Lock()
			e.WebUser = f.webUsers[int(*e.UID)]
			f.mu.Unlock()
		}
	}
	f.send(e)
}

func (f *Files) send(e Event) {
	if f.Urgent != nil && f.IsRootEvent != nil && f.IsRootEvent(e) {
		select {
		case f.Urgent <- e:
		default:
			f.Dropped.Add(1)
			f.DroppedSystem.Add(1)
		}
		return
	}
	select {
	case f.out <- e:
	default:
		f.Dropped.Add(1)
	}
}

// depth is how deep a recursive target goes.
func (t Target) depth() int {
	if t.Depth > 0 {
		return t.Depth
	}
	return MaxDepth
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
