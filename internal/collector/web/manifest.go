package web

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A manifest lists the hash of every code file of an application, in the order the walk visits
// them, so that the next run can name the files that changed where the tree hash only says which
// directory did. It is written while walking and compared with the previous one as two streams,
// so its size never costs memory, whatever the size of the application.
const (
	manifestDir = "web-manifests"
	// maxManifestFiles bounds the files listed for one application; past it, no change is named.
	maxManifestFiles = 1_000_000
	// maxChanges bounds the changes listed for one application in a snapshot; ChangeCount has
	// them all.
	maxChanges = 200
	// maxSkimmerChanges is how many files may change at once for each to be read for skimmers.
	maxSkimmerChanges = 50
	// maxManifestLine bounds one line read back: a quoted path of the longest length and a hash.
	maxManifestLine = 64 << 10
)

// Changes of a file between two runs.
const (
	ChangeAdded    = "added"
	ChangeModified = "modified"
	ChangeRemoved  = "removed"
)

// FileChange is a code file added, changed or removed since the previous run.
type FileChange struct {
	Path   string `json:"path"`
	Change string `json:"change"`
	// SHA256 is the file's content now, absent for a removal or a file too large to hash.
	SHA256 string `json:"sha256,omitempty"`
}

// manifestWriter writes the manifest of one application's run next to the one in use.
type manifestWriter struct {
	f    *os.File
	w    *bufio.Writer
	next string
	last string
	n    int
	// broken is set when the manifest cannot be trusted to be complete or ordered; reason
	// says why, for the issue that reports it.
	broken bool
	reason string
}

func (m *manifestWriter) fail(reason string) {
	if !m.broken {
		m.broken, m.reason = true, reason
	}
}

func manifestPath(stateDir, app string) string {
	sum := sha256.Sum256([]byte(app))
	return filepath.Join(stateDir, manifestDir, hex.EncodeToString(sum[:12]))
}

func newManifestWriter(stateDir, app string) (*manifestWriter, error) {
	dir := filepath.Join(stateDir, manifestDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	next := manifestPath(stateDir, app) + ".next"
	f, err := os.OpenFile(next, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // under the operator's state directory
	if err != nil {
		return nil, err
	}
	return &manifestWriter{f: f, w: bufio.NewWriterSize(f, 64<<10), next: next}, nil
}

// add records a file. Paths come in the walk's order; one out of it would make the comparison
// wrong, so the manifest is given up instead.
func (m *manifestWriter) add(name, sum string) {
	if m == nil || m.broken {
		return
	}
	switch {
	case m.n >= maxManifestFiles:
		m.fail(fmt.Sprintf("more than %d code files", maxManifestFiles))
		return
	case m.n > 0 && comparePaths(name, m.last) <= 0:
		m.fail("files listed out of order")
		return
	}
	m.last = name
	m.n++
	// The path is quoted: file names may hold tabs and line breaks.
	if _, err := fmt.Fprintf(m.w, "%s %s\n", strconv.Quote(name), sum); err != nil {
		m.fail(err.Error())
	}
}

// close finishes the file; it returns false when the manifest must not be used.
func (m *manifestWriter) close() bool {
	if err := m.w.Flush(); err != nil {
		m.fail(err.Error())
	}
	if err := m.f.Sync(); err != nil {
		m.fail(err.Error())
	}
	if err := m.f.Close(); err != nil {
		m.fail(err.Error())
	}
	if m.broken {
		_ = os.Remove(m.next)
	}
	return !m.broken
}

// comparePaths orders paths as the walk visits them: component by component, each in byte order.
func comparePaths(a, b string) int {
	for {
		ca, ra, moreA := strings.Cut(a, "/")
		cb, rb, moreB := strings.Cut(b, "/")
		if c := strings.Compare(ca, cb); c != 0 {
			return c
		}
		switch {
		case !moreA && !moreB:
			return 0
		case !moreA:
			return -1
		case !moreB:
			return 1
		}
		a, b = ra, rb
	}
}

type manifestReader struct {
	sc   *bufio.Scanner
	path string
	sum  string
	done bool
	err  error
}

func newManifestReader(f *os.File) *manifestReader {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxManifestLine)
	r := &manifestReader{sc: sc}
	r.advance()
	return r
}

func (r *manifestReader) advance() {
	if !r.sc.Scan() {
		r.done, r.err = true, r.sc.Err()
		return
	}
	line := r.sc.Text()
	i := strings.LastIndexByte(line, ' ')
	if i < 0 {
		r.done, r.err = true, errors.New("malformed manifest line")
		return
	}
	p, err := strconv.Unquote(line[:i])
	if err != nil {
		r.done, r.err = true, err
		return
	}
	r.path, r.sum = p, line[i+1:]
}

// diffManifests compares the previous manifest with the new one, both in walk order, and returns
// at most maxChanges changes and how many there were.
func diffManifests(prev, cur string) ([]FileChange, int, error) {
	pf, err := os.Open(prev) //nolint:gosec // under the operator's state directory
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = pf.Close() }()
	cf, err := os.Open(cur) //nolint:gosec // under the operator's state directory
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = cf.Close() }()
	old, now := newManifestReader(pf), newManifestReader(cf)
	var out []FileChange
	count := 0
	emit := func(c FileChange) {
		count++
		if len(out) < maxChanges {
			out = append(out, c)
		}
	}
	for !old.done || !now.done {
		switch c := cmpReaders(old, now); {
		case c < 0:
			emit(FileChange{Path: "/" + old.path, Change: ChangeRemoved})
			old.advance()
		case c > 0:
			emit(FileChange{Path: "/" + now.path, Change: ChangeAdded, SHA256: contentHash(now.sum)})
			now.advance()
		default:
			// A file hashed in one run and only fingerprinted in the other (the hash budget ran
			// out) cannot be compared; two fingerprints can, since a rewrite changes the change
			// time or the inode.
			if old.sum != now.sum && strings.HasPrefix(old.sum, "unhashed:") == strings.HasPrefix(now.sum, "unhashed:") {
				emit(FileChange{Path: "/" + now.path, Change: ChangeModified, SHA256: contentHash(now.sum)})
			}
			old.advance()
			now.advance()
		}
	}
	if err := errors.Join(old.err, now.err); err != nil {
		return nil, 0, err
	}
	return out, count, nil
}

func cmpReaders(old, now *manifestReader) int {
	switch {
	case old.done:
		return 1
	case now.done:
		return -1
	}
	return comparePaths(old.path, now.path)
}

// contentHash keeps a hash only when it is a file's content, not a link or a fingerprint.
func contentHash(sum string) string {
	if len(sum) == 64 && strings.Trim(sum, "0123456789abcdef") == "" {
		return sum
	}
	return ""
}

// finishManifest closes the manifest of a complete scan, names what changed since the one in
// use, and returns the new one for Commit. A scan cut short leaves the one in use as it was.
func (s *scanner) finishManifest(stateDir string) string {
	m := s.manifest
	if m == nil {
		return ""
	}
	cut := s.report.Truncated || s.stopped
	if cut {
		m.fail("scan cut short")
	}
	if !m.close() {
		// A cut scan already says so; anything else would switch the naming off in silence.
		if !cut {
			s.issues = append(s.issues, fmt.Sprintf("%s: manifest not written, changed files not named: %s", s.report.Path, m.reason))
		}
		return ""
	}
	prev := manifestPath(stateDir, s.report.Path)
	if _, err := os.Stat(prev); err == nil {
		changes, count, err := diffManifests(prev, m.next)
		if err != nil {
			s.issues = append(s.issues, fmt.Sprintf("%s: previous manifest unreadable, changed files not named: %v", s.report.Path, err))
		} else {
			s.report.Changes, s.report.ChangeCount = changes, count
			// A deploy rebuilds bundles that hold payment code and every library's eval at once:
			// only the few files changed outside one are judged.
			if count <= maxSkimmerChanges {
				s.inspectChanged(changes)
			}
		}
	}
	return m.next
}

// pendingManifests are the manifests written by the last Collect, waiting for its snapshot to be
// delivered before they replace the ones in use.
type pendingManifests struct {
	mu    sync.Mutex
	files []string
}

func (p *pendingManifests) set(files []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.files = files
}

func (p *pendingManifests) commit() error {
	p.mu.Lock()
	files := p.files
	p.files = nil
	p.mu.Unlock()
	var errs []error
	for _, next := range files {
		errs = append(errs, os.Rename(next, strings.TrimSuffix(next, ".next")))
	}
	return errors.Join(errs...)
}

// staleManifestAge is how long a manifest is kept after its application was last scanned: one
// in use is rewritten at every run, so an older one belongs to an application that is gone, and
// a leftover ".next" to a run that never finished.
const staleManifestAge = 7 * 24 * time.Hour

// removeStaleManifests deletes the manifests no run has rewritten for staleManifestAge. Going by
// age rather than by the applications found keeps the manifests of one that discovery missed
// for a run.
func removeStaleManifests(stateDir string, now time.Time) error {
	dir := filepath.Join(stateDir, manifestDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	var errs []error
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || now.Sub(info.ModTime()) < staleManifestAge {
			continue
		}
		errs = append(errs, os.Remove(filepath.Join(dir, e.Name())))
	}
	return errors.Join(errs...)
}
