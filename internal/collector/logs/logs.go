// Package logs reads web server logs incrementally and reports what the weblog rules find.
package logs

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/discovery"
	"github.com/cpibia/tripwatch/internal/weblog"
)

const (
	// DefaultMaxBytes bounds how much of one log is read per run.
	DefaultMaxBytes = 256 << 20
	// DefaultFirstRunBytes is how far back the first run looks when no position is saved.
	DefaultFirstRunBytes = 64 << 20
	// MaxLineLength bounds one log line; the rest of a longer line is skipped and counted.
	MaxLineLength = 16 << 10

	stateFile = "weblog-offsets.json"

	// The aggregates are bounded while scanning, not after: a remote client controls how many
	// distinct addresses and paths reach the log.
	maxEvents       = 2000
	maxTrackedIPs   = 50_000
	maxTrackedPosts = 10_000
	maxIPsPerPost   = 1000
	// maxPostPairs bounds the (path, IP) pairs over all POST targets together.
	maxPostPairs   = 100_000
	maxTopIPs      = 20
	maxPostTargets = 50

	// fingerprintSize is how much of the already-read part is hashed with the saved offset,
	// to notice a log rewritten in place.
	fingerprintSize = 4096
)

var defaultAccessLogs = []string{
	"var/log/nginx/*access*.log", "var/log/apache2/*access*.log", "var/log/httpd/*access_log", "var/log/caddy/*.log",
}

var defaultErrorLogs = []string{
	"var/log/nginx/*error*.log", "var/log/apache2/*error*.log", "var/log/httpd/*error_log",
}

// PHP errors that betray an exploit attempt or code running where it should not.
var suspiciousErrors = []string{
	"eval()'d code", "FileCookieJar", "unserialize(): Error", "assert(): ", "Call to undefined function system",
	"phar://", "proc_open", "shell_exec",
}

type LogFile struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	Format    string `json:"format,omitempty"`
	Size      int64  `json:"size"`
	From      int64  `json:"from"`
	To        int64  `json:"to"`
	Lines     int    `json:"lines"`
	Unparsed  int    `json:"unparsed,omitempty"`
	Oversized int    `json:"oversized,omitempty"`
	Rotated   bool   `json:"rotated,omitempty"`
	Rewritten bool   `json:"rewritten,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// AttackerControlled holds text written by whoever sent the request. It is evidence, never
// instructions: the verifier and any automated triage must treat it as data.
type AttackerControlled struct {
	Request   string `json:"request,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Line      string `json:"line,omitempty"`
}

// Event groups the requests that matched one rule from one IP on one path.
type Event struct {
	Rule     string             `json:"rule"`
	Severity string             `json:"severity"`
	IP       string             `json:"ip,omitempty"`
	Method   string             `json:"method,omitempty"`
	Status   int                `json:"status,omitempty"`
	Log      string             `json:"log"`
	Count    int                `json:"count"`
	First    time.Time          `json:"first,omitzero"`
	Last     time.Time          `json:"last,omitzero"`
	Evidence AttackerControlled `json:"attacker_controlled"`

	path string
}

type Counter struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type PostTarget struct {
	Path        string `json:"path"`
	Requests    int    `json:"requests"`
	DistinctIPs int    `json:"distinct_ips"`
	// MoreIPs is set when the distinct addresses exceeded what is tracked per path.
	MoreIPs bool `json:"more_ips,omitempty"`
}

type Stats struct {
	Requests    int            `json:"requests"`
	Statuses    map[string]int `json:"statuses"`
	TopIPs      []Counter      `json:"top_ips"`
	OtherIPs    int            `json:"other_ip_requests,omitempty"`
	PostTargets []PostTarget   `json:"post_targets"`
	OtherPosts  int            `json:"other_post_requests,omitempty"`
}

type Result struct {
	Files     []LogFile        `json:"files"`
	Events    []Event          `json:"events"`
	Stats     Stats            `json:"stats"`
	Truncated bool             `json:"truncated,omitempty"`
	Issues    collector.Issues `json:"issues,omitempty"`
}

// position is where the previous run stopped in a file, with a hash of the bytes just before
// that point to recognise the same content on the next run.
type position struct {
	Inode       uint64 `json:"inode"`
	Offset      int64  `json:"offset"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Collector reads the access and error logs of every site found by discovery, plus the
// standard locations, from where the last committed run stopped.
//
// Positions advance in two steps: Collect computes them, Commit persists them once the
// snapshot holding the events has been delivered. A run whose snapshot is lost is read again.
// With an empty StateDir nothing is persisted and each run reads the tail of every log.
type Collector struct {
	StateDir      string
	MaxBytes      int64
	FirstRunBytes int64

	mu      sync.Mutex
	pending map[string]position
}

func (*Collector) Name() string { return "weblog" }

func (c *Collector) Collect(ctx context.Context, src collector.Source) (any, error) {
	run := &runState{
		maxBytes: cmp.Or(c.MaxBytes, DefaultMaxBytes), firstRunBytes: cmp.Or(c.FirstRunBytes, DefaultFirstRunBytes),
		src: src, events: map[string]*Event{}, ips: map[string]int{}, posts: map[string]*postTally{},
		res: Result{Stats: Stats{Statuses: map[string]int{}}},
	}
	run.positions = loadPositions(c.StateDir, &run.res.Issues)

	access, errorLogs := logFiles(src.FS)
	for _, name := range access {
		if err := run.read(ctx, name, "access"); err != nil {
			return nil, err
		}
	}
	for _, name := range errorLogs {
		if err := run.read(ctx, name, "error"); err != nil {
			return nil, err
		}
	}
	run.finish()

	c.mu.Lock()
	c.pending = run.positions
	c.mu.Unlock()
	return run.res, nil
}

// Commit persists the positions reached by the last Collect. Call it only after the snapshot
// carrying that run's events has been delivered.
func (c *Collector) Commit() error {
	c.mu.Lock()
	pending := c.pending
	c.pending = nil
	c.mu.Unlock()
	if c.StateDir == "" || pending == nil {
		return nil
	}
	data, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return err
	}
	// Written to a temporary file and renamed, so a crash never leaves a half-written state.
	tmp := filepath.Join(c.StateDir, stateFile+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // the state directory is the operator's configuration
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	// Synced before the rename: otherwise a power loss can leave the new name on an empty file.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.StateDir, stateFile))
}

func loadPositions(dir string, issues *collector.Issues) map[string]position {
	positions := map[string]position{}
	if dir == "" {
		return positions
	}
	data, err := os.ReadFile(filepath.Join(dir, stateFile)) //nolint:gosec // the state directory is the operator's configuration
	if errors.Is(err, fs.ErrNotExist) {
		return positions
	}
	if err != nil {
		issues.Add(err)
		return positions
	}
	if err := json.Unmarshal(data, &positions); err != nil {
		*issues = append(*issues, fmt.Sprintf("weblog state unreadable, logs read from the tail: %v", err))
	}
	return positions
}

// logFiles lists the logs to read: those named in the web server configurations, then the
// standard locations. Paths still holding variables are skipped.
func logFiles(fsys fs.FS) (access, errorLogs []string) {
	inv := discovery.Inspect(fsys)
	add := func(list []string, p string) []string {
		if p == "" || strings.Contains(p, "$") {
			return list
		}
		p = collector.Rel(p)
		if info, err := fs.Stat(fsys, p); err != nil || !info.Mode().IsRegular() || slices.Contains(list, p) {
			return list
		}
		return append(list, p)
	}
	for _, s := range inv.Sites {
		for _, p := range s.AccessLogs {
			access = add(access, p)
		}
		for _, p := range s.ErrorLogs {
			errorLogs = add(errorLogs, p)
		}
	}
	for _, pattern := range defaultAccessLogs {
		for _, p := range collector.Glob(fsys, pattern) {
			access = add(access, "/"+p)
		}
	}
	for _, pattern := range defaultErrorLogs {
		for _, p := range collector.Glob(fsys, pattern) {
			if !slices.Contains(access, p) {
				errorLogs = add(errorLogs, "/"+p)
			}
		}
	}
	return access, errorLogs
}

type postTally struct {
	requests int
	ips      map[string]struct{}
	moreIPs  bool
}

type runState struct {
	maxBytes      int64
	firstRunBytes int64
	src           collector.Source
	positions     map[string]position
	res           Result
	events        map[string]*Event
	ips           map[string]int
	posts         map[string]*postTally
	postPairs     int
}

func (r *runState) read(ctx context.Context, name, kind string) error {
	info, err := fs.Stat(r.src.FS, name)
	if err != nil {
		r.res.Issues.Add(err)
		return nil
	}
	inode, _ := collector.Inode(info)
	lf := LogFile{Path: "/" + name, Kind: kind, Size: info.Size()}

	prev, known := r.positions[name]
	switch {
	case !known:
		lf.From = max(0, info.Size()-r.firstRunBytes)
		if lf.From > 0 {
			r.res.Issues = append(r.res.Issues, fmt.Sprintf("/%s: no saved position, only the last %d bytes read", name, r.firstRunBytes))
		}
	case prev.Inode != inode:
		lf.Rotated = true
		r.drainRotated(ctx, name, kind, prev)
	case info.Size() < prev.Offset && r.drainCopy(ctx, name, kind, prev):
		// logrotate copytruncate: the content was copied to a sibling, then the file emptied.
		lf.Rotated = true
	case info.Size() < prev.Offset:
		// Same file, shorter than what was already read, and no copy holds what was there:
		// truncated in place.
		lf.Rewritten = true
		r.tamper(name, "log_truncated", fmt.Sprintf("%d bytes, %d already read", info.Size(), prev.Offset))
	case prev.Fingerprint != "" && fingerprint(r.src.FS, name, prev.Offset) != prev.Fingerprint:
		// Same file, but the part already read changed: rewritten in place, possibly to hide
		// the lines of an attack. Everything is read again.
		lf.Rewritten = true
		r.tamper(name, "log_rewritten", fmt.Sprintf("content before offset %d changed", prev.Offset))
	default:
		lf.From = prev.Offset
	}

	var analyzer *weblog.Analyzer
	if kind == "access" {
		analyzer = weblog.NewAnalyzer()
	}
	if err := r.scan(ctx, name, lf.From, analyzer, &lf); err != nil {
		return err
	}
	lf.Truncated = lf.To-lf.From >= r.maxBytes && lf.To < info.Size()
	r.positions[name] = position{Inode: inode, Offset: lf.To, Fingerprint: fingerprint(r.src.FS, name, lf.To)}
	r.res.Files = append(r.res.Files, lf)
	return nil
}

func (r *runState) tamper(name, rule, detail string) {
	key := rule + "\x00" + name
	if _, seen := r.events[key]; !seen && r.admit(weblog.SeverityHigh) {
		r.events[key] = &Event{Rule: rule, Severity: weblog.SeverityHigh, Log: "/" + name, Count: 1, Evidence: AttackerControlled{Line: detail}}
	}
	r.res.Issues = append(r.res.Issues, fmt.Sprintf("/%s: %s (%s), read again from the start", name, strings.ReplaceAll(rule, "_", " "), detail))
}

// fingerprint hashes the bytes just before offset.
func fingerprint(fsys fs.FS, name string, offset int64) string {
	if offset == 0 {
		return ""
	}
	f, err := fsys.Open(name)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	ra, ok := f.(io.ReaderAt)
	if !ok {
		return ""
	}
	start := max(0, offset-fingerprintSize)
	buf := make([]byte, offset-start)
	if n, err := ra.ReadAt(buf, start); err != nil && (!errors.Is(err, io.EOF) || int64(n) != offset-start) {
		return "unreadable"
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// rotatedSiblings lists the files rotation may have produced from name: name.1, dated copies
// (name-20261022 with dateext), and Caddy's stem-<timestamp>.ext. Compressed copies cannot be
// read from an offset and are left out.
func rotatedSiblings(fsys fs.FS, name string) []string {
	dir, base := path.Dir(name), path.Base(name)
	stem := strings.TrimSuffix(base, path.Ext(base))
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if n == base || !e.Type().IsRegular() || slices.Contains([]string{".gz", ".bz2", ".xz", ".zst"}, path.Ext(n)) {
			continue
		}
		if strings.HasPrefix(n, base) || strings.HasPrefix(n, stem+"-") {
			out = append(out, path.Join(dir, n))
		}
	}
	return out
}

// drainRotated finishes the previous file, found among the rotated siblings by its inode,
// from where the last run stopped. When it cannot be found the lines in between are lost,
// and that is said.
func (r *runState) drainRotated(ctx context.Context, name, kind string, prev position) {
	for _, sibling := range rotatedSiblings(r.src.FS, name) {
		info, err := fs.Stat(r.src.FS, sibling)
		if err != nil {
			continue
		}
		if inode, ok := collector.Inode(info); ok && inode == prev.Inode && info.Size() >= prev.Offset {
			r.drain(ctx, sibling, kind, prev.Offset, info.Size())
			return
		}
	}
	r.res.Issues = append(r.res.Issues, fmt.Sprintf("/%s rotated and the previous file is gone or compressed: lines after offset %d of the old file were not read", name, prev.Offset))
}

// drainCopy recognises copytruncate: a sibling whose bytes before the saved offset match the
// saved fingerprint is the copy of what was read, and is drained from there.
func (r *runState) drainCopy(ctx context.Context, name, kind string, prev position) bool {
	if prev.Fingerprint == "" {
		return false
	}
	for _, sibling := range rotatedSiblings(r.src.FS, name) {
		info, err := fs.Stat(r.src.FS, sibling)
		if err != nil || info.Size() < prev.Offset {
			continue
		}
		if fingerprint(r.src.FS, sibling, prev.Offset) == prev.Fingerprint {
			r.drain(ctx, sibling, kind, prev.Offset, info.Size())
			return true
		}
	}
	return false
}

func (r *runState) drain(ctx context.Context, name, kind string, from, size int64) {
	var analyzer *weblog.Analyzer
	if kind == "access" {
		analyzer = weblog.NewAnalyzer()
	}
	lf := LogFile{Path: "/" + name, Kind: kind, Size: size, From: from}
	if err := r.scan(ctx, name, from, analyzer, &lf); err != nil {
		r.res.Issues.Add(err)
		return
	}
	r.res.Files = append(r.res.Files, lf)
}

// scan reads complete lines from lf.From, up to maxBytes, and sets lf.To after the last
// complete line: a line still being written is left for the next run. Lines longer than
// MaxLineLength are skipped past and counted, never held in memory.
func (r *runState) scan(ctx context.Context, name string, offset int64, analyzer *weblog.Analyzer, lf *LogFile) error {
	lf.To = offset
	f, err := r.src.FS.Open(name)
	if err != nil {
		r.res.Issues.Add(err)
		return nil
	}
	defer func() { _ = f.Close() }()
	if err := seek(f, offset); err != nil {
		r.res.Issues.Add(fmt.Errorf("seek %s: %w", name, err))
		return nil
	}

	br := bufio.NewReaderSize(io.LimitReader(f, r.maxBytes), MaxLineLength)
	for {
		if lf.Lines%1000 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		line, n, complete, err := readLine(br)
		if !complete {
			// A stretch with no line end longer than the per-run limit (a hole made with
			// truncate -s +N, for instance) would otherwise stop the offset here forever.
			if n >= MaxLineLength && lf.To+n-offset >= r.maxBytes {
				lf.To += n
				lf.Oversized++
				r.res.Issues = append(r.res.Issues, fmt.Sprintf("/%s: %d bytes without a line end skipped at offset %d", name, n, lf.To-n))
			}
			break
		}
		lf.To += n
		lf.Lines++
		if errors.Is(err, errLineTooLong) {
			lf.Oversized++
			continue
		}
		line = bytes.TrimRight(line, "\r\n")

		if analyzer == nil {
			r.errorLine(name, string(line))
			continue
		}
		if lf.Format == "" {
			lf.Format = weblog.DetectFormat(string(line))
		}
		req, ok := weblog.Parse(lf.Format, string(line))
		if !ok {
			lf.Unparsed++
			continue
		}
		r.request(name, &req, analyzer.Analyze(&req))
	}
	return nil
}

var errLineTooLong = errors.New("line too long")

// readLine returns the next line and how many bytes it took. complete is false at the end of
// the data, including a final line without its newline. A line over the buffer is consumed
// to its end without being kept, and reported with errLineTooLong.
func readLine(br *bufio.Reader) (line []byte, n int64, complete bool, err error) {
	line, err = br.ReadSlice('\n')
	n = int64(len(line))
	if err == nil {
		return line, n, true, nil
	}
	if !errors.Is(err, bufio.ErrBufferFull) {
		return nil, n, false, nil
	}
	for errors.Is(err, bufio.ErrBufferFull) {
		var chunk []byte
		chunk, err = br.ReadSlice('\n')
		n += int64(len(chunk))
	}
	if err != nil {
		return nil, n, false, nil
	}
	return nil, n, true, errLineTooLong
}

func seek(f fs.File, offset int64) error {
	if offset == 0 {
		return nil
	}
	if s, ok := f.(io.Seeker); ok {
		_, err := s.Seek(offset, io.SeekStart)
		return err
	}
	_, err := io.CopyN(io.Discard, f, offset)
	return err
}

func (r *runState) request(log string, req *weblog.Request, hits []weblog.Hit) {
	r.res.Stats.Requests++
	r.res.Stats.Statuses[fmt.Sprintf("%dxx", req.Status/100)]++
	r.countIP(req.IP)
	if req.Method == "POST" {
		r.countPost(req)
	}

	for _, h := range hits {
		key := h.Rule + "\x00" + req.IP + "\x00" + req.Path()
		e, ok := r.events[key]
		if !ok {
			if !r.admit(h.Severity) {
				continue
			}
			e = &Event{
				Rule: h.Rule, Severity: h.Severity, IP: req.IP, Method: req.Method, Status: req.Status,
				Log: "/" + log, First: req.Time, path: req.Path(),
				Evidence: AttackerControlled{Request: weblog.RedactURI(req.URI), UserAgent: weblog.RedactLine(req.UserAgent)},
			}
			r.events[key] = e
		}
		// The worst outcome wins: a later 200 on a probed web shell path raises the event.
		if weblog.SeverityRank(h.Severity) > weblog.SeverityRank(e.Severity) {
			e.Severity, e.Status, e.Evidence.Request = h.Severity, req.Status, weblog.RedactURI(req.URI)
		}
		e.Count++
		e.Last = req.Time
	}
}

// admit decides whether a new event fits. Up to maxEvents anything does. Past it, an event of
// high or critical severity evicts the least severe and least frequent event below high, so
// noise sent first cannot push out the event that matters; with nothing to evict, urgent events
// may grow the list up to twice the limit.
func (r *runState) admit(severity string) bool {
	if len(r.events) < maxEvents {
		return true
	}
	r.res.Truncated = true
	urgent := weblog.SeverityRank(weblog.SeverityHigh)
	if weblog.SeverityRank(severity) < urgent {
		return false
	}
	victim := ""
	for k, e := range r.events {
		rank := weblog.SeverityRank(e.Severity)
		if rank >= urgent {
			continue
		}
		if v := r.events[victim]; victim == "" || rank < weblog.SeverityRank(v.Severity) || (rank == weblog.SeverityRank(v.Severity) && e.Count < v.Count) {
			victim = k
		}
	}
	if victim != "" {
		delete(r.events, victim)
		return true
	}
	return len(r.events) < 2*maxEvents
}

// countIP keeps approximate per-IP counts with the Misra-Gries summary: when the table is
// full, every count drops by one and empty entries leave. Heavy hitters stay whatever the
// order of arrival, and the table never exceeds maxTrackedIPs.
func (r *runState) countIP(ip string) {
	if _, tracked := r.ips[ip]; tracked || len(r.ips) < maxTrackedIPs {
		r.ips[ip]++
		return
	}
	r.res.Stats.OtherIPs++
	for k := range r.ips {
		if r.ips[k]--; r.ips[k] == 0 {
			delete(r.ips, k)
		}
	}
}

func (r *runState) countPost(req *weblog.Request) {
	t, ok := r.posts[req.Path()]
	if !ok {
		if len(r.posts) >= maxTrackedPosts {
			r.res.Stats.OtherPosts++
			return
		}
		t = &postTally{ips: map[string]struct{}{}}
		r.posts[req.Path()] = t
	}
	t.requests++
	if _, seen := t.ips[req.IP]; !seen {
		if len(t.ips) < maxIPsPerPost && r.postPairs < maxPostPairs {
			t.ips[req.IP] = struct{}{}
			r.postPairs++
		} else {
			t.moreIPs = true
		}
	}
}

func (r *runState) errorLine(log, line string) {
	for _, marker := range suspiciousErrors {
		if !strings.Contains(line, marker) {
			continue
		}
		key := "php_error\x00" + marker + "\x00" + log
		e, ok := r.events[key]
		if !ok {
			if !r.admit(weblog.SeverityMedium) {
				return
			}
			e = &Event{Rule: "suspicious_php_error", Severity: weblog.SeverityMedium, Log: "/" + log, Evidence: AttackerControlled{Line: weblog.RedactLine(line)}}
			r.events[key] = e
		}
		e.Count++
		return
	}
}

func (r *runState) finish() {
	for _, e := range r.events {
		r.res.Events = append(r.res.Events, *e)
	}
	slices.SortFunc(r.res.Events, func(a, b Event) int {
		return cmp.Or(
			cmp.Compare(weblog.SeverityRank(b.Severity), weblog.SeverityRank(a.Severity)),
			cmp.Compare(b.Count, a.Count),
			cmp.Compare(a.Rule+a.IP+a.path+a.Log, b.Rule+b.IP+b.path+b.Log),
		)
	})

	for ip, n := range r.ips {
		r.res.Stats.TopIPs = append(r.res.Stats.TopIPs, Counter{Key: ip, Count: n})
	}
	slices.SortFunc(r.res.Stats.TopIPs, func(a, b Counter) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Key, b.Key))
	})
	r.res.Stats.TopIPs = r.res.Stats.TopIPs[:min(len(r.res.Stats.TopIPs), maxTopIPs)]

	for p, t := range r.posts {
		r.res.Stats.PostTargets = append(r.res.Stats.PostTargets, PostTarget{Path: weblog.RedactURI(p), Requests: t.requests, DistinctIPs: len(t.ips), MoreIPs: t.moreIPs})
	}
	slices.SortFunc(r.res.Stats.PostTargets, func(a, b PostTarget) int {
		return cmp.Or(cmp.Compare(b.DistinctIPs, a.DistinctIPs), cmp.Compare(b.Requests, a.Requests), cmp.Compare(a.Path, b.Path))
	})
	r.res.Stats.PostTargets = r.res.Stats.PostTargets[:min(len(r.res.Stats.PostTargets), maxPostTargets)]
}
