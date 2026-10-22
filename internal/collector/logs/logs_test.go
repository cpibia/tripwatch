package logs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
)

const accessLog = "var/log/nginx/access.log"

func logLine(ip, method, uri string, status int) string {
	return fmt.Sprintf("%s - - [14/Feb/2026:18:48:01 +0000] \"%s %s HTTP/1.1\" %d 100 \"-\" \"Mozilla\"\n", ip, method, uri, status)
}

type host struct {
	t     *testing.T
	root  string
	state string
	c     *Collector
}

func newHost(t *testing.T) *host {
	t.Helper()
	h := &host{t: t, root: t.TempDir(), state: t.TempDir()}
	if err := os.MkdirAll(filepath.Join(h.root, "var/log/nginx"), 0o750); err != nil {
		t.Fatal(err)
	}
	h.c = &Collector{StateDir: h.state}
	return h
}

func (h *host) writeLog(content string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.root, accessLog), []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *host) appendLog(content string) {
	h.t.Helper()
	f, err := os.OpenFile(filepath.Join(h.root, accessLog), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600) //nolint:gosec // test fixture under t.TempDir
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(content); err != nil {
		h.t.Fatal(err)
	}
}

func (h *host) collect() Result {
	h.t.Helper()
	out, err := h.c.Collect(context.Background(), collector.NewSource(h.root))
	if err != nil {
		h.t.Fatal(err)
	}
	return out.(Result)
}

func (h *host) run() Result {
	h.t.Helper()
	res := h.collect()
	if err := h.c.Commit(); err != nil {
		h.t.Fatal(err)
	}
	return res
}

func eventRules(res Result) []string {
	var out []string
	for _, e := range res.Events {
		out = append(out, e.Rule)
	}
	slices.Sort(out)
	return out
}

func TestIncrementalReading(t *testing.T) {
	h := newHost(t)
	h.writeLog(logLine("203.0.113.7", "GET", "/media/x.php", 200) + logLine("198.51.100.2", "GET", "/", 200))

	first := h.run()
	if first.Stats.Requests != 2 || !slices.Equal(eventRules(first), []string{"script_in_upload_path"}) {
		t.Fatalf("first run: %d requests, events %v", first.Stats.Requests, eventRules(first))
	}

	h.appendLog(logLine("203.0.113.8", "GET", "/.env", 200) + `203.0.113.9 - - [14/Feb/2026:18:48:01 +0000] "GET /partial`)
	second := h.run()
	if second.Stats.Requests != 1 || !slices.Equal(eventRules(second), []string{"sensitive_file"}) {
		t.Errorf("second run: %d requests, events %v", second.Stats.Requests, eventRules(second))
	}

	h.appendLog(` HTTP/1.1" 200 1 "-" "x"` + "\n")
	if third := h.run(); third.Stats.Requests != 1 {
		t.Errorf("a line completed between runs must be read once whole: %d requests", third.Stats.Requests)
	}
}

// Positions only advance on Commit: a run whose snapshot was never delivered is read again.
func TestPositionsAdvanceOnlyOnCommit(t *testing.T) {
	h := newHost(t)
	h.writeLog(logLine("203.0.113.7", "GET", "/media/x.php", 200))
	if res := h.collect(); res.Stats.Requests != 1 {
		t.Fatalf("requests = %d", res.Stats.Requests)
	}
	h.c = &Collector{StateDir: h.state} // the sensor restarted before delivering
	if res := h.run(); res.Stats.Requests != 1 || len(res.Events) != 1 {
		t.Errorf("undelivered run lost: %d requests, %d events", res.Stats.Requests, len(res.Events))
	}
	if res := h.run(); res.Stats.Requests != 0 {
		t.Errorf("committed run read again: %d requests", res.Stats.Requests)
	}
}

func TestRotation(t *testing.T) {
	h := newHost(t)
	h.writeLog(logLine("203.0.113.7", "GET", "/", 200))
	h.run()

	h.appendLog(logLine("203.0.113.7", "GET", "/media/late.php", 200))
	if err := os.Rename(filepath.Join(h.root, accessLog), filepath.Join(h.root, accessLog+".1")); err != nil {
		t.Fatal(err)
	}
	h.writeLog(logLine("203.0.113.8", "GET", "/", 200))

	res := h.run()
	if res.Stats.Requests != 2 || !slices.Equal(eventRules(res), []string{"script_in_upload_path"}) {
		t.Errorf("lines written before rotation lost: %d requests, events %v", res.Stats.Requests, eventRules(res))
	}
	if len(res.Issues) != 0 {
		t.Errorf("issues = %v", res.Issues)
	}
}

// logrotate with compress and no delaycompress leaves name.1.gz, not name.1: the lines
// written after the last run cannot be read, and that must be said.
func TestRotationWithoutOldFileIsReported(t *testing.T) {
	h := newHost(t)
	h.writeLog(logLine("203.0.113.7", "GET", "/", 200))
	h.run()
	h.appendLog(logLine("203.0.113.7", "GET", "/media/late.php", 200))
	if err := os.Rename(filepath.Join(h.root, accessLog), filepath.Join(h.root, accessLog+".1.gz")); err != nil {
		t.Fatal(err)
	}
	h.writeLog(logLine("203.0.113.8", "GET", "/", 200))

	res := h.run()
	if !slices.ContainsFunc(res.Issues, func(s string) bool { return strings.Contains(s, "were not read") }) {
		t.Errorf("issues = %v, want the lost lines reported", res.Issues)
	}
}

// A log rewritten in place to hide an attack, at the same size or truncated, is an event and
// is read again from the start.
func TestRewrittenOrTruncatedLog(t *testing.T) {
	h := newHost(t)
	benign := logLine("198.51.100.2", "GET", "/aaaa", 200)
	h.writeLog(benign)
	h.run()

	f, err := os.OpenFile(filepath.Join(h.root, accessLog), os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte(logLine("198.51.100.2", "GET", "/bbbb", 200)), 0); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	res := h.run()
	if !slices.Contains(eventRules(res), "log_rewritten") || res.Files[0].From != 0 || !res.Files[0].Rewritten {
		t.Errorf("rewrite: events %v, files %+v", eventRules(res), res.Files)
	}

	if err := os.Truncate(filepath.Join(h.root, accessLog), 10); err != nil {
		t.Fatal(err)
	}
	if res := h.run(); !slices.Contains(eventRules(res), "log_truncated") {
		t.Errorf("truncation: events %v", eventRules(res))
	}
}

func TestOversizedLineIsSkipped(t *testing.T) {
	h := newHost(t)
	h.writeLog(strings.Repeat("A", 5<<20) + "\n" + logLine("203.0.113.7", "GET", "/.env", 200))
	h.c.MaxBytes = 1 << 30

	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	res := h.run()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if res.Files[0].Oversized != 1 || res.Stats.Requests != 1 {
		t.Errorf("files %+v, requests %d", res.Files, res.Stats.Requests)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 4<<20 {
		t.Errorf("a 5 MB line allocated %d bytes", grown)
	}
}

// Requests from as many distinct addresses and paths as a remote client wants must not make
// memory grow with them.
func TestMemoryIsBoundedUnderAnonymousFlood(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("writes and reads a large log: run without -race and -short")
	}
	h := newHost(t)
	f, err := os.Create(filepath.Join(h.root, accessLog))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 500_000 {
		ip := fmt.Sprintf("2001:db8::%x:%x", i>>16, i&0xffff)
		if _, err := f.WriteString(logLine(ip, "POST", fmt.Sprintf("/x%d.php?t=%d", i, i), 404)); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.Close()
	h.c.FirstRunBytes = 1 << 30

	runtime.GC()
	stop := make(chan struct{})
	peak := make(chan uint64, 1)
	go func() {
		// ReadMemStats stops the world: sample, do not spin.
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		var m runtime.MemStats
		var top uint64
		for {
			select {
			case <-stop:
				peak <- top
				return
			case <-tick.C:
				runtime.ReadMemStats(&m)
				top = max(top, m.HeapAlloc)
			}
		}
	}()
	res := h.run()
	close(stop)

	if res.Stats.Requests != 500_000 || res.Stats.OtherIPs == 0 || res.Stats.OtherPosts == 0 {
		t.Errorf("requests %d, other IPs %d, other posts %d", res.Stats.Requests, res.Stats.OtherIPs, res.Stats.OtherPosts)
	}
	if top := <-peak; top > 128<<20 {
		t.Errorf("heap peaked at %d MB", top>>20)
	}
}

func TestEventsKeepAttackerTextApartAndRedacted(t *testing.T) {
	h := newHost(t)
	h.writeLog(logLine("203.0.113.7", "GET", "/account/reset?token=SECRET123&f=../../etc/passwd", 404))
	res := h.run()
	if len(res.Events) != 1 {
		t.Fatalf("events = %+v", res.Events)
	}
	e := res.Events[0]
	if strings.Contains(e.Evidence.Request, "SECRET123") || !strings.Contains(e.Evidence.Request, "../../etc/passwd") {
		t.Errorf("evidence = %q", e.Evidence.Request)
	}
}
