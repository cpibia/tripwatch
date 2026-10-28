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
	// Half the lines spread over distinct paths, half over few paths with many addresses each:
	// both must stay bounded.
	for i := range 250_000 {
		ip := fmt.Sprintf("2001:db8::%x:%x", i>>16, i&0xffff)
		if _, err := f.WriteString(logLine(ip, "POST", fmt.Sprintf("/x%d.php?t=%d", i, i), 404)); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 250_000 {
		ip := fmt.Sprintf("2001:db8:1::%x:%x", i>>16, i&0xffff)
		if _, err := f.WriteString(logLine(ip, "POST", fmt.Sprintf("/form%d", i%1000), 404)); err != nil {
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

// Noise sent first must not push the event that matters out of the bounded list.
func TestUrgentEventsSurviveNoise(t *testing.T) {
	h := newHost(t)
	var b strings.Builder
	for i := range maxEvents + 500 {
		fmt.Fprintf(&b, "2001:db8::%x - - [14/Feb/2026:18:48:01 +0000] \"GET /p%d HTTP/1.1\" 404 1 \"-\" \"nikto\"\n", i, i)
	}
	b.WriteString(logLine("203.0.113.66", "GET", "/media/catalog/x.php", 200))
	h.writeLog(b.String())

	res := h.run()
	if !slices.ContainsFunc(res.Events, func(e Event) bool { return e.Rule == "script_in_upload_path" && e.Severity == "critical" }) {
		t.Errorf("web shell event lost among %d events", len(res.Events))
	}
	if !res.Truncated {
		t.Error("dropped noise must be declared")
	}
}

// A stretch without line ends longer than the per-run limit is skipped, not read forever.
func TestHoleWithoutNewlines(t *testing.T) {
	h := newHost(t)
	h.c.MaxBytes = 64 << 10
	h.writeLog(logLine("198.51.100.2", "GET", "/", 200))
	h.run()
	if err := os.Truncate(filepath.Join(h.root, accessLog), int64(len(logLine("198.51.100.2", "GET", "/", 200)))+200<<10); err != nil {
		t.Fatal(err)
	}
	h.appendLog("\n" + logLine("203.0.113.7", "GET", "/.env", 200))

	var events []string
	var issues []string
	for range 6 {
		res := h.run()
		events = append(events, eventRules(res)...)
		issues = append(issues, res.Issues...)
	}
	if !slices.Contains(events, "sensitive_file") {
		t.Errorf("the line after the hole was never read: events %v, issues %v", events, issues)
	}
	if !slices.ContainsFunc(issues, func(s string) bool { return strings.Contains(s, "without a line end skipped") }) {
		t.Errorf("issues = %v", issues)
	}
}

// With dateext the previous file is access.log-20261022, not access.log.1.
func TestDateextRotation(t *testing.T) {
	h := newHost(t)
	h.writeLog(logLine("203.0.113.7", "GET", "/", 200))
	h.run()
	h.appendLog(logLine("203.0.113.7", "GET", "/media/late.php", 200))
	if err := os.Rename(filepath.Join(h.root, accessLog), filepath.Join(h.root, accessLog+"-20261022")); err != nil {
		t.Fatal(err)
	}
	h.writeLog(logLine("203.0.113.8", "GET", "/", 200))

	res := h.run()
	if !slices.Contains(eventRules(res), "script_in_upload_path") || len(res.Issues) != 0 {
		t.Errorf("events %v, issues %v", eventRules(res), res.Issues)
	}
}

// copytruncate copies the log and empties it in place. The copy is drained either way; the
// truncation is a rotation only if the log's owner could not have forged the copy.
func TestCopyTruncate(t *testing.T) {
	for _, copyByRoot := range []bool{false, true} {
		if copyByRoot && os.Geteuid() != 0 {
			continue // needs chown: covered when the tests run as root
		}
		h := newHost(t)
		h.writeLog(logLine("203.0.113.7", "GET", "/", 200))
		h.run()
		h.appendLog(logLine("203.0.113.7", "GET", "/media/late.php", 200))
		logPath := filepath.Join(h.root, accessLog)
		data, err := os.ReadFile(logPath) //nolint:gosec // test fixture under t.TempDir
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(logPath+".1", data, 0o600); err != nil { //nolint:gosec // test fixture under t.TempDir
			t.Fatal(err)
		}
		if copyByRoot {
			if err := os.Chown(logPath, 33, 33); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Truncate(logPath, 0); err != nil {
			t.Fatal(err)
		}

		rules := eventRules(h.run())
		if !slices.Contains(rules, "script_in_upload_path") {
			t.Errorf("copy by root %v: lines in the copy not read: %v", copyByRoot, rules)
		}
		if got := slices.Contains(rules, "log_truncated"); got == copyByRoot {
			t.Errorf("copy by root %v: log_truncated reported = %v", copyByRoot, got)
		}
	}
}

func TestFirstRunTailIsDeclared(t *testing.T) {
	h := newHost(t)
	h.c.FirstRunBytes = 100
	h.writeLog(strings.Repeat(logLine("198.51.100.2", "GET", "/", 200), 10))
	res := h.run()
	if !slices.ContainsFunc(res.Issues, func(s string) bool { return strings.Contains(s, "no saved position") }) {
		t.Errorf("issues = %v", res.Issues)
	}
}

// A flood of high events from many addresses must not keep a critical one out.
func TestCriticalEventSurvivesHighFlood(t *testing.T) {
	h := newHost(t)
	var b strings.Builder
	for i := range 2 * maxEvents {
		b.WriteString(logLine(fmt.Sprintf("2001:db8::%x", i), "POST", fmt.Sprintf("/media/p%d.php", i), 404))
	}
	b.WriteString(logLine("203.0.113.66", "GET", "/media/catalog/x.php", 200))
	h.writeLog(b.String())

	res := h.run()
	if !slices.ContainsFunc(res.Events, func(e Event) bool { return e.Severity == "critical" }) {
		t.Errorf("critical event lost among %d events", len(res.Events))
	}
	if len(res.Events) > maxEvents {
		t.Errorf("%d events kept, limit %d", len(res.Events), maxEvents)
	}
}

// A request is not hidden by a long user agent: the start of the line is still inspected.
func TestLongLineIsStillInspected(t *testing.T) {
	h := newHost(t)
	ua := strings.Repeat(`\x41`, MaxLineLength)
	h.writeLog(fmt.Sprintf("203.0.113.7 - - [14/Feb/2026:18:48:01 +0000] \"GET /media/catalog/x.php HTTP/1.1\" 200 10 \"-\" \"%s\"\n", ua))
	res := h.run()
	if res.Files[0].Oversized != 1 || !slices.Contains(eventRules(res), "script_in_upload_path") {
		t.Errorf("oversized %d, events %v", res.Files[0].Oversized, eventRules(res))
	}
}

// A hole of NUL bytes glued to the next line must not swallow it.
func TestLineAfterNulHole(t *testing.T) {
	h := newHost(t)
	h.writeLog(logLine("198.51.100.2", "GET", "/", 200) + strings.Repeat("\x00", 100<<10) + logLine("203.0.113.7", "GET", "/.env", 200))
	res := h.run()
	if !slices.Contains(eventRules(res), "sensitive_file") {
		t.Errorf("line after the hole lost: events %v", eventRules(res))
	}
	if !slices.ContainsFunc(res.Issues, func(s string) bool { return strings.Contains(s, "NUL bytes") }) {
		t.Errorf("issues = %v", res.Issues)
	}
}

// Thousands of fake criticals from one /64, each address once, on one path: one event, and
// the real web shell on another path still gets in.
func TestFloodFromManyAddressesIsOneEvent(t *testing.T) {
	h := newHost(t)
	var b strings.Builder
	for i := range 2500 {
		b.WriteString(logLine(fmt.Sprintf("2001:db8::%x", i), "GET", "/index.php?c=id", 200))
	}
	b.WriteString(logLine("203.0.113.66", "GET", "/media/catalog/x.php", 200))
	h.writeLog(b.String())

	res := h.run()
	var flood, shell *Event
	for i := range res.Events {
		switch res.Events[i].Evidence.Request {
		case "/index.php?c=id":
			flood = &res.Events[i]
		case "/media/catalog/x.php":
			shell = &res.Events[i]
		}
	}
	if flood == nil || flood.Count != 2500 || flood.IPs != maxIPsPerEvent || len(flood.SampleIPs) != maxSampleIPs {
		t.Errorf("flood event = %+v", flood)
	}
	if shell == nil || shell.Severity != "critical" {
		t.Errorf("web shell event = %+v", shell)
	}
}

// Path variants that nginx resolves to the same file are one event, so they cannot flood the
// list and push out a real one.
func TestPathVariantsAreOneEvent(t *testing.T) {
	h := newHost(t)
	var b strings.Builder
	for i := range 3000 {
		b.WriteString(logLine(fmt.Sprintf("2001:db8::%x", i), "GET", fmt.Sprintf("/v%d/../index.php?c=id", i), 200))
	}
	b.WriteString(logLine("203.0.113.66", "GET", "/media/catalog/x.php", 200))
	h.writeLog(b.String())
	res := h.run()
	perRule := map[string]int{}
	for _, e := range res.Events {
		perRule[e.Rule]++
	}
	// The flood triggers two rules (command in parameters, traversal), each one event.
	if perRule["command_in_parameters"] != 1 || perRule["path_traversal"] != 1 {
		t.Errorf("events per rule = %v", perRule)
	}
	if !slices.ContainsFunc(res.Events, func(e Event) bool { return e.Evidence.Request == "/media/catalog/x.php" && e.Severity == "critical" }) {
		t.Error("web shell event lost")
	}
}

// PATH_INFO and ";" variants of one script are one event: they cannot fill a rule's quota and
// push out a web shell that triggers the same rule.
func TestPathInfoVariantsAreOneEvent(t *testing.T) {
	h := newHost(t)
	var b strings.Builder
	for i := range 2000 {
		b.WriteString(logLine("198.51.100.7", "GET", fmt.Sprintf("/index.php/p%d?c=id", i), 200))
		b.WriteString(logLine("198.51.100.7", "GET", fmt.Sprintf("/index.php;p%d?c=id", i), 200))
	}
	b.WriteString(logLine("203.0.113.66", "GET", "/wp-content/plugins/hello/zz.php?cmd=whoami", 200))
	h.writeLog(b.String())
	res := h.run()
	n := 0
	for _, e := range res.Events {
		if e.Rule == "command_in_parameters" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("command_in_parameters events = %d, want the flood as one and the web shell", n)
	}
	if !slices.ContainsFunc(res.Events, func(e Event) bool { return strings.HasPrefix(e.Evidence.Request, "/wp-content/plugins/hello/zz.php") }) {
		t.Error("web shell event lost")
	}
}

// Dropped serious events keep one sample per source address, so a flood from one address
// leaves room for the others.
func TestDroppedSamplesOnePerAddress(t *testing.T) {
	h := newHost(t)
	var b strings.Builder
	for i := range 3000 {
		b.WriteString(logLine("198.51.100.7", "GET", fmt.Sprintf("/x%d.php?cmd=id", i), 200))
	}
	b.WriteString(logLine("203.0.113.66", "GET", "/wp-content/plugins/hello/zz.php?cmd=whoami", 200))
	h.writeLog(b.String())
	res := h.run()
	ips := map[string]int{}
	for _, d := range res.Stats.DroppedSamples {
		ips[d.IP]++
	}
	if ips["198.51.100.7"] > 1 {
		t.Errorf("one address took %d samples", ips["198.51.100.7"])
	}
	kept := slices.ContainsFunc(res.Events, func(e Event) bool { return e.IP == "203.0.113.66" })
	if !kept && ips["203.0.113.66"] != 1 {
		t.Error("the web shell request is neither kept nor sampled")
	}
}

func TestSourceOf(t *testing.T) {
	if sourceOf("2001:db8::1") != sourceOf("2001:db8:0:ffff::1") || sourceOf("2001:db8::1") == sourceOf("2001:db8:1::1") {
		t.Error("IPv6 addresses are not grouped by /48")
	}
	if sourceOf("198.51.100.7") != sourceOf("198.51.100.200") || sourceOf("198.51.100.7") == sourceOf("198.51.101.7") || sourceOf("junk") != "junk" {
		t.Error("IPv4 addresses are not grouped by /24")
	}
}

// A requested script is looked up in the document roots of the sites writing the log; a log no
// configuration names, or a site that may proxy the request, leaves the answer open.
func TestScriptsLookedUpOnDisk(t *testing.T) {
	h := newHost(t)
	write := func(name, content string) {
		t.Helper()
		p := filepath.Join(h.root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/nginx/nginx.conf", `http {
		server { root /var/www/a/public; access_log /var/log/nginx/access.log; location ~ \.php$ { fastcgi_pass unix:/run/php.sock; } }
		server { root /var/www/b; access_log /var/log/nginx/access.log; location /api/ { proxy_pass http://127.0.0.1:8080; } }
		server { root /var/www/c; access_log /var/log/nginx/c.log; location / { proxy_pass http://127.0.0.1:9000; } }
		server { listen 80; access_log /var/log/nginx/redirect.log; return 301 https://$host$request_uri; }
	}`)
	write("var/www/b/uploads/shell.php", "<?php")
	h.writeLog(logLine("203.0.113.7", "GET", "/wp-content/uploads/probe.php", 404) +
		logLine("203.0.113.7", "GET", "/uploads/shell.php/x.jpg", 404) +
		logLine("203.0.113.7", "GET", "/api/files/x.php", 404) +
		logLine("203.0.113.7", "GET", "/.env", 404))
	write("var/log/nginx/c.log", logLine("203.0.113.8", "GET", "/media/y.php", 404))
	write("var/log/nginx/other.access.log", logLine("203.0.113.9", "GET", "/media/z.php", 404))
	write("var/log/nginx/redirect.log", logLine("203.0.113.10", "GET", "/tmp/phpinfo.php", 301))

	got := map[string]string{}
	for _, e := range h.run().Events {
		got[e.Evidence.Request] = e.OnDisk
	}
	for uri, want := range map[string]string{
		"/wp-content/uploads/probe.php": "missing",
		"/uploads/shell.php/x.jpg":      "present",
		"/api/files/x.php":              "",
		"/.env":                         "",
		"/media/y.php":                  "elsewhere",
		"/tmp/phpinfo.php":              "elsewhere",
		"/media/z.php":                  "",
	} {
		if v, ok := got[uri]; !ok || v != want {
			t.Errorf("%s: on disk %q (event %v), want %q", uri, v, ok, want)
		}
	}
}
