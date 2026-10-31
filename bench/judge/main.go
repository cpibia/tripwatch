// Command judge applies the verifier's real-time rules to event batches printed by
// tripwatch-sensor -watch-only, read from standard input, and prints each alert they raise as a
// JSON object: the benchmark counts what the verifier would raise, not what the sensor saw.
//
//	judge [-refs <dir>] -snapshots <before> <after> [events]
//
// applies the verifier's snapshot rules to two snapshots printed by tripwatch-sensor instead,
// the second compared with the first, and prints the alerts the same way; with the event batches
// the watchers printed meanwhile, it leaves out what an event already reported, as the verifier
// does with the events it stored; with -refs, the changed files of packages are judged against
// content references served locally from the fixtures in dir, as the verifier does with references
// turned on.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/analyze"
	"github.com/cpibia/tripwatch/internal/verifier/refs"
	"github.com/cpibia/tripwatch/internal/verifier/store"
	"github.com/cpibia/tripwatch/internal/watch"
)

func main() {
	args := os.Args[1:]
	refsDir := ""
	if i := slices.Index(args, "-refs"); i >= 0 && i+1 < len(args) {
		refsDir = args[i+1]
		args = slices.Delete(args, i, i+2)
	}
	if (len(args) == 3 || len(args) == 4) && args[0] == "-snapshots" {
		events := ""
		if len(args) == 4 {
			events = args[3]
		}
		if err := snapshots(args[1], args[2], events, refsDir); err != nil {
			fmt.Fprintln(os.Stderr, "judge:", err)
			os.Exit(1)
		}
		return
	}
	seen := map[string][]watch.Event{}
	history := func(path string, since time.Time) []watch.Event {
		var out []watch.Event
		for _, e := range seen[path] {
			if !e.At.Before(since) {
				out = append(out, e)
			}
		}
		return out
	}
	enc := json.NewEncoder(os.Stdout)
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for in.Scan() {
		var b watch.Batch
		if json.Unmarshal(in.Bytes(), &b) != nil || b.Event != watch.BatchEvent {
			continue
		}
		events := make([]watch.Event, 0, len(b.Events))
		for _, raw := range b.Events {
			var e watch.Event
			if json.Unmarshal(raw, &e) == nil {
				events = append(events, e)
				key := e.Path
				if e.Class == watch.ClassExec {
					key = e.Exe
				}
				seen[key] = append(seen[key], e)
			}
		}
		for _, f := range analyze.EvaluateEvents(events, b.PackageManager, history) {
			_ = enc.Encode(map[string]string{"severity": f.Severity, "title": f.Title, "fingerprint": f.Fingerprint, "detail": f.Detail})
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "judge:", err)
		os.Exit(1)
	}
}

// snapshots prints the alerts the verifier raises on the snapshot in after, compared with the one
// in before, but for the file contents the events in the file named events reported.
func snapshots(before, after, events, refsDir string) error {
	prev, err := readSnapshot(before)
	if err != nil {
		return err
	}
	cur, err := readSnapshot(after)
	if err != nil {
		return err
	}
	if refsDir != "" {
		if cur.Published, err = published(refsDir, cur); err != nil {
			return err
		}
		// The verifier remembers the releases of earlier snapshots; the bench has one.
		cur.KnownReleases = analyze.KnownFrom(prev)
	}
	reported, err := reportedContents(events)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	for _, f := range analyze.Evaluate(&prev, cur) {
		if f.Path != "" && f.SHA256 != "" && reported[f.Path+"\x00"+f.SHA256] {
			continue
		}
		if err := enc.Encode(map[string]string{"severity": f.Severity, "title": f.Title, "fingerprint": f.Fingerprint, "detail": f.Detail}); err != nil {
			return err
		}
	}
	return nil
}

// published judges the snapshot's changed files against content references served from the
// fixtures in dir, on a local server, as the verifier does with references turned on: the bench
// never reaches the network.
func published(dir string, st analyze.State) (map[string]analyze.Published, error) {
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()
	tmp, err := os.MkdirTemp("", "judge-refs")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	db, err := store.Open(filepath.Join(tmp, "refs.db"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	r := &refs.Resolver{Store: db, Fetcher: &refs.Fetcher{Sources: map[string]string{refs.WordPressPlugin: srv.URL}}, Enabled: true, PerRound: 50, PerHostDay: 500}
	return analyze.PublishedFor(context.Background(), r, "bench", st), nil
}

// reportedContents returns the path and content of every file event in the batches of a file.
func reportedContents(name string) (map[string]bool, error) {
	out := map[string]bool{}
	if name == "" {
		return out, nil
	}
	data, err := os.ReadFile(name) //nolint:gosec // a file the benchmark names
	if err != nil {
		return nil, err
	}
	for line := range bytes.Lines(data) {
		var b watch.Batch
		if json.Unmarshal(line, &b) != nil || b.Event != watch.BatchEvent {
			continue
		}
		for _, raw := range b.Events {
			var e watch.Event
			if json.Unmarshal(raw, &e) == nil && e.SHA256 != "" {
				out[e.Path+"\x00"+e.SHA256] = true
			}
		}
	}
	return out, nil
}

// readSnapshot reads a snapshot as tripwatch-sensor prints it, compressed as the sensor sends it.
func readSnapshot(name string) (analyze.State, error) {
	data, err := os.ReadFile(name) //nolint:gosec // a file the benchmark names
	if err != nil {
		return analyze.State{}, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return analyze.State{}, err
	}
	if err := zw.Close(); err != nil {
		return analyze.State{}, err
	}
	return analyze.Decode(buf.Bytes())
}
