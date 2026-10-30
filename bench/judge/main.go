// Command judge applies the verifier's real-time rules to event batches printed by
// tripwatch-sensor -watch-only, read from standard input, and prints each alert they raise as a
// JSON object: the benchmark counts what the verifier would raise, not what the sensor saw.
//
//	judge -snapshots <before> <after> [events]
//
// applies the verifier's snapshot rules to two snapshots printed by tripwatch-sensor instead,
// the second compared with the first, and prints the alerts the same way; with the event batches
// the watchers printed meanwhile, it leaves out what an event already reported, as the verifier
// does with the events it stored.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/analyze"
	"github.com/cpibia/tripwatch/internal/watch"
)

func main() {
	if (len(os.Args) == 4 || len(os.Args) == 5) && os.Args[1] == "-snapshots" {
		events := ""
		if len(os.Args) == 5 {
			events = os.Args[4]
		}
		if err := snapshots(os.Args[2], os.Args[3], events); err != nil {
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
func snapshots(before, after, events string) error {
	prev, err := readSnapshot(before)
	if err != nil {
		return err
	}
	cur, err := readSnapshot(after)
	if err != nil {
		return err
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
