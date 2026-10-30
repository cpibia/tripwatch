// Command judge applies the verifier's real-time rules to event batches printed by
// tripwatch-sensor -watch-only, read from standard input, and prints each alert they raise as a
// JSON object: the benchmark counts what the verifier would raise, not what the sensor saw.
//
//	judge -snapshots <before> <after>
//
// applies the verifier's snapshot rules to two snapshots printed by tripwatch-sensor instead,
// the second compared with the first, and prints the alerts the same way.
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
	if len(os.Args) == 4 && os.Args[1] == "-snapshots" {
		if err := snapshots(os.Args[2], os.Args[3]); err != nil {
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
// in before.
func snapshots(before, after string) error {
	prev, err := readSnapshot(before)
	if err != nil {
		return err
	}
	cur, err := readSnapshot(after)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	for _, f := range analyze.Evaluate(&prev, cur) {
		if err := enc.Encode(map[string]string{"severity": f.Severity, "title": f.Title, "fingerprint": f.Fingerprint, "detail": f.Detail}); err != nil {
			return err
		}
	}
	return nil
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
