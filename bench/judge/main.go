// Command judge applies the verifier's real-time rules to event batches printed by
// tripwatch-sensor -watch-only, read from standard input, and prints each alert they raise as a
// JSON object: the benchmark counts what the verifier would raise, not what the sensor saw.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/analyze"
	"github.com/cpibia/tripwatch/internal/watch"
)

func main() {
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
