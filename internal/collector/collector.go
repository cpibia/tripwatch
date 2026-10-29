// Package collector defines how the sensor gathers state and the types collectors share.
package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Timeout bounds each collector, so that one stuck on a hostile file or a huge tree cannot
// stop the others or the next snapshot.
var Timeout = 15 * time.Minute

// Grace is how long a collector has, after its deadline, to hand back a partial result.
var Grace = 30 * time.Second

// Collector gathers one aspect of the machine state. Collectors only observe: judging what
// is suspicious is the verifier's job.
type Collector interface {
	Name() string
	Collect(ctx context.Context, src Source) (any, error)
}

// Snapshot is the combined output of a collection run.
type Snapshot struct {
	TakenAt time.Time                  `json:"taken_at"`
	Results map[string]json.RawMessage `json:"results"`
	Errors  map[string]string          `json:"errors,omitempty"`
	// Warnings are conditions that weaken what the snapshot can be trusted for.
	Warnings []string `json:"warnings,omitempty"`
}

// MaxResultsSize bounds the results of a snapshot together: the verifier refuses a snapshot past
// 32 MB uncompressed, and the transport an envelope past its own limit, which would stay pending
// and hold back every envelope after it.
const MaxResultsSize = 30 << 20

// Bound drops the largest results until the rest fit in limit bytes, each named in Errors: what
// a user inflated (processes, files in a home) costs that result, never the whole snapshot.
func (s *Snapshot) Bound(limit int) {
	total := 0
	for _, r := range s.Results {
		total += len(r)
	}
	for total > limit && len(s.Results) > 0 {
		name, size := "", -1
		for n, r := range s.Results {
			if len(r) > size || (len(r) == size && n < name) {
				name, size = n, len(r)
			}
		}
		delete(s.Results, name)
		total -= size
		if s.Errors == nil {
			s.Errors = map[string]string{}
		}
		s.Errors[name] = fmt.Sprintf("result left out of the snapshot: %d bytes, past the %d all results may take together", size, limit)
	}
}

// Run executes every collector against src. A failing collector is recorded in Errors and
// does not stop the others.
func Run(ctx context.Context, src Source, collectors []Collector, now time.Time) Snapshot {
	snap := Snapshot{TakenAt: now.UTC(), Results: map[string]json.RawMessage{}}
	fail := func(name string, err error) {
		if snap.Errors == nil {
			snap.Errors = map[string]string{}
		}
		snap.Errors[name] = err.Error()
	}

	for _, c := range collectors {
		result, err := collectWithTimeout(ctx, c, src)
		if err != nil {
			fail(c.Name(), err)
			continue
		}
		raw, err := json.Marshal(result)
		if err != nil {
			fail(c.Name(), err)
			continue
		}
		snap.Results[c.Name()] = raw
	}
	snap.Warnings = Warnings()
	return snap
}

type outcome struct {
	result any
	err    error
}

// collectWithTimeout runs c under a deadline. Collectors check their context while walking and
// may return what they gathered so far; that partial result is waited for during Grace. A
// collector stuck in a call that ignores the context is abandoned and left to finish alone.
func collectWithTimeout(ctx context.Context, c Collector, src Source) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	done := make(chan outcome, 1)
	go func() {
		result, err := c.Collect(ctx, src)
		done <- outcome{result, err}
	}()
	select {
	case o := <-done:
		return o.result, o.err
	case <-ctx.Done():
	}
	select {
	case o := <-done:
		if o.err != nil {
			return nil, fmt.Errorf("%s: %w after %s", c.Name(), o.err, Timeout)
		}
		return o.result, nil
	case <-time.After(Grace):
		return nil, fmt.Errorf("%s: %w after %s", c.Name(), ctx.Err(), Timeout)
	}
}
