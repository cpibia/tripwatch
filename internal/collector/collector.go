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

// collectWithTimeout runs c under a deadline. Collectors check their context while walking,
// so they stop soon after it expires; if one is stuck in a call that ignores it, Run moves on
// and the goroutine is left to finish on its own.
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
		return nil, fmt.Errorf("%s: %w after %s", c.Name(), ctx.Err(), Timeout)
	}
}
