// Package collector defines how the sensor gathers state and the types collectors share.
package collector

import (
	"context"
	"encoding/json"
	"time"
)

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
		result, err := c.Collect(ctx, src)
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
	return snap
}
