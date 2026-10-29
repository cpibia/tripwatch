package store

import (
	"errors"
	"fmt"
	"time"
)

// Retention says how long the verifier keeps what it holds. Snapshots are thinned to one a day
// after DenseRetention and kept as evidence of open alerts past Snapshots; resolved alerts stay
// for reference, high and critical ones for Resolved, medium and low ones, which are most of the
// noise, for MinorResolved; a condition that comes back after that is raised as new.
type Retention struct {
	Snapshots     time.Duration
	Events        time.Duration
	Resolved      time.Duration
	MinorResolved time.Duration
}

const day = 24 * time.Hour

// DefaultRetention is what the verifier keeps unless configured otherwise.
var DefaultRetention = Retention{Snapshots: 30 * day, Events: 7 * day, Resolved: 90 * day, MinorResolved: 7 * day}

// maxRetention bounds every retention: the database has to stay a size one machine handles.
const maxRetention = 3650 * day

// Validate refuses a retention the verifier cannot work with: snapshots shorter than the time
// they are all kept, or anything under a day or past ten years.
func (r Retention) Validate() error {
	for _, v := range []struct {
		name  string
		value time.Duration
	}{{"snapshots", r.Snapshots}, {"events", r.Events}, {"resolved alerts", r.Resolved}, {"resolved minor alerts", r.MinorResolved}} {
		if v.value < day || v.value > maxRetention {
			return fmt.Errorf("store: retention of %s must be from 1 to %d days", v.name, maxRetention/day)
		}
	}
	if r.Snapshots < DenseRetention {
		return fmt.Errorf("store: snapshots are kept at least %d days", DenseRetention/day)
	}
	if r.MinorResolved > r.Resolved {
		return errors.New("store: resolved minor alerts cannot be kept longer than the others")
	}
	return nil
}

// SetRetention changes what the store keeps from now on. It is set once, before the verifier
// serves.
func (s *Store) SetRetention(r Retention) error {
	if err := r.Validate(); err != nil {
		return err
	}
	s.retain = r
	return nil
}

// Retention returns what the store keeps.
func (s *Store) Retention() Retention { return s.retain }
