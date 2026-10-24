//go:build !linux

package watch

import (
	"context"
	"sync/atomic"

	"github.com/cpibia/tripwatch/internal/collector"
)

// Files is a stand-in outside Linux, where inotify does not exist: the sensor runs there only
// for development.
type Files struct {
	Dropped       atomic.Int64
	DroppedSystem atomic.Int64
	Urgent        chan<- Event
	IsRootEvent   func(Event) bool
}

func NewFiles(string, collector.Source, chan<- Event) (*Files, error) { return nil, ErrUnsupported }

func (*Files) Close() error                  { return nil }
func (*Files) Issues() collector.Issues      { return nil }
func (*Files) Watches() int                  { return 0 }
func (*Files) Unwatched() []string           { return nil }
func (*Files) SetWebUsers([]int)             {}
func (*Files) Set([]Target)                  {}
func (*Files) Run(ctx context.Context) error { <-ctx.Done(); return nil }

// Execs is a stand-in outside Linux, where the process connector does not exist.
type Execs struct {
	Dropped    atomic.Int64
	Skipped    atomic.Int64
	CapDropErr error
}

func NewExecs(collector.Source, chan<- Event) (*Execs, error) { return nil, ErrUnsupported }

func (*Execs) Close() error                  { return nil }
func (*Execs) SetWebUsers([]int)             {}
func (*Execs) SetHomes(map[int]string)       {}
func (*Execs) SetUploads([]string)           {}
func (*Execs) Run(ctx context.Context) error { <-ctx.Done(); return nil }
