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
	Dropped atomic.Int64
}

func NewFiles(string, collector.Source, chan<- Event) (*Files, error) { return nil, ErrUnsupported }

func (*Files) Close() error                  { return nil }
func (*Files) Issues() collector.Issues      { return nil }
func (*Files) Watches() int                  { return 0 }
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
func (*Execs) Run(ctx context.Context) error { <-ctx.Done(); return nil }
