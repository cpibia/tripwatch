//go:build !linux

package watch

import (
	"context"
	"sync/atomic"

	"github.com/cpibia/tripwatch/internal/collector"
)

// Decoys is a stand-in outside Linux, where fanotify does not exist.
type Decoys struct {
	Dropped  atomic.Int64
	Overflow atomic.Int64
}

func NewDecoys(collector.Source, chan<- Event) (*Decoys, error) { return nil, ErrUnsupported }

func (*Decoys) Close() error                  { return nil }
func (*Decoys) Set([]string) []string         { return nil }
func (*Decoys) Run(ctx context.Context) error { <-ctx.Done(); return nil }
