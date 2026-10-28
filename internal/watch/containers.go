package watch

import (
	"context"
	"io/fs"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/system"
)

// ContainerInfo describes, in an event, a container with power over the host.
type ContainerInfo struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Image   string   `json:"image,omitempty"`
	Runtime string   `json:"runtime"`
	Created string   `json:"created,omitempty"`
	Powers  []string `json:"powers"`
}

// Key identifies a container the way the snapshot rules do: by name, image and powers, so a
// redeploy of the same container is not a new one.
func (c ContainerInfo) Key() string {
	return c.Name + "|" + c.Image + "|" + strings.Join(c.Powers, ",")
}

// Bounds of the container watcher.
const (
	// ContainerPoll is how often the runtimes' state is listed. A container started to escape
	// and removed once its job is done lives seconds, never an hour: snapshots miss it.
	ContainerPoll = time.Second
	// maxContainerReads bounds the configurations read in one look, the first aside.
	maxContainerReads = 64
	// maxContainerTries is how many looks a container's configuration may stay unreadable, as
	// while its runtime is still writing it, before it is left out.
	maxContainerTries = 5
	// maxContainerKeys bounds the containers remembered as known. When it is full a new one is
	// not remembered, and each of its redeploys is reported.
	maxContainerKeys = 4096
	maxPowers        = 32
)

// Containers reports, as they appear, the containers with power over the host, and their
// removal. The runtimes' state directories are root's: only root, or whoever the runtime lets
// start containers, which amounts to root, can produce these events.
type Containers struct {
	fsys  fs.FS
	out   chan<- Event
	now   func() time.Time
	known map[string]*tracked
	tries map[string]int
	keys  map[string]bool
	// looked is set after the first look, whose containers were there before the sensor and are
	// left to the snapshots.
	looked bool
	// Dropped counts events lost because the consumer did not keep up.
	Dropped atomic.Int64
}

type tracked struct {
	info     *ContainerInfo
	reported bool
}

func NewContainers(src collector.Source, out chan<- Event) *Containers {
	return &Containers{fsys: src.FS, out: out, now: time.Now, known: map[string]*tracked{}, tries: map[string]int{}, keys: map[string]bool{}}
}

// Run looks at the runtimes' state every ContainerPoll until ctx ends.
func (c *Containers) Run(ctx context.Context) error {
	tick := time.NewTicker(ContainerPoll)
	defer tick.Stop()
	for {
		c.look()
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

func (c *Containers) look() {
	var issues collector.Issues
	refs, _ := system.ContainerRefs(c.fsys, &issues)
	present := make(map[string]bool, len(refs))
	reads := 0
	for _, ref := range refs {
		present[ref.Path] = true
		if _, ok := c.known[ref.Path]; ok {
			continue
		}
		if c.looked && reads == maxContainerReads {
			continue
		}
		reads++
		ct, ok := system.ReadContainer(c.fsys, ref, &issues)
		if !ok {
			if c.tries[ref.Path]++; c.tries[ref.Path] < maxContainerTries {
				continue
			}
			ct = system.Container{}
		}
		delete(c.tries, ref.Path)
		t := &tracked{}
		c.known[ref.Path] = t
		powers := system.ContainerPowers(ct)
		if len(powers) == 0 {
			continue
		}
		t.info = &ContainerInfo{ID: clipText(ct.ID), Name: clipText(ct.Name), Image: clipText(ct.Image), Runtime: ref.Runtime,
			Created: clipText(ct.Created), Powers: powers[:min(len(powers), maxPowers)]}
		key := t.info.Key()
		if c.keys[key] {
			continue
		}
		if len(c.keys) < maxContainerKeys {
			c.keys[key] = true
		}
		if c.looked {
			t.reported = true
			c.send(Event{At: c.now(), Class: ClassContainer, Op: OpCreate, Path: "/" + ref.Path, Container: t.info})
		}
	}
	for p, t := range c.known {
		if present[p] {
			continue
		}
		delete(c.known, p)
		if t.reported {
			c.send(Event{At: c.now(), Class: ClassContainer, Op: OpDelete, Path: "/" + p, Container: t.info})
		}
	}
	for p := range c.tries {
		if !present[p] {
			delete(c.tries, p)
		}
	}
	c.looked = true
}

func (c *Containers) send(e Event) {
	select {
	case c.out <- e:
	default:
		c.Dropped.Add(1)
	}
}
