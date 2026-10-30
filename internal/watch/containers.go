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
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image,omitempty"`
	ImageID string `json:"image_id,omitempty"`
	// Replaces is the image a container of the same name, tag and powers ran within the hour
	// before, when it was another one.
	Replaces string   `json:"replaces,omitempty"`
	Runtime  string   `json:"runtime"`
	Created  string   `json:"created,omitempty"`
	Powers   []string `json:"powers"`
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
	// containerKeyTTL is how long a container's key stays known after the last container with
	// it is gone: a redeploy is not reported, the same container started again later is.
	containerKeyTTL = time.Hour
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
	// keys holds when a container was last seen, by its key and image; images the image last
	// seen for each key, to tell a swapped image from a redeploy.
	keys   map[string]time.Time
	images map[string]seenImage
	// looked is set after the first look, whose containers were there before the sensor and are
	// left to the snapshots.
	looked bool
	// rereadFrom is where in the list the next look starts reading changed containers again,
	// so that containers rewritten every second (by a health check) cannot take every turn.
	rereadFrom int
	// Dropped counts events lost because the consumer did not keep up.
	Dropped atomic.Int64
}

type seenImage struct {
	id string
	at time.Time
}

type tracked struct {
	info     *ContainerInfo
	reported bool
	// stamp is the configuration's as last read: a start rewrites it, and the container is
	// read again, since its mounts are only certain once its process runs.
	stamp string
}

func NewContainers(src collector.Source, out chan<- Event) *Containers {
	return &Containers{fsys: src.FS, out: out, now: time.Now, known: map[string]*tracked{}, tries: map[string]int{},
		keys: map[string]time.Time{}, images: map[string]seenImage{}}
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
	host := system.NewHostMounts(c.fsys)
	present := make(map[string]bool, len(refs))
	// Containers never seen come first, with a budget of their own: rewrites of known ones
	// cannot hold back the one started to escape.
	reads := 0
	var changed []system.ContainerRef
	for _, ref := range refs {
		present[ref.Path] = true
		if _, seen := c.known[ref.Path]; seen {
			changed = append(changed, ref)
			continue
		}
		if c.looked && reads == maxContainerReads {
			continue
		}
		reads++
		c.read(ref, nil, host, &issues)
	}
	rereads := 0
	for n := range changed {
		if rereads == maxContainerReads {
			break
		}
		ref := changed[(c.rereadFrom+n)%len(changed)]
		t := c.known[ref.Path]
		if system.ContainerStamp(c.fsys, ref) == t.stamp {
			continue
		}
		rereads++
		c.read(ref, t, host, &issues)
	}
	if len(changed) > 0 {
		c.rereadFrom = (c.rereadFrom + maxContainerReads) % len(changed)
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
	now := c.now()
	for _, t := range c.known {
		if t.info != nil {
			c.remember(t.info, now)
		}
	}
	for k, at := range c.keys {
		if now.Sub(at) > containerKeyTTL {
			delete(c.keys, k)
		}
	}
	for k, img := range c.images {
		if now.Sub(img.at) > containerKeyTTL {
			delete(c.images, k)
		}
	}
	c.looked = true
}

// read reads a container, new when t is nil, and reports it when it has power over the host
// that was not reported for it, or for a container like it, before.
func (c *Containers) read(ref system.ContainerRef, t *tracked, host *system.HostMounts, issues *collector.Issues) {
	stamp := system.ContainerStamp(c.fsys, ref)
	ct, ok := system.ReadContainer(c.fsys, ref, host, issues)
	if !ok && t != nil {
		t.stamp = stamp
		return
	}
	if !ok {
		if c.tries[ref.Path]++; c.tries[ref.Path] < maxContainerTries {
			return
		}
		ct = system.Container{}
	}
	delete(c.tries, ref.Path)
	if t == nil {
		t = &tracked{}
		c.known[ref.Path] = t
	}
	t.stamp = stamp
	powers := system.ContainerPowers(ct)
	if len(powers) == 0 {
		return
	}
	info := &ContainerInfo{ID: clipText(ct.ID), Name: clipText(ct.Name), Image: clipText(ct.Image), ImageID: clipText(ct.ImageID),
		Runtime: ref.Runtime, Created: clipText(ct.Created), Powers: powers[:min(len(powers), maxPowers)]}
	if t.info != nil && imageKey(t.info) == imageKey(info) {
		return
	}
	t.info = info
	now := c.now()
	if _, known := c.keys[imageKey(info)]; known {
		c.remember(info, now)
		return
	}
	// The tag is a label whoever controls the daemon rewrites: the same name, tag and powers on
	// another image is another program, reported with the image it took the place of.
	if was, ok := c.images[info.Key()]; ok && was.id != "" && info.ImageID != "" && was.id != info.ImageID {
		info.Replaces = was.id
	}
	c.remember(info, now)
	if c.looked {
		t.reported = true
		c.send(Event{At: c.now(), Class: ClassContainer, Op: OpCreate, Path: "/" + ref.Path, Container: t.info})
	}
}

// remember records a container's key and image as seen at now. When the bound is reached a new
// key is not remembered, and each redeploy of its container is reported.
func (c *Containers) remember(info *ContainerInfo, now time.Time) {
	if _, ok := c.keys[imageKey(info)]; ok || len(c.keys) < maxContainerKeys {
		c.keys[imageKey(info)] = now
	}
	if _, ok := c.images[info.Key()]; ok || len(c.images) < maxContainerKeys {
		c.images[info.Key()] = seenImage{id: info.ImageID, at: now}
	}
}

// imageKey is a container's key with its image's digest.
func imageKey(info *ContainerInfo) string {
	return info.Key() + "|" + info.ImageID
}

func (c *Containers) send(e Event) {
	select {
	case c.out <- e:
	default:
		c.Dropped.Add(1)
	}
}
