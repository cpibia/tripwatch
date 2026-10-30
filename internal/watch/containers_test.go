package watch

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
)

func dockerContainer(fsys fstest.MapFS, id, name string, hostConfig string) {
	dir := "var/lib/docker/containers/" + id + "/"
	fsys[dir+"config.v2.json"] = &fstest.MapFile{Data: []byte(`{"ID": "` + id + `", "Name": "/` + name + `", "Config": {"Image": "alpine:3.20"}}`)}
	fsys[dir+"hostconfig.json"] = &fstest.MapFile{Data: []byte(hostConfig)}
}

func drain(ch chan Event) []Event {
	var out []Event
	for {
		select {
		case e := <-ch:
			out = append(out, e)
		default:
			return out
		}
	}
}

// Containers there before the sensor are left to the snapshots. One that appears with power
// over the host is reported, and so is its removal; a plain one, a redeploy of a known one and
// one whose configuration is still being written are not, until it can be read.
func TestContainersReportPowerOverTheHost(t *testing.T) {
	fsys := fstest.MapFS{}
	dockerContainer(fsys, "proxy1", "proxy", `{"Binds": []}`)
	fsys["var/lib/docker/containers/proxy1/config.v2.json"].Data = []byte(`{"ID": "proxy1", "Name": "/proxy", "Config": {"Image": "traefik"},
		"MountPoints": {"/var/run/docker.sock": {"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "Type": "bind"}}}`)
	out := make(chan Event, 16)
	c := NewContainers(collector.Source{FS: fsys}, out)
	c.look()
	if got := drain(out); len(got) != 0 {
		t.Fatalf("containers already there reported: %+v", got)
	}

	dockerContainer(fsys, "esc1", "escape", `{"Privileged": true}`)
	dockerContainer(fsys, "app1", "app", `{}`)
	fsys["var/lib/docker/containers/proxy2/config.v2.json"] = fsys["var/lib/docker/containers/proxy1/config.v2.json"]
	fsys["var/lib/docker/containers/late1/hostconfig.json"] = &fstest.MapFile{Data: []byte(`{"PidMode": "host"}`)}
	c.look()
	got := drain(out)
	if len(got) != 1 || got[0].Class != ClassContainer || got[0].Op != OpCreate || got[0].Path != "/var/lib/docker/containers/esc1" ||
		got[0].Container == nil || got[0].Container.Name != "escape" || got[0].Container.Runtime != "docker" || got[0].Container.Powers[0] != "privileged" {
		t.Fatalf("after the start: %+v", got)
	}

	fsys["var/lib/docker/containers/late1/config.v2.json"] = &fstest.MapFile{Data: []byte(`{"ID": "late1", "Name": "/late"}`)}
	delete(fsys, "var/lib/docker/containers/esc1/config.v2.json")
	delete(fsys, "var/lib/docker/containers/esc1/hostconfig.json")
	c.look()
	got = drain(out)
	if len(got) != 2 {
		t.Fatalf("after the removal: %+v", got)
	}
	for _, e := range got {
		switch {
		case e.Op == OpCreate && e.Container.Name == "late" && e.Container.Powers[0] == "the host's processes":
		case e.Op == OpDelete && e.Path == "/var/lib/docker/containers/esc1" && e.Container.Name == "escape":
		default:
			t.Errorf("unexpected event %+v", e)
		}
	}

	// A full consumer loses the event and counts it.
	full := make(chan Event)
	c.out = full
	dockerContainer(fsys, "esc2", "escape-2", `{"Privileged": true}`)
	c.look()
	if c.Dropped.Load() != 1 {
		t.Errorf("dropped = %d", c.Dropped.Load())
	}
}

// The same name, tag and powers on another image is reported with the image it replaces, even
// while the key is known; the same container started again is reported once its key has been
// gone for an hour, not when it is redeployed within it.
func TestContainersImageSwapAndKeyExpiry(t *testing.T) {
	sock := func(id, image string) []byte {
		return []byte(`{"ID": "` + id + `", "Name": "/proxy", "Image": "` + image + `", "Config": {"Image": "proxy:v2"},
			"MountPoints": {"/var/run/docker.sock": {"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "Type": "bind"}}}`)
	}
	start := func(fsys fstest.MapFS, id, image string) {
		dockerContainer(fsys, id, "proxy", `{}`)
		fsys["var/lib/docker/containers/"+id+"/config.v2.json"].Data = sock(id, image)
	}
	stop := func(fsys fstest.MapFS, id string) {
		delete(fsys, "var/lib/docker/containers/"+id+"/config.v2.json")
		delete(fsys, "var/lib/docker/containers/"+id+"/hostconfig.json")
	}
	now := time.Unix(1_000_000, 0)
	fsys := fstest.MapFS{}
	start(fsys, "p1", "sha256:good")
	out := make(chan Event, 8)
	c := NewContainers(collector.Source{FS: fsys}, out)
	c.now = func() time.Time { return now }
	c.look()

	stop(fsys, "p1")
	start(fsys, "p2", "sha256:good")
	c.look()
	if got := drain(out); len(got) != 0 {
		t.Fatalf("redeploy of the same image: %+v", got)
	}

	stop(fsys, "p2")
	start(fsys, "p3", "sha256:backdoor")
	now = now.Add(time.Minute)
	c.look()
	got := drain(out)
	if len(got) != 1 || got[0].Op != OpCreate || got[0].Container.ImageID != "sha256:backdoor" || got[0].Container.Replaces != "sha256:good" {
		t.Fatalf("image swapped under the same tag: %+v", got)
	}

	stop(fsys, "p3")
	c.look()
	drain(out)
	now = now.Add(containerKeyTTL + time.Minute)
	c.look()
	start(fsys, "p4", "sha256:backdoor")
	c.look()
	got = drain(out)
	if len(got) != 1 || got[0].Op != OpCreate || got[0].Container.ID != "p4" || got[0].Container.Replaces != "" {
		t.Fatalf("started again after its key expired: %+v", got)
	}

	// The image last seen for a key outlives the key: a swap after a long stop names it.
	stop(fsys, "p4")
	c.look()
	drain(out)
	now = now.Add(24 * time.Hour)
	c.look()
	start(fsys, "p5", "sha256:other")
	c.look()
	got = drain(out)
	if len(got) != 1 || got[0].Container.Replaces != "sha256:backdoor" {
		t.Fatalf("image swapped after a day stopped: %+v", got)
	}
}

// A configuration never readable is given up after a few looks, and not read again.
func TestContainersGiveUpOnUnreadable(t *testing.T) {
	fsys := fstest.MapFS{"var/lib/docker/containers/bad1/config.v2.json": &fstest.MapFile{Data: []byte(`{`)}}
	c := NewContainers(collector.Source{FS: fsys}, make(chan Event, 1))
	for range maxContainerTries + 1 {
		c.look()
	}
	if len(c.tries) != 0 || c.known["var/lib/docker/containers/bad1"] == nil {
		t.Errorf("tries %v, known %v", c.tries, c.known)
	}
}

// A container is read again when its configuration is rewritten, as at its start: created with
// a harmless directory, started with the host's root behind it, it is reported then.
func TestContainersReadAgainAtStart(t *testing.T) {
	const cfg = "var/lib/docker/containers/s1/config.v2.json"
	fsys := fstest.MapFS{
		"proc/1/mountinfo":     &fstest.MapFile{Data: []byte("22 1 8:1 / / rw shared:1 - ext4 /dev/vda1 rw\n")},
		"proc/77/mountinfo":    &fstest.MapFile{Data: []byte("501 500 8:1 / /h rw - ext4 /dev/vda1 rw\n")},
		"tmp/x/keep":           &fstest.MapFile{},
		"var/lib/docker/.keep": &fstest.MapFile{},
	}
	out := make(chan Event, 4)
	c := NewContainers(collector.Source{FS: fsys}, out)
	c.look()
	created := `{"ID": "s1", "Name": "/s", "MountPoints": {"/h": {"Source": "/tmp/x", "Destination": "/h", "RW": true, "Type": "bind"}}}`
	fsys[cfg] = &fstest.MapFile{Data: []byte(created), ModTime: time.Unix(100, 0)}
	c.look()
	if got := drain(out); len(got) != 0 {
		t.Fatalf("after the creation: %+v", got)
	}
	c.look()
	started := strings.Replace(created, `"MountPoints"`, `"State": {"Running": true, "Pid": 77}, "MountPoints"`, 1)
	fsys[cfg] = &fstest.MapFile{Data: []byte(started), ModTime: time.Unix(101, 0)}
	c.look()
	got := drain(out)
	if len(got) != 1 || got[0].Op != OpCreate || got[0].Container.Powers[0] != "the host's /, writable" {
		t.Fatalf("after the start: %+v", got)
	}
	c.look()
	if got := drain(out); len(got) != 0 {
		t.Errorf("reported again without a change: %+v", got)
	}
}

// Containers rewritten at every look, as a health check does, neither hold back a new one nor
// keep a started one from being read again within a few looks.
func TestContainersRewritesDoNotStarve(t *testing.T) {
	fsys := fstest.MapFS{
		"proc/1/mountinfo":  &fstest.MapFile{Data: []byte("22 1 8:1 / / rw shared:1 - ext4 /dev/vda1 rw\n")},
		"proc/77/mountinfo": &fstest.MapFile{Data: []byte("501 500 8:1 / /h rw - ext4 /dev/vda1 rw\n")},
	}
	busy := maxContainerReads + 6
	for i := range busy {
		dockerContainer(fsys, fmt.Sprintf("a%03d", i), fmt.Sprintf("busy-%d", i), `{}`)
	}
	const late = "var/lib/docker/containers/ffff/config.v2.json"
	created := `{"ID": "ffff", "Name": "/s", "MountPoints": {"/h": {"Source": "/tmp/x", "Destination": "/h", "RW": true, "Type": "bind"}}}`
	fsys[late] = &fstest.MapFile{Data: []byte(created)}
	out := make(chan Event, 8)
	c := NewContainers(collector.Source{FS: fsys}, out)
	c.look()
	tick := 0
	rewrite := func() {
		tick++
		for i := range busy {
			fsys[fmt.Sprintf("var/lib/docker/containers/a%03d/config.v2.json", i)].ModTime = time.Unix(int64(tick), 0)
		}
	}
	rewrite()
	dockerContainer(fsys, "fffe", "escape", `{"Privileged": true}`)
	c.look()
	if got := drain(out); len(got) != 1 || got[0].Container.Name != "escape" {
		t.Fatalf("new container behind rewrites: %+v", got)
	}
	started := strings.Replace(created, `"MountPoints"`, `"State": {"Running": true, "Pid": 77}, "MountPoints"`, 1)
	fsys[late] = &fstest.MapFile{Data: []byte(started), ModTime: time.Unix(1000, 0)}
	var got []Event
	for range 3 {
		rewrite()
		c.look()
		got = append(got, drain(out)...)
	}
	if len(got) != 1 || got[0].Container.Name != "s" {
		t.Errorf("started container behind rewrites: %+v", got)
	}
}
