package watch

import (
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
	if len(got) != 1 || got[0].Op != OpCreate || got[0].Container.Powers[0] != "the host's /tmp/x (/), writable" {
		t.Fatalf("after the start: %+v", got)
	}
	c.look()
	if got := drain(out); len(got) != 0 {
		t.Errorf("reported again without a change: %+v", got)
	}
}
