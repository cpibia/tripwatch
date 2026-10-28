package watch

import (
	"testing"
	"testing/fstest"

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
