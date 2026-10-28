package system

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/cpibia/tripwatch/internal/collector"
)

// Containers are read from the daemon's state, at its data root when daemon.json moves it, with
// what gives them power over the host and never their environment.
func TestContainers(t *testing.T) {
	const id = "4f1c2a9be3d0aa11bb22cc33dd44ee55ff66778899aabbccddeeff0011223344"
	dir := "srv/docker/containers/" + id + "/"
	fsys := fstest.MapFS{
		"etc/docker/daemon.json": text(`{"data-root": "/srv/docker"}`),
		dir + "config.v2.json": text(`{"ID": "` + id + `", "Name": "/escape", "Image": "sha256:abc", "Created": "2026-10-28T10:00:00Z",
			"Config": {"Image": "alpine:3.20", "User": "", "Env": ["DB_PASSWORD=secret"]}, "State": {"Running": true},
			"MountPoints": {"/host": {"Source": "/", "Destination": "/host", "RW": true, "Type": "bind"},
				"/data": {"Source": "/srv/docker/volumes/x/_data", "Destination": "/data", "RW": true, "Type": "volume"}}}`),
		dir + "hostconfig.json":             text(`{"Privileged": true, "CapAdd": ["SYS_ADMIN"], "PidMode": "host", "Devices": [{"PathOnHost": "/dev/sda"}]}`),
		"srv/docker/containers/broken/x":    text(""),
		"var/lib/docker/containers/old/cfg": text(""),
	}
	res := collect[ContainersResult](t, Containers{}, collector.Source{FS: fsys})
	if res.Runtime != "docker" || len(res.Containers) != 1 {
		t.Fatalf("result = %+v", res)
	}
	c := res.Containers[0]
	if c.ID != id[:12] || c.Name != "escape" || c.Image != "alpine:3.20" || !c.Running || !c.Privileged || c.PIDMode != "host" ||
		!slices.Equal(c.CapAdd, []string{"SYS_ADMIN"}) || !slices.Equal(c.Devices, []string{"/dev/sda"}) {
		t.Errorf("container = %+v", c)
	}
	if len(c.Mounts) != 1 || c.Mounts[0] != (Mount{Source: "/", Destination: "/host", RW: true}) {
		t.Errorf("mounts = %+v", c.Mounts)
	}
	if data, _ := json.Marshal(res); strings.Contains(string(data), "secret") {
		t.Error("the environment was collected")
	}
	if res := collect[ContainersResult](t, Containers{}, collector.Source{FS: fstest.MapFS{}}); res.Runtime != "" || len(res.Containers) != 0 {
		t.Errorf("no runtime: %+v", res)
	}
}
