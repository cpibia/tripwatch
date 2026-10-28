package system

import (
	"encoding/json"
	"fmt"
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

// Containers of containerd (Kubernetes' included, Docker's own namespace left to the daemon's
// state), Podman and CRI-O are read from their OCI bundles: a namespace missing from the list is
// the host's, a full set of capabilities is privileged mode.
func TestOCIContainers(t *testing.T) {
	var caps []string
	for i := range 41 {
		caps = append(caps, fmt.Sprintf("CAP_%d", i))
	}
	all, _ := json.Marshal(caps)
	fsys := fstest.MapFS{
		"run/containerd/io.containerd.runtime.v2.task/k8s.io/0a1b2c3d4e5f6a7b/config.json": text(`{"hostname": "node-1",
			"process": {"user": {"uid": 0}, "capabilities": {"effective": ` + string(all) + `}, "env": ["TOKEN=secret"]},
			"linux": {"namespaces": [{"type": "mount"}, {"type": "network"}, {"type": "ipc"}]},
			"mounts": [{"destination": "/host", "type": "bind", "source": "/", "options": ["rbind", "rw"]}, {"destination": "/proc", "type": "proc", "source": "proc"}],
			"annotations": {"io.kubernetes.cri.container-name": "agent", "io.kubernetes.cri.sandbox-name": "agent-x7k2p", "io.kubernetes.cri.sandbox-namespace": "kube-system", "io.kubernetes.cri.image-name": "registry.example.com/agent:1"}}`),
		"run/containerd/io.containerd.runtime.v2.task/moby/ffff/config.json": text(`{"hostname": "docker-one"}`),
		"var/lib/containers/storage/overlay-containers/9e8d7c6b5a4f3e2d1c0b/userdata/config.json": text(`{"hostname": "web",
			"process": {"user": {"uid": 33}, "capabilities": {"effective": ["CAP_CHOWN", "CAP_NET_BIND_SERVICE"]}},
			"linux": {"namespaces": [{"type": "pid"}, {"type": "network"}, {"type": "ipc"}, {"type": "mount"}]},
			"mounts": [{"destination": "/etc/host", "type": "bind", "source": "/etc", "options": ["rbind", "ro"]}]}`),
	}
	res := collect[ContainersResult](t, Containers{}, collector.Source{FS: fsys})
	if res.Runtime != "containerd,podman" || len(res.Containers) != 2 {
		t.Fatalf("result = %+v", res)
	}
	k, p := res.Containers[0], res.Containers[1]
	if k.Name != "containerd:kube-system/agent-x7k2p/agent" || k.Image != "registry.example.com/agent:1" || !k.Privileged || k.PIDMode != "host" ||
		k.NetworkMode != "" || k.UsernsMode != "host" || len(k.Mounts) != 1 || k.Mounts[0] != (Mount{Source: "/", Destination: "/host", RW: true}) {
		t.Errorf("kubernetes container = %+v", k)
	}
	if p.Name != "podman:web" || p.ID != "9e8d7c6b5a4f" || p.Privileged || p.PIDMode != "" || p.UsernsMode != "" ||
		!slices.Equal(p.CapAdd, []string{"CAP_CHOWN", "CAP_NET_BIND_SERVICE"}) || p.Mounts[0] != (Mount{Source: "/etc", Destination: "/etc/host"}) {
		t.Errorf("podman container = %+v", p)
	}
	if data, _ := json.Marshal(res); strings.Contains(string(data), "secret") {
		t.Error("the environment was collected")
	}
}
