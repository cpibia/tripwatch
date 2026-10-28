package system

import (
	"encoding/json"
	"fmt"
	"io/fs"
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

// Every way of handing a container the host counts, under any name; what containers commonly
// share without power over the host does not.
func TestContainerPowers(t *testing.T) {
	rw := func(src string) Mount { return Mount{Source: src, Destination: "/x", RW: true} }
	ro := func(src string) Mount { return Mount{Source: src, Destination: "/x"} }
	for _, tt := range []struct {
		c    Container
		want []string
	}{
		{Container{Mounts: []Mount{rw("/")}}, []string{"the host's /, writable"}},
		{Container{Mounts: []Mount{{Source: "/", Destination: "/host", RW: true, Volume: "h"}}}, []string{"the host's volume h (/), writable"}},
		{Container{Mounts: []Mount{{Source: "/tmp/l", Resolved: "/", Destination: "/host"}}}, []string{"the host's /tmp/l (/), read-only"}},
		{Container{Mounts: []Mount{rw("/etc/cron.d")}}, []string{"the host's /etc/cron.d, writable"}},
		{Container{Mounts: []Mount{rw("/etc/systemd/system/")}}, []string{"the host's /etc/systemd/system, writable"}},
		{Container{Mounts: []Mount{ro("/root/.ssh")}}, []string{"the host's /root/.ssh, read-only"}},
		{Container{Mounts: []Mount{ro("/etc/shadow")}}, []string{"the host's /etc/shadow, read-only"}},
		{Container{Mounts: []Mount{ro("/proc/1/root")}}, []string{"the host's /proc/1/root, read-only"}},
		{Container{Mounts: []Mount{rw("/sys/fs/cgroup")}}, []string{"the host's /sys/fs/cgroup, writable"}},
		{Container{Mounts: []Mount{rw("/var")}}, []string{"the host's /var, writable"}},
		{Container{Mounts: []Mount{rw("/var/run/docker.sock")}}, []string{"the runtime socket /var/run/docker.sock"}},
		{Container{Mounts: []Mount{rw("/run/containerd")}}, []string{"the runtime socket /run/containerd"}},
		{Container{Mounts: []Mount{rw("/srv/ci/docker.sock")}}, []string{"the runtime socket /srv/ci/docker.sock"}},
		{Container{Mounts: []Mount{rw("/dev/vda")}}, []string{"the host's disk /dev/vda, writable"}},
		{Container{Devices: []string{"/dev/xvda", "/dev/dm-0", "/dev/null", "/dev/fuse"}}, []string{"device /dev/xvda", "device /dev/dm-0"}},
		{Container{DeviceRules: []string{"b *:* rwm"}}, []string{"device rule b *:* rwm"}},
		{Container{DeviceRules: []string{"c 1:1 rw", "c 1:3 rwm", "c 189:* rwm", "b *:* m"}}, []string{"device rule c 1:1 rw"}},
		{Container{DeviceRules: []string{DeviceRulesTruncated}}, []string{"device rule ..."}},
		{Container{Mounts: []Mount{rw("/etc/localtime"), {Source: "/etc/localtime", Resolved: "/usr/share/zoneinfo/Europe/Rome", RW: true}, rw("/etc/hosts"), ro("/etc/letsencrypt"), ro("/etc/ssl/certs"), rw("/srv/app"),
			rw("/home/app/data"), rw("/var/log/app"), rw("/dev/log"), ro("/sys/fs/cgroup"), rw("/run/user/1000/bus")}}, nil},
	} {
		if got := ContainerPowers(tt.c); !slices.Equal(got, tt.want) {
			t.Errorf("%+v: got %q, want %q", tt.c, got, tt.want)
		}
	}
}

// A Docker volume whose local driver binds a host path is that path; a link is followed inside
// the observed root; only cgroup rules granting access are kept, with a marker past the bound.
func TestDockerVolumesLinksAndDeviceRules(t *testing.T) {
	const id = "0123456789ab0123456789ab"
	dir := "var/lib/docker/containers/" + id + "/"
	var rules []string
	for i := range maxContainerList + 1 {
		rules = append(rules, fmt.Sprintf(`"c 4:%d rw"`, i))
	}
	fsys := fstest.MapFS{
		"var/lib/docker/volumes/h/opts.json":   text(`{"MountType":"none","MountOpts":"bind","MountDevice":"/etc","Quota":{"Size":0}}`),
		"var/lib/docker/volumes/nfs/opts.json": text(`{"MountType":"nfs","MountOpts":"addr=10.0.0.1","MountDevice":":/export"}`),
		"var/lib/docker/volumes/data/_data/x":  text(""),
		"tmp/l":                                &fstest.MapFile{Data: []byte("/"), Mode: fs.ModeSymlink},
		dir + "config.v2.json": text(`{"ID": "` + id + `", "Name": "/v", "MountPoints": {
			"/a": {"Source": "/var/lib/docker/volumes/h/_data", "Destination": "/a", "RW": true, "Name": "h", "Driver": "local", "Type": "volume"},
			"/b": {"Source": "/var/lib/docker/volumes/nfs/_data", "Destination": "/b", "Name": "nfs", "Driver": "local", "Type": "volume"},
			"/c": {"Source": "/var/lib/docker/volumes/data/_data", "Destination": "/c", "Name": "data", "Driver": "local", "Type": "volume"},
			"/d": {"Source": "/var/lib/docker/volumes/x/_data", "Destination": "/d", "Name": "../../../etc", "Driver": "local", "Type": "volume"},
			"/e": {"Source": "/tmp/l", "Destination": "/e", "Type": "bind"}}}`),
		dir + "hostconfig.json": text(`{"DeviceCgroupRules": ["b *:* m", ` + strings.Join(rules, ", ") + `]}`),
	}
	res := collect[ContainersResult](t, Containers{}, collector.Source{FS: fsys})
	if len(res.Containers) != 1 {
		t.Fatalf("result = %+v", res)
	}
	c := res.Containers[0]
	want := []Mount{{Source: "/etc", Destination: "/a", RW: true, Volume: "h"}, {Source: "/tmp/l", Destination: "/e", Resolved: "/"}}
	if !slices.Equal(c.Mounts, want) {
		t.Errorf("mounts = %+v", c.Mounts)
	}
	if len(c.DeviceRules) != maxContainerList+1 || c.DeviceRules[0] != "c 4:0 rw" || c.DeviceRules[maxContainerList] != DeviceRulesTruncated {
		t.Errorf("device rules = %q", c.DeviceRules)
	}
}
