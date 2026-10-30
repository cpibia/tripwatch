package system

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

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

// CRI-O names the image's ID in the bundle, which tells an image put under the same tag apart.
func TestCRIOImageID(t *testing.T) {
	var cfg ociConfig
	if err := json.Unmarshal([]byte(`{"annotations": {"io.kubernetes.container.name": "agent", "io.kubernetes.container.image": "agent:1",
		"io.kubernetes.cri-o.ImageRef": "3f2a9c1d"}}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if c := ociContainer(fstest.MapFS{}, "cri-o", "run/containers/storage/overlay-containers/abc/userdata/config.json", cfg); c.Image != "agent:1" || c.ImageID != "3f2a9c1d" {
		t.Errorf("container = %+v", c)
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
		{Container{Mounts: []Mount{rw("/run/dbus/system_bus_socket")}}, []string{"the root socket /run/dbus/system_bus_socket"}},
		{Container{Mounts: []Mount{ro("/run/dbus")}}, []string{"the root socket /run/dbus"}},
		{Container{Mounts: []Mount{ro("/run/systemd")}}, []string{"the root socket /run/systemd"}},
		{Container{Mounts: []Mount{rw("/var/snap/lxd/common/lxd/unix.socket")}}, []string{"the root socket /var/snap/lxd/common/lxd/unix.socket"}},
		{Container{Mounts: []Mount{rw("/srv/build/buildkitd.sock")}}, []string{"the root socket /srv/build/buildkitd.sock"}},
		{Container{Mounts: []Mount{rw("/run/systemd/journal")}}, nil},
		{Container{Mounts: []Mount{rw("/run/systemd/system")}}, []string{"the host's /run/systemd/system, writable"}},
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

// A running container's mounts are also judged by its kernel's mount table, which a link swapped
// in before the start and put back afterwards cannot fool. The kernel adds powers and never
// takes one away: a shorter alias of a sensitive tree does not hide it.
func TestRunningContainerMountsFromTheKernel(t *testing.T) {
	const host = "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw\n" +
		"23 22 8:16 / /data rw shared:2 - ext4 /dev/vdb1 rw\n" +
		"24 22 8:16 /docker /var/lib/docker rw shared:2 - ext4 /dev/vdb1 rw\n" +
		"25 24 0:52 / /var/lib/docker/overlay2/abc/merged rw - overlay overlay rw\n" +
		"26 22 8:1 /srv/x /mnt/x rw shared:1 - ext4 /dev/vda1 rw\n"
	const rootfs = "500 400 0:52 / / rw - overlay overlay rw\n" +
		"501 500 0:60 / /proc rw - proc proc rw\n" +
		"502 500 8:16 /docker/containers/a1b2c3d4e5f6a1b2c3d4e5f6/hosts /etc/hosts rw - ext4 /dev/vdb1 rw\n"
	run := func(mountinfo, mountPoints string) Container {
		t.Helper()
		const id = "a1b2c3d4e5f6a1b2c3d4e5f6"
		fsys := fstest.MapFS{
			"proc/1/mountinfo":    text(host),
			"proc/4242/mountinfo": text(mountinfo),
			"var/lib/docker/containers/" + id + "/config.v2.json": text(`{"ID": "` + id + `", "Name": "/s", "State": {"Running": true, "Pid": 4242},
				"MountPoints": {` + mountPoints + `}}`),
		}
		return collect[ContainersResult](t, Containers{}, collector.Source{FS: fsys}).Containers[0]
	}
	const unverified = "mounts not verified by the kernel"
	bind := func(src, dst string) string {
		return `"` + dst + `": {"Source": "` + src + `", "Destination": "` + dst + `", "RW": true, "Type": "bind"}`
	}
	for _, tt := range []struct {
		name, mountinfo, mountPoints string
		want                         []string
	}{
		{"link swapped back", rootfs + "503 500 8:1 / /h rw - ext4 /dev/vda1 rw\n", bind("/tmp/x", "/h"), []string{"the host's /, writable", unverified}},
		{"link in the image", rootfs + "503 500 8:1 / /x rw - ext4 /dev/vda1 rw\n", bind("/tmp/x", "/h"), []string{"the host's /, writable", unverified}},
		{"chrooted into the mount", "503 500 8:1 / / rw - ext4 /dev/vda1 rw\n", bind("/tmp/x", "/h"), []string{"the host's /, writable", unverified}},
		{"link in the image to a system directory", rootfs + "503 500 8:1 /etc/cron.d /x rw - ext4 /dev/vda1 rw\n", bind("/tmp/x", "/h"),
			[]string{"the host's /etc/cron.d, writable", unverified}},
		{"another container's state", rootfs + "503 500 8:16 /docker/containers/ffff00001111/config.v2.json /c rw - ext4 /dev/vdb1 rw\n", "",
			[]string{"the host's /var/lib/docker/containers/ffff00001111/config.v2.json, writable"}},
		{"another container's layer through an alias, moved by a link in the image", rootfs + "503 500 8:16 /docker/overlay2/ffff/diff /y rw - ext4 /dev/vdb1 rw\n",
			bind("/data/docker/overlay2/ffff/diff", "/h"), []string{"the host's /var/lib/docker/overlay2/ffff/diff, writable"}},
		{"the data disk holding the runtime's state", rootfs + "503 500 8:16 / /h rw - ext4 /dev/vdb1 rw\n", bind("/data", "/h"),
			[]string{"the host's /var/lib/docker, writable"}},
		{"chrooted into a tmpfs", "503 500 0:70 / / rw - tmpfs tmpfs rw\n", bind("/", "/h"), []string{"the host's /, writable", unverified}},
		{"file replaced since its mount", rootfs + "503 500 8:1 /etc/localtime//deleted /etc/localtime ro - ext4 /dev/vda1 rw\n", bind("/etc/localtime", "/etc/localtime"), nil},
		{"chrooted elsewhere", "", bind("/tmp/x", "/h"), []string{"mounts not verified by the kernel"}},
		{"data root behind a shorter alias", rootfs + "503 500 8:16 /docker /x rw - ext4 /dev/vdb1 rw\n", bind("/var/lib/docker", "/x"),
			[]string{"the host's /var/lib/docker, writable"}},
		{"system tree as the kernel sees it", rootfs + "503 500 8:1 /etc/cron.d /c rw - ext4 /dev/vda1 rw\n", bind("/srv/c", "/c"),
			[]string{"the host's /etc/cron.d, writable", unverified}},
		{"plain container", rootfs + "503 500 8:1 /srv/data /data rw - ext4 /dev/vda1 rw\n", bind("/srv/data", "/data"), nil},
		{"pod volume", rootfs + "503 500 8:1 /var/lib/kubelet/pods/7f3a/volumes/kubernetes.io~configmap/cfg /cfg ro - ext4 /dev/vda1 rw\n",
			bind("/var/lib/kubelet/pods/7f3a/volumes/kubernetes.io~configmap/cfg", "/cfg"), nil},
	} {
		if got := ContainerPowers(run(tt.mountinfo, tt.mountPoints)); !slices.Equal(got, tt.want) {
			t.Errorf("%s: powers = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// A volume of the local driver bound to another container's layer through an alias of the data
// root, moved by a link in the image, is judged as the bind it is.
func TestLocalBindVolumeMovedByALink(t *testing.T) {
	c := Container{ID: "a1b2c3d4e5f6", Running: true,
		Mounts: []Mount{{Source: "/data/docker/overlay2/ffff/diff", Destination: "/h", RW: true, Volume: "v"}},
		KernelMounts: []Mount{{Source: "/data/docker/overlay2/ffff/diff", Destination: "/y", RW: true, Undeclared: true},
			{Source: "/var/lib/docker/overlay2/ffff/diff", Destination: "/y", RW: true, Undeclared: true}}}
	if got := ContainerPowers(c); !slices.Equal(got, []string{"the host's /var/lib/docker/overlay2/ffff/diff, writable"}) {
		t.Errorf("powers = %q", got)
	}
}

// A host mount table too large to read is an issue, and the containers it leaves unverified say so.
func TestHostMountTableTooLarge(t *testing.T) {
	const id = "b1b2c3d4e5f6a1b2c3d4e5f6"
	var b strings.Builder
	for i := range maxMountEntries + 1 {
		fmt.Fprintf(&b, "%d 1 0:%d / /home/u/m%d rw - fuse.x x rw,user_id=1000\n", i+30, i+100, i)
	}
	fsys := fstest.MapFS{
		"proc/1/mountinfo": text(b.String()),
		"proc/9/mountinfo": text("501 500 8:1 / /h rw - ext4 /dev/vda1 rw\n"),
		"var/lib/docker/containers/" + id + "/config.v2.json": text(`{"ID": "` + id + `", "Name": "/s", "State": {"Running": true, "Pid": 9},
			"MountPoints": {"/h": {"Source": "/tmp/x", "Destination": "/h", "RW": true, "Type": "bind"}}}`),
	}
	res := collect[ContainersResult](t, Containers{}, collector.Source{FS: fsys})
	if got := ContainerPowers(res.Containers[0]); !slices.Equal(got, []string{"mounts not verified by the kernel"}) || len(res.Issues) != 1 {
		t.Errorf("powers = %q, issues = %q", got, res.Issues)
	}
}

// Harmless entries in front of a power do not push it out of the bounded lists, and a list cut
// at its bound is a power of its own.
func TestContainerListsKeepPowersFirst(t *testing.T) {
	const id = "f00df00df00df00df00df00d"
	dir := "var/lib/docker/containers/" + id + "/"
	var mounts, devices, caps []string
	for i := range maxContainerList {
		mounts = append(mounts, fmt.Sprintf(`"/a%02d": {"Source": "/srv/d%02d", "Destination": "/a%02d", "Type": "bind"}`, i, i, i))
		devices = append(devices, `{"PathOnHost": "/dev/null"}`)
		caps = append(caps, `"CHOWN"`)
	}
	mounts = append(mounts, `"/zz": {"Source": "/", "Destination": "/zz", "RW": true, "Type": "bind"}`)
	fsys := fstest.MapFS{
		dir + "config.v2.json":  text(`{"ID": "` + id + `", "Name": "/many", "MountPoints": {` + strings.Join(mounts, ",") + `}}`),
		dir + "hostconfig.json": text(`{"Devices": [` + strings.Join(devices, ",") + `, {"PathOnHost": "/dev/vda"}], "CapAdd": [` + strings.Join(caps, ",") + `, "SYS_ADMIN"]}`),
	}
	c := collect[ContainersResult](t, Containers{}, collector.Source{FS: fsys}).Containers[0]
	if len(c.Mounts) != maxContainerList || len(c.Devices) != maxContainerList || len(c.CapAdd) != maxContainerList {
		t.Fatalf("lists not bounded: %d %d %d", len(c.Mounts), len(c.Devices), len(c.CapAdd))
	}
	want := []string{"capability SYS_ADMIN", "the host's /, writable", "device /dev/vda", "more mounts than the sensor reads",
		"more devices than the sensor reads", "more cap_add than the sensor reads"}
	if got := ContainerPowers(c); !slices.Equal(got, want) {
		t.Errorf("powers = %q", got)
	}
}

// A service systemd sandboxes sees the host's root through a mount namespace of its own; a
// container sees another filesystem as "/".
func TestSameRootAsTheHost(t *testing.T) {
	fsys := fstest.MapFS{
		"proc/1/mountinfo": text("22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw\n23 22 0:21 / /proc rw - proc proc rw\n"),
		"proc/700/mountinfo": text("500 499 8:1 / / ro,relatime master:1 - ext4 /dev/vda1 rw\n501 500 0:21 / /proc rw - proc proc rw\n" +
			"502 500 8:1 /var/lib/private/x /var/lib/x rw - ext4 /dev/vda1 rw\n"),
		"proc/800/mountinfo": text("600 599 0:52 / / rw - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/A\n"),
		"proc/900/mountinfo": text("700 699 8:1 /srv/chroot / rw - ext4 /dev/vda1 rw\n"),
	}
	h := &rootOf{}
	for pid, want := range map[int]bool{700: true, 800: false, 900: false, 1000: false} {
		if got := h.sameAs(fsys, pid); got != want {
			t.Errorf("pid %d: %v, want %v", pid, got, want)
		}
	}
}

// A disk given by one of its links (an LVM volume, /dev/block/<major>:<minor>) is the disk the
// runtime resolved; SCSI generic devices and their cgroup rules reach the disks too.
func TestContainerDevicesThroughLinks(t *testing.T) {
	id := strings.Repeat("d", 64)
	dir := "var/lib/docker/containers/" + id + "/"
	fsys := fstest.MapFS{
		"dev/dm-0":              &fstest.MapFile{Mode: fs.ModeDevice},
		"dev/vg0/root":          &fstest.MapFile{Data: []byte("../dm-0"), Mode: fs.ModeSymlink},
		dir + "config.v2.json":  text(`{"ID": "` + id + `", "Name": "/lvm"}`),
		dir + "hostconfig.json": text(`{"Devices": [{"PathOnHost": "/dev/vg0/root"}, {"PathOnHost": "/dev/sg0"}], "DeviceCgroupRules": ["c 21:* rw"]}`),
	}
	c := collect[ContainersResult](t, Containers{}, collector.Source{FS: fsys}).Containers[0]
	want := []string{"device /dev/dm-0", "device /dev/sg0", "device rule c 21:* rw"}
	if got := ContainerPowers(c); !slices.Equal(got, want) {
		t.Errorf("powers = %q, want %q", got, want)
	}
}

// A local volume of type overlay is the host directories its options name: the root as a lower
// layer is read, the upper one is written.
func TestOverlayVolumeIsItsLayers(t *testing.T) {
	id := strings.Repeat("e", 64)
	dir := "var/lib/docker/containers/" + id + "/"
	fsys := fstest.MapFS{
		"var/lib/docker/volumes/v/opts.json": text(`{"MountType": "overlay", "MountOpts": "lowerdir=/:/etc,upperdir=/etc/cron.d,workdir=/tmp/w", "MountDevice": "overlay"}`),
		dir + "config.v2.json": text(`{"ID": "` + id + `", "Name": "/o", "MountPoints": {
			"/o": {"Source": "/var/lib/docker/volumes/v/_data", "Destination": "/o", "RW": true, "Name": "v", "Driver": "local", "Type": "volume"}}}`),
	}
	c := collect[ContainersResult](t, Containers{}, collector.Source{FS: fsys}).Containers[0]
	got := ContainerPowers(c)
	for _, want := range []string{"the host's volume v (/), read-only", "the host's volume v (/etc/cron.d), writable"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}

// Past the bound the containers whose configuration changed last are read: stopped ones
// created by the thousand cannot push out the privileged one started after them, and the cut
// is said.
func TestManyStoppedContainersDoNotHideAPrivilegedOne(t *testing.T) {
	fsys := fstest.MapFS{}
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range maxContainers {
		id := fmt.Sprintf("%064x", i)
		fsys["var/lib/docker/containers/"+id+"/config.v2.json"] = &fstest.MapFile{Data: []byte(`{"ID": "` + id + `", "Name": "/d"}`), ModTime: old}
	}
	id := strings.Repeat("f", 64)
	fsys["var/lib/docker/containers/"+id+"/config.v2.json"] = &fstest.MapFile{Data: []byte(`{"ID": "` + id + `", "Name": "/escape", "State": {"Running": true}}`), ModTime: old.Add(time.Hour)}
	fsys["var/lib/docker/containers/"+id+"/hostconfig.json"] = text(`{"Privileged": true}`)
	res := collect[ContainersResult](t, Containers{}, collector.Source{FS: fsys})
	if !res.Truncated || !slices.ContainsFunc(res.Containers, func(c Container) bool { return c.Name == "escape" && c.Privileged }) {
		t.Errorf("truncated %v, privileged container read %v", res.Truncated, slices.ContainsFunc(res.Containers, func(c Container) bool { return c.Name == "escape" }))
	}
}

// Docker keeps its containers elsewhere with userns-remap, as a snap, or with --data-root on
// its command line; k3s keeps its tasks under its own run directory. All are read.
func TestContainersInOtherDockerLayouts(t *testing.T) {
	cfg := func(id, name string) *fstest.MapFile {
		return text(`{"ID": "` + id + `", "Name": "/` + name + `"}`)
	}
	id := strings.Repeat("a", 64)
	for name, fsys := range map[string]fstest.MapFS{
		"userns-remap": {"var/lib/docker/100000.100000/containers/" + id + "/config.v2.json": cfg(id, "remapped")},
		"snap":         {"var/snap/docker/common/var-lib-docker/containers/" + id + "/config.v2.json": cfg(id, "snapped")},
		"command line": {
			"run/docker.pid":  text("42\n"),
			"proc/42/cmdline": text("/usr/bin/dockerd\x00--data-root\x00/data/docker\x00"),
			"data/docker/containers/" + id + "/config.v2.json": cfg(id, "moved"),
		},
		"k3s": {"run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/" + id + "/config.json": text(`{"hostname": "pod", "annotations": {"io.kubernetes.cri.container-name": "app"}}`)},
	} {
		if res := collect[ContainersResult](t, Containers{}, collector.Source{FS: fsys}); len(res.Containers) != 1 {
			t.Errorf("%s: %d containers", name, len(res.Containers))
		}
	}
}

// A runtime running whose state is nowhere it is read from is said; one with an empty state is
// a host without containers.
func TestRuntimeRunningWithoutState(t *testing.T) {
	running := func(extra fstest.MapFS) ContainersResult {
		fsys := fstest.MapFS{"proc/7/comm": text("containerd\n")}
		for k, v := range extra {
			fsys[k] = v
		}
		return collect[ContainersResult](t, Containers{}, collector.Source{FS: fsys})
	}
	if res := running(nil); !slices.ContainsFunc(res.Issues, func(i string) bool { return strings.HasPrefix(i, RuntimeUnread+"containerd") }) {
		t.Errorf("issues = %v", res.Issues)
	}
	if res := running(fstest.MapFS{"run/containerd/containerd.toml": text("")}); len(res.Issues) != 0 {
		t.Errorf("empty state: issues = %v", res.Issues)
	}
}
