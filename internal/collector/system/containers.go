package system

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

// Mount is a directory or file of the host a container sees.
type Mount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw,omitempty"`
	// Resolved is where Source leads on the host when it goes through symbolic links, read
	// when the containers are collected: a link to / mounts the host's root under any name.
	Resolved string `json:"resolved,omitempty"`
	// Volume names the Docker volume the mount comes from, when its local driver binds a host
	// path or device (Source is then that path, not the volume's own directory).
	Volume string `json:"volume,omitempty"`
	// Undeclared marks a mount of the kernel's table at a point the configuration does not
	// list: the runtime's own (the root filesystem, /etc/hosts), or one moved by a link in the
	// image or a chroot.
	Undeclared bool `json:"undeclared,omitempty"`
}

// Container is a Docker container as its daemon keeps it on disk. Only what gives it power over
// the host is collected: never its environment, which holds the application's secrets.
type Container struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	ImageID string `json:"image_id,omitempty"`
	Created string `json:"created,omitempty"`
	Running bool   `json:"running,omitempty"`
	// PID is the container's first process on the host, for those reading the container's own
	// filesystem through /proc; not part of the snapshot.
	PID        int    `json:"-"`
	User       string `json:"user,omitempty"`
	Privileged bool   `json:"privileged,omitempty"`
	// CapAdd are the capabilities added to Docker's default set, or for the other runtimes
	// the effective ones.
	CapAdd      []string `json:"cap_add,omitempty"`
	PIDMode     string   `json:"pid_mode,omitempty"`
	NetworkMode string   `json:"network_mode,omitempty"`
	IPCMode     string   `json:"ipc_mode,omitempty"`
	UsernsMode  string   `json:"userns_mode,omitempty"`
	SecurityOpt []string `json:"security_opt,omitempty"`
	Devices     []string `json:"devices,omitempty"`
	// DeviceRules are the device cgroup rules that allow access ("b *:* rwm"): with the
	// CAP_MKNOD containers have by default, an allowed node can be created and opened.
	DeviceRules []string `json:"device_rules,omitempty"`
	Mounts      []Mount  `json:"mounts,omitempty"`
	// Published maps the host ports the container publishes to its own ("8101" to "80"), for
	// telling which container a proxy on the host sends a site to; not part of the snapshot.
	Published map[string]string `json:"-"`
	// Volumes are the ordinary named volumes, in the daemon's own directory: no power over the
	// host, so not part of the snapshot, but where an application's files may live.
	Volumes []Mount `json:"-"`
	// KernelMounts are, for a running container, the host paths its process's mount table leads
	// to, one per mount of the same filesystem on the host. They add powers to those of Mounts,
	// whose text a link swapped around the start can fool, and never take any away.
	KernelMounts []Mount `json:"kernel_mounts,omitempty"`
	// KernelUnverified says why a running container's mount table could not be read.
	KernelUnverified string `json:"kernel_unverified,omitempty"`
	// Cut names the lists cut at their bound ("mounts", "devices", "cap_add", "security_opt"):
	// what gives power is kept first, and what was left out may give more.
	Cut []string `json:"cut,omitempty"`
}

type ContainersResult struct {
	// Runtime names where the containers were read from; empty when no runtime was found.
	Runtime    string           `json:"runtime,omitempty"`
	Containers []Container      `json:"containers"`
	Truncated  bool             `json:"truncated,omitempty"`
	Issues     collector.Issues `json:"issues,omitempty"`
}

// maxContainers bounds the containers read; maxContainerList the lists of one container.
const (
	maxContainers    = 1000
	maxContainerList = 64
)

// Containers reads the containers of the Docker daemon from its state directory, which is
// root's (its data root is read from daemon.json when it is moved), and those of containerd,
// Podman and CRI-O from their OCI bundles.
type Containers struct{}

func (Containers) Name() string { return "containers" }

func (Containers) Collect(ctx context.Context, src collector.Source) (any, error) {
	res := ContainersResult{Containers: []Container{}}
	refs, truncated := ContainerRefs(src.FS, &res.Issues)
	res.Truncated = truncated
	host := NewHostMounts(src.FS)
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		c, ok := ReadContainer(src.FS, ref, host, &res.Issues)
		if !ok {
			continue
		}
		res.Containers = append(res.Containers, c)
		if !slices.Contains(strings.Split(res.Runtime, ","), ref.Runtime) {
			res.Runtime = strings.TrimPrefix(res.Runtime+","+ref.Runtime, ",")
		}
	}
	if !strings.HasPrefix(res.Runtime, "docker") && dockerFound(src.FS) {
		res.Runtime = strings.TrimSuffix("docker,"+res.Runtime, ",")
	}
	// A runtime running whose state was found nowhere means its containers are not read: an
	// empty list must not pass for a host without containers.
	if res.Runtime == "" {
		if name := runningRuntime(src.FS); name != "" {
			res.Issues = append(res.Issues, RuntimeUnread+name)
		}
	}
	return res, nil
}

// RuntimeUnread starts the issue of a container runtime that runs while none of its state was
// found.
const RuntimeUnread = "container runtime running, its containers not found: "

// runtimeState is where each runtime daemon keeps the state of its containers.
var runtimeState = map[string][]string{
	"dockerd":    {"var/lib/docker", "var/snap/docker/common/var-lib-docker"},
	"containerd": {"run/containerd", "run/k3s/containerd", "var/snap/microk8s/common/run/containerd"},
	"crio":       {"run/containers/storage"},
	"k3s-server": {"run/k3s/containerd"},
	"k3s-agent":  {"run/k3s/containerd"},
}

// runningRuntime returns the name of a container runtime daemon running on the host whose state
// is in none of the places it is read from.
func runningRuntime(fsys fs.FS) string {
	entries, err := fs.ReadDir(fsys, "proc")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		comm, _ := fs.ReadFile(fsys, "proc/"+e.Name()+"/comm")
		name := strings.TrimSpace(string(comm))
		dirs, ok := runtimeState[name]
		if !ok {
			continue
		}
		if name == "dockerd" && dockerdDataRoot(fsys) != "" {
			continue
		}
		if !slices.ContainsFunc(dirs, func(d string) bool { _, err := fs.Stat(fsys, d); return err == nil }) {
			return name
		}
	}
	return ""
}

// ContainerRef is where a runtime keeps one container: Docker's directory of it, or the OCI
// bundle's config.json for the others.
type ContainerRef struct {
	Runtime string
	Path    string
}

// ContainerRefs lists the containers of every runtime found, up to the bound for each, without
// reading them: cheap enough to be done every second. Past the bound Docker's are taken by the
// last change of their configuration, which the daemon rewrites when it starts one, so stopped
// containers created by the thousand cannot push a running one out of the list.
func ContainerRefs(fsys fs.FS, issues *collector.Issues) (refs []ContainerRef, truncated bool) {
	// With userns-remap the daemon keeps its state in a <uid>.<gid> directory of the data root.
	root := dockerRoot(fsys, issues)
	remapped, _ := fs.Glob(fsys, path.Join(root, "*.*", "containers"))
	dirs := append([]string{path.Join(root, "containers")}, remapped...)
	var docker []ContainerRef
	for _, dir := range dirs {
		entries, _ := fs.ReadDir(fsys, dir)
		for _, e := range entries {
			if e.IsDir() {
				docker = append(docker, ContainerRef{Runtime: "docker", Path: path.Join(dir, e.Name())})
			}
		}
	}
	if len(docker) > maxContainers {
		truncated = true
		changed := make(map[string]int64, len(docker))
		for _, r := range docker {
			if info, err := fs.Stat(fsys, path.Join(r.Path, "config.v2.json")); err == nil {
				changed[r.Path] = info.ModTime().UnixNano()
			}
		}
		slices.SortStableFunc(docker, func(a, b ContainerRef) int { return cmp.Compare(changed[b.Path], changed[a.Path]) })
		docker = docker[:maxContainers]
	}
	refs = docker
	others := 0
	for _, b := range ociBundles {
		for _, name := range collector.Glob(fsys, b.glob) {
			if b.runtime == "containerd" && strings.Contains(name, "/io.containerd.runtime.v2.task/moby/") {
				continue
			}
			if others == maxContainers {
				return refs, true
			}
			others++
			refs = append(refs, ContainerRef{Runtime: b.runtime, Path: name})
		}
	}
	return refs, truncated
}

// ReadContainer reads one container; false when its configuration is not (yet) there or does
// not parse.
func ReadContainer(fsys fs.FS, ref ContainerRef, host *HostMounts, issues *collector.Issues) (Container, bool) {
	if ref.Runtime == "docker" {
		return readDockerContainer(fsys, ref.Path, host, issues)
	}
	data, err := fs.ReadFile(fsys, ref.Path)
	if err != nil {
		return Container{}, false
	}
	var cfg ociConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		issues.Add(err)
		return Container{}, false
	}
	c := ociContainer(fsys, ref.Runtime, ref.Path, cfg)
	// containerd's shim writes the task's PID next to its bundle once it has started.
	if ref.Runtime == "containerd" {
		if data, err := fs.ReadFile(fsys, path.Join(path.Dir(ref.Path), "init.pid")); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				c.PID = pid
				c.KernelMounts, c.KernelUnverified = kernelMounts(fsys, pid, host, c.Mounts, issues)
			}
		}
	}
	finishContainer(&c)
	return c, true
}

// ContainerStamp changes when a container's configuration is rewritten, as Docker does when it
// starts one: what was read at its creation may no longer be what it runs with.
func ContainerStamp(fsys fs.FS, ref ContainerRef) string {
	name := ref.Path
	switch ref.Runtime {
	case "docker":
		name = path.Join(ref.Path, "config.v2.json")
	case "containerd":
		name = path.Join(path.Dir(ref.Path), "init.pid")
	}
	info, err := fs.Stat(fsys, name)
	if err != nil {
		return ""
	}
	return strconv.FormatInt(info.ModTime().UnixNano(), 10) + ":" + strconv.FormatInt(info.Size(), 10)
}

// dockerFound says whether the daemon's state directory exists, though no container was read.
func dockerFound(fsys fs.FS) bool {
	var none collector.Issues
	_, err := fs.Stat(fsys, path.Join(dockerRoot(fsys, &none), "containers"))
	return err == nil
}

// dockerRoot is the daemon's data root, relative to the observed root.
func dockerRoot(fsys fs.FS, issues *collector.Issues) string {
	// Docker installed as a snap keeps its configuration and its state under the snap's
	// directories.
	root, config := "var/lib/docker", "etc/docker/daemon.json"
	if _, err := fs.Stat(fsys, "var/snap/docker/common/var-lib-docker"); err == nil {
		root, config = "var/snap/docker/common/var-lib-docker", "var/snap/docker/current/config/daemon.json"
	}
	if data, err := fs.ReadFile(fsys, config); err == nil {
		var cfg struct {
			DataRoot string `json:"data-root"`
			Graph    string `json:"graph"`
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			issues.Add(err)
		} else if p := cmp.Or(cfg.DataRoot, cfg.Graph); path.IsAbs(p) {
			return collector.Rel(p)
		}
	}
	// The data root can also be given on dockerd's command line, in its unit.
	if _, err := fs.Stat(fsys, path.Join(root, "containers")); err != nil {
		if p := dockerdDataRoot(fsys); p != "" {
			return p
		}
	}
	return root
}

// dockerdDataRoot reads --data-root (or the old -g/--graph) from the command line of the running
// dockerd, found through its pidfile: cheap enough for the watcher's every second.
func dockerdDataRoot(fsys fs.FS) string {
	pid, err := fs.ReadFile(fsys, "run/docker.pid")
	if err != nil {
		return ""
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(pid)))
	if err != nil || n <= 0 {
		return ""
	}
	cmdline, _ := fs.ReadFile(fsys, "proc/"+strconv.Itoa(n)+"/cmdline")
	args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	for i, a := range args {
		var v string
		switch {
		case strings.HasPrefix(a, "--data-root="), strings.HasPrefix(a, "--graph="):
			_, v, _ = strings.Cut(a, "=")
		case (a == "--data-root" || a == "--graph" || a == "-g") && i+1 < len(args):
			v = args[i+1]
		}
		if path.IsAbs(v) {
			return collector.Rel(v)
		}
	}
	return ""
}

// dockerConfig and dockerHostConfig hold the fields read from config.v2.json and hostconfig.json;
// the decoder skips the rest, the environment included.
type dockerConfig struct {
	ID      string
	Name    string
	Image   string
	Created string
	Config  struct {
		Image string
		User  string
	}
	State struct {
		Running bool
		Pid     int
	}
	MountPoints map[string]struct {
		Source      string
		Destination string
		RW          bool
		Type        string
		Name        string
		Driver      string
	}
}

type dockerHostConfig struct {
	Privileged        bool
	CapAdd            []string
	PidMode           string
	NetworkMode       string
	IpcMode           string
	UsernsMode        string
	SecurityOpt       []string
	Devices           []struct{ PathOnHost string }
	DeviceCgroupRules []string
	Binds             []string
	PortBindings      map[string][]struct{ HostIP, HostPort string }
}

func readDockerContainer(fsys fs.FS, dir string, host *HostMounts, issues *collector.Issues) (Container, bool) {
	data, err := fs.ReadFile(fsys, path.Join(dir, "config.v2.json"))
	if err != nil {
		return Container{}, false
	}
	var cfg dockerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		issues.Add(err)
		return Container{}, false
	}
	c := Container{ID: shortID(cfg.ID), Name: strings.TrimPrefix(cfg.Name, "/"), Image: cfg.Config.Image, ImageID: cfg.Image,
		Created: cfg.Created, Running: cfg.State.Running, User: cfg.Config.User}
	for _, m := range cfg.MountPoints {
		mount := Mount{Source: m.Source, Destination: m.Destination, RW: m.RW}
		if m.Type == "volume" {
			// Named volumes live in the daemon's own directory, unless the local driver was told
			// to bind a host path or mount a device there instead.
			device, ok := volumeDevice(fsys, path.Dir(path.Dir(dir)), m.Name, m.Driver, issues)
			if layers := volumeOverlay(fsys, path.Dir(path.Dir(dir)), m.Name, m.Driver); !ok && len(layers) > 0 {
				for _, l := range layers {
					c.Mounts = append(c.Mounts, resolveMount(fsys, Mount{Source: l.Source, Destination: m.Destination, RW: l.RW && m.RW, Volume: m.Name}))
				}
				continue
			}
			if !ok {
				if path.IsAbs(m.Source) && len(c.Volumes) < maxContainerList {
					c.Volumes = append(c.Volumes, Mount{Source: m.Source, Destination: m.Destination, RW: m.RW, Volume: m.Name})
				}
				continue
			}
			mount.Source, mount.Volume = device, m.Name
		} else if m.Type != "" && m.Type != "bind" || m.Source == "" {
			continue
		}
		c.Mounts = append(c.Mounts, resolveMount(fsys, mount))
	}
	if cfg.State.Running {
		c.PID = cfg.State.Pid
		c.KernelMounts, c.KernelUnverified = kernelMounts(fsys, cfg.State.Pid, host, c.Mounts, issues)
	}
	if data, err := fs.ReadFile(fsys, path.Join(dir, "hostconfig.json")); err == nil {
		var hc dockerHostConfig
		if err := json.Unmarshal(data, &hc); err != nil {
			issues.Add(err)
		} else {
			c.Privileged, c.PIDMode, c.NetworkMode, c.IPCMode, c.UsernsMode = hc.Privileged, hc.PidMode, hc.NetworkMode, hc.IpcMode, hc.UsernsMode
			c.CapAdd, c.SecurityOpt = hc.CapAdd, hc.SecurityOpt
			for _, d := range hc.Devices {
				c.Devices = append(c.Devices, hostDevice(fsys, d.PathOnHost))
			}
			c.DeviceRules = deviceRules(hc.DeviceCgroupRules)
			for port, bindings := range hc.PortBindings {
				for _, b := range bindings {
					if len(c.Published) < maxContainerList && b.HostPort != "" {
						if c.Published == nil {
							c.Published = map[string]string{}
						}
						c.Published[b.HostPort], _, _ = strings.Cut(port, "/")
					}
				}
			}
		}
	}
	finishContainer(&c)
	return c, true
}

// finishContainer orders the container's lists and cuts them at their bound. What gives power
// goes first, so that harmless entries put in front of it cannot push it out, and a cut list
// is named: it counts as a power of its own.
func finishContainer(c *Container) {
	slices.SortFunc(c.Mounts, func(a, b Mount) int {
		return cmp.Or(rank(mountPower(b) != "")-rank(mountPower(a) != ""), strings.Compare(a.Destination, b.Destination))
	})
	c.Mounts = clipNamed(c, "mounts", c.Mounts)
	slices.SortFunc(c.KernelMounts, func(a, b Mount) int {
		return cmp.Or(rank(kernelMountPower(b) != "")-rank(kernelMountPower(a) != ""), strings.Compare(a.Destination, b.Destination),
			strings.Compare(a.Source, b.Source))
	})
	c.KernelMounts = clipNamed(c, "kernel_mounts", c.KernelMounts)
	c.Devices = clipNamed(c, "devices", powerFirst(c.Devices, isRawDisk))
	c.CapAdd = clipNamed(c, "cap_add", powerFirst(c.CapAdd, isAdminCap))
	c.SecurityOpt = clipNamed(c, "security_opt", powerFirst(c.SecurityOpt, isUnconfined))
}

func powerFirst(l []string, power func(string) bool) []string {
	l = slices.Clone(l)
	slices.SortStableFunc(l, func(a, b string) int { return rank(power(b)) - rank(power(a)) })
	return l
}

func rank(b bool) int {
	if b {
		return 1
	}
	return 0
}

func clipNamed[T any](c *Container, name string, l []T) []T {
	if len(l) <= maxContainerList {
		return l
	}
	c.Cut = append(c.Cut, name)
	return l[:maxContainerList]
}

// volumeDevice is the host path or device a local Docker volume is mounted from, from the
// options its driver keeps in opts.json; false for an ordinary volume or another driver.
func volumeDevice(fsys fs.FS, dockerRoot, name, driver string, issues *collector.Issues) (string, bool) {
	if driver != "local" || name == "" || name != path.Base(name) || name == ".." {
		return "", false
	}
	data, err := fs.ReadFile(fsys, path.Join(dockerRoot, "volumes", name, "opts.json"))
	if err != nil {
		return "", false
	}
	var opts struct{ MountType, MountOpts, MountDevice string }
	if err := json.Unmarshal(data, &opts); err != nil {
		issues.Add(err)
		return "", false
	}
	// Network filesystems name a remote ("host:/export"), never a path of this host.
	if !path.IsAbs(opts.MountDevice) {
		return "", false
	}
	return opts.MountDevice, true
}

// volumeOverlay is what a local Docker volume of type overlay is made of: the host directories
// its options name, the upper one written to. Its device is the word "overlay", not a path.
func volumeOverlay(fsys fs.FS, dockerRoot, name, driver string) []Mount {
	if driver != "local" || name == "" || name != path.Base(name) || name == ".." {
		return nil
	}
	data, err := fs.ReadFile(fsys, path.Join(dockerRoot, "volumes", name, "opts.json"))
	if err != nil {
		return nil
	}
	var opts struct{ MountType, MountOpts string }
	if json.Unmarshal(data, &opts) != nil || opts.MountType != "overlay" {
		return nil
	}
	var out []Mount
	for _, opt := range strings.Split(opts.MountOpts, ",") {
		key, value, _ := strings.Cut(opt, "=")
		switch key {
		case "lowerdir":
			for _, dir := range strings.Split(value, ":") {
				if path.IsAbs(dir) && len(out) < maxContainerList {
					out = append(out, Mount{Source: dir})
				}
			}
		case "upperdir", "workdir":
			if path.IsAbs(value) && len(out) < maxContainerList {
				out = append(out, Mount{Source: value, RW: true})
			}
		}
	}
	return out
}

// resolveMount records where a mount's source leads when it goes through links. The link can
// be removed once the container runs; the bind stays, so this is only seen while it exists.
func resolveMount(fsys fs.FS, m Mount) Mount {
	if !path.IsAbs(m.Source) {
		return m
	}
	resolved, err := collector.ResolvePath(fsys, collector.Rel(m.Source))
	if err != nil {
		return m
	}
	if resolved = path.Clean("/" + strings.TrimPrefix(resolved, ".")); resolved != path.Clean(m.Source) {
		m.Resolved = resolved
	}
	return m
}

// deviceRules keeps the cgroup rules that grant reading or writing. Past the bound a marker
// stands for the rest, so that rules hidden behind many harmless ones still count.
func deviceRules(rules []string) []string {
	var out []string
	for _, r := range rules {
		f := strings.Fields(r)
		if len(f) != 3 || !strings.ContainsAny(f[2], "rw") {
			continue
		}
		if len(out) == maxContainerList {
			return append(out, DeviceRulesTruncated)
		}
		out = append(out, strings.Join(f, " "))
	}
	return out
}

// DeviceRulesTruncated ends a device rule list cut at its bound.
const DeviceRulesTruncated = "..."

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// ociBundles are where runtimes keep the OCI configuration of their containers: containerd's
// running tasks (one directory per namespace, Kubernetes' included; Docker's own namespace is
// read from the daemon instead), and the containers of Podman and CRI-O.
var ociBundles = []struct{ runtime, glob string }{
	{"containerd", "run/containerd/io.containerd.runtime.v2.task/*/*/config.json"},
	{"containerd", "run/k3s/containerd/io.containerd.runtime.v2.task/*/*/config.json"},
	{"containerd", "var/snap/microk8s/common/run/containerd/io.containerd.runtime.v2.task/*/*/config.json"},
	{"podman", "var/lib/containers/storage/overlay-containers/*/userdata/config.json"},
	{"cri-o", "run/containers/storage/overlay-containers/*/userdata/config.json"},
}

// ociConfig holds the fields read from an OCI runtime configuration; the process's environment
// is skipped by the decoder.
type ociConfig struct {
	Hostname string
	Process  struct {
		User         struct{ UID int }
		Capabilities struct{ Effective []string }
	}
	Mounts []struct {
		Destination string
		Type        string
		Source      string
		Options     []string
	}
	Linux struct {
		Namespaces []struct{ Type string }
		Devices    []struct{ Path string }
		Resources  struct {
			Devices []struct {
				Allow  bool
				Type   string
				Major  *int64
				Minor  *int64
				Access string
			}
		}
	}
	Annotations map[string]string
}

// allCapabilities is how many capabilities a privileged container holds at least.
const allCapabilities = 38

func ociContainer(fsys fs.FS, runtime, name string, cfg ociConfig) Container {
	// The bundle's directory is the container's ID: .../<id>/config.json or .../<id>/userdata/config.json.
	dir := path.Dir(name)
	if path.Base(dir) == "userdata" {
		dir = path.Dir(dir)
	}
	a := cfg.Annotations
	c := Container{ID: shortID(path.Base(dir)), Running: runtime != "podman",
		Name:  cmp.Or(a["io.kubernetes.cri.container-name"], a["io.kubernetes.container.name"], a["io.container.name"], cfg.Hostname),
		Image: cmp.Or(a["io.kubernetes.cri.image-name"], a["io.kubernetes.container.image"], a["org.opencontainers.image.ref.name"], a["io.podman.annotations.image"]),
		User:  fmt.Sprint(cfg.Process.User.UID)}
	if pod := cmp.Or(a["io.kubernetes.cri.sandbox-name"], a["io.kubernetes.pod.name"]); pod != "" {
		c.Name = cmp.Or(a["io.kubernetes.cri.sandbox-namespace"], a["io.kubernetes.pod.namespace"]) + "/" + pod + "/" + c.Name
	}
	c.Name = runtime + ":" + c.Name
	caps := cfg.Process.Capabilities.Effective
	c.Privileged = len(caps) >= allCapabilities
	if !c.Privileged {
		c.CapAdd = caps
	}
	isolated := map[string]bool{}
	for _, ns := range cfg.Linux.Namespaces {
		isolated[ns.Type] = true
	}
	// A namespace missing from the list is the host's.
	for kind, mode := range map[string]*string{"pid": &c.PIDMode, "network": &c.NetworkMode, "ipc": &c.IPCMode, "user": &c.UsernsMode} {
		if !isolated[kind] {
			*mode = "host"
		}
	}
	if !isolated["user"] && !c.Privileged {
		// Without a user namespace is the norm: only privileged mode makes it the host's root.
		c.UsernsMode = ""
	}
	for _, m := range cfg.Mounts {
		if m.Type != "bind" && !slices.Contains(m.Options, "bind") && !slices.Contains(m.Options, "rbind") {
			continue
		}
		c.Mounts = append(c.Mounts, resolveMount(fsys, Mount{Source: m.Source, Destination: m.Destination, RW: !slices.Contains(m.Options, "ro")}))
	}
	for _, d := range cfg.Linux.Devices {
		c.Devices = append(c.Devices, hostDevice(fsys, d.Path))
	}
	var rules []string
	for _, d := range cfg.Linux.Resources.Devices {
		if d.Allow {
			rules = append(rules, cmp.Or(d.Type, "a")+" "+deviceNumber(d.Major)+":"+deviceNumber(d.Minor)+" "+d.Access)
		}
	}
	c.DeviceRules = deviceRules(rules)
	return c
}

func deviceNumber(n *int64) string {
	if n == nil || *n < 0 {
		return "*"
	}
	return fmt.Sprint(*n)
}

// runtimeSockets are the sockets of container runtimes, where they usually are: a container that
// holds one, or a directory above it, can start a privileged container of its own. Daemons can
// listen elsewhere, so a socket with one of these names counts wherever it is.
var runtimeSockets = []string{
	"/run/docker.sock", "/var/run/docker.sock", "/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock",
	"/run/crio/crio.sock", "/var/run/crio/crio.sock", "/run/podman/podman.sock", "/var/run/podman/podman.sock",
	"/run/k3s/containerd/containerd.sock", "/run/dockershim.sock", "/var/run/dockershim.sock",
	"/var/snap/docker/common/run/docker.sock", "/var/snap/microk8s/common/run/containerd.sock",
}

// rootSockets are the sockets of other daemons that do as root what whoever talks to them asks:
// systemd starts a unit (directly or through the system bus), snapd installs, libvirt and LXD
// start machines, BuildKit runs builds. Root in the container reaches them as root.
var rootSockets = []string{
	"/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket", "/run/systemd/private", "/run/snapd.socket",
	"/run/libvirt/libvirt-sock", "/var/run/libvirt/libvirt-sock", "/var/snap/lxd/common/lxd/unix.socket", "/var/lib/lxd/unix.socket",
	"/run/buildkit/buildkitd.sock",
}

// hostTrees are the host directories that give a container the host as a whole: its root, its
// configuration, root's home, the kernel's interfaces and the runtimes' state.
var hostTrees = []string{"/", "/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/var", "/var/lib", "/var/lib/docker", "/var/lib/containerd",
	"/var/lib/containers", "/var/lib/kubelet", "/var/run", "/run", "/usr", "/lib", "/lib64", "/bin", "/sbin", "/home", "/var/spool", "/var/spool/cron"}

// systemTrees are those where any directory or file below is the host's too when writable: a
// cron.d, a unit directory, a library, root's keys, a cgroup's release_agent.
var systemTrees = []string{"/etc", "/root", "/boot", "/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc", "/sys", "/run/systemd",
	"/var/lib/docker", "/var/lib/containerd", "/var/lib/containers", "/var/lib/kubelet", "/var/spool/cron"}

// secretTrees are those where reading is enough: password hashes, private keys, the cluster's
// and the runtimes' credentials, and through /proc/<pid>/root the whole host.
var secretTrees = []string{"/root", "/etc/shadow", "/etc/gshadow", "/etc/ssh", "/etc/sudoers", "/etc/sudoers.d", "/etc/kubernetes",
	"/etc/docker", "/proc", "/var/lib/docker", "/var/lib/containerd", "/var/lib/containers", "/var/lib/kubelet", "/var/spool/cron"}

// harmlessFiles are host files commonly shared writable with containers that give no power
// over the host, the time zone files /etc/localtime links to, and the journal's sockets
// containers log to.
var harmlessFiles = []string{"/etc/localtime", "/etc/timezone", "/etc/hostname", "/etc/hosts", "/etc/resolv.conf", "/etc/machine-id", "/etc/os-release", "/usr/share/zoneinfo",
	"/run/systemd/journal"}

// rawDisks are the device names of disks and memory: raw access to them bypasses every
// permission of the filesystems on top.
var rawDisks = []string{"/dev/sd", "/dev/hd", "/dev/vd", "/dev/xvd", "/dev/nvme", "/dev/dm-", "/dev/mapper/", "/dev/loop", "/dev/md",
	"/dev/mmcblk", "/dev/disk/", "/dev/nbd", "/dev/rbd", "/dev/zd", "/dev/mem", "/dev/kmem", "/dev/port", "/dev/sg", "/dev/ng", "/dev/bsg/"}

// adminCaps are the capabilities that let a container's root act as the host's.
var adminCaps = []string{"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH", "SYS_BOOT", "BPF", "PERFMON"}

// ContainerPowers lists what lets a container reach the host. A runtime's socket, the host's
// root, privileged mode or the host's process namespace each amount to root on the host.
func ContainerPowers(c Container) []string {
	var out []string
	if c.Privileged {
		out = append(out, "privileged")
	}
	for _, cp := range c.CapAdd {
		if isAdminCap(cp) {
			out = append(out, "capability "+cp)
		}
	}
	if c.PIDMode == "host" {
		out = append(out, "the host's processes")
	}
	if c.UsernsMode == "host" && c.Privileged {
		out = append(out, "the host's users")
	}
	for _, opt := range c.SecurityOpt {
		if isUnconfined(opt) {
			out = append(out, "security "+opt)
		}
	}
	for _, m := range c.Mounts {
		if p := mountPower(m); p != "" {
			out = append(out, p)
		}
	}
	for _, m := range c.KernelMounts {
		if p := kernelMountPower(m); p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	if c.KernelUnverified != "" {
		out = append(out, "mounts not verified by the kernel")
	}
	for _, d := range c.Devices {
		if isRawDisk(d) {
			out = append(out, "device "+d)
		}
	}
	for _, r := range c.DeviceRules {
		if deviceRuleGrantsHost(r) {
			out = append(out, "device rule "+r)
		}
	}
	for _, name := range c.Cut {
		out = append(out, "more "+name+" than the sensor reads")
	}
	return out
}

func isAdminCap(cp string) bool {
	return slices.Contains(adminCaps, strings.TrimPrefix(strings.ToUpper(cp), "CAP_"))
}

func isUnconfined(opt string) bool {
	return strings.HasSuffix(opt, "=unconfined") || strings.HasSuffix(opt, ":unconfined")
}

// mountPower describes the power a mount gives, judged on where it leads when that is known.
func mountPower(m Mount) string {
	src := path.Clean("/" + cmp.Or(m.Resolved, m.Source))
	name := src
	if m.Resolved != "" {
		name = path.Clean("/"+m.Source) + " (" + src + ")"
	}
	if m.Volume != "" {
		name = "volume " + m.Volume + " (" + src + ")"
	}
	mode := "read-only"
	if m.RW {
		mode = "writable"
	}
	switch {
	case src == "/" || slices.Contains(hostTrees, src) && !holdsSocket(src):
		return fmt.Sprintf("the host's %s, %s", name, mode)
	case holdsSocket(src) || slices.Contains([]string{"docker.sock", "containerd.sock", "crio.sock", "podman.sock", "dockershim.sock"}, path.Base(src)):
		return "the runtime socket " + name
	case slices.ContainsFunc(rootSockets, func(r string) bool { return r == src || strings.HasPrefix(r, src+"/") }) &&
		!slices.Contains([]string{"/", "/var", "/var/lib", "/var/snap"}, src) || slices.Contains([]string{"system_bus_socket", "buildkitd.sock", "libvirt-sock"}, path.Base(src)):
		return "the root socket " + name
	case isRawDisk(src):
		return fmt.Sprintf("the host's disk %s, %s", name, mode)
	case under(src, harmlessFiles) || slices.Contains(harmlessFiles, path.Clean("/"+m.Source)) || podOwned(src):
		return ""
	case under(src, secretTrees) || m.RW && under(src, systemTrees):
		return fmt.Sprintf("the host's %s, %s", name, mode)
	}
	return ""
}

// kernelMountPower is the power of a mount read from the kernel. One the configuration does not
// list counts only when it is a whole tree of the host or a socket: the runtime's own mounts
// (the root filesystem's layers, the container's hosts file) lie deep in its state directory.
func kernelMountPower(m Mount) string {
	p := mountPower(m)
	src := path.Clean("/" + m.Source)
	if m.Undeclared && src != "/" && !slices.Contains(hostTrees, src) && !strings.HasPrefix(p, "the runtime socket") {
		return ""
	}
	return p
}

// podRuntimeDirs hold one directory per pod or sandbox whose files the runtime mounts into it:
// its volumes, its hosts and resolv.conf.
var podRuntimeDirs = []string{"/var/lib/kubelet/pods/", "/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/",
	"/run/containerd/io.containerd.grpc.v1.cri/sandboxes/"}

func podOwned(p string) bool {
	return slices.ContainsFunc(podRuntimeDirs, func(dir string) bool {
		rest, ok := strings.CutPrefix(p, dir)
		return ok && strings.Contains(rest, "/")
	})
}

// holdsSocket says whether dir is a runtime's socket or a directory above one, short of the
// trees that are reported as the host's own.
func holdsSocket(dir string) bool {
	return slices.ContainsFunc(runtimeSockets, func(s string) bool { return s == dir || strings.HasPrefix(s, dir+"/") }) &&
		!slices.Contains([]string{"/", "/var", "/var/lib", "/var/snap"}, dir)
}

func under(p string, trees []string) bool {
	return slices.ContainsFunc(trees, func(t string) bool { return p == t || strings.HasPrefix(p, t+"/") })
}

// hostDevice is the device a container was given, through the links the runtime resolved when
// it created it (/dev/<vg>/<lv> -> /dev/dm-0, /dev/block/8:0 -> /dev/sda): the configuration
// keeps the name it was given.
func hostDevice(fsys fs.FS, d string) string {
	resolved, err := collector.ResolvePath(fsys, collector.Rel(d))
	if err != nil || !strings.HasPrefix(resolved, "dev/") || "/"+resolved == path.Clean(d) {
		return d
	}
	return "/" + resolved
}

func isRawDisk(d string) bool {
	return slices.ContainsFunc(rawDisks, func(prefix string) bool { return strings.HasPrefix(d, prefix) })
}

// deviceRuleGrantsHost says whether a cgroup rule ("type major:minor access") lets the container
// read or write a disk or the host's memory: any block device, or the memory character devices
// (major 1: mem, kmem, port; the others of major 1 are /dev/null, zero and the random sources),
// or the SCSI generic devices (major 21), which pass commands to the disks behind them.
func deviceRuleGrantsHost(rule string) bool {
	if rule == DeviceRulesTruncated {
		return true
	}
	f := strings.Fields(rule)
	if len(f) != 3 || !strings.ContainsAny(f[2], "rw") {
		return false
	}
	major, minor, _ := strings.Cut(f[1], ":")
	switch f[0] {
	case "a", "b":
		return true
	case "c":
		return major == "*" || major == "21" || major == "1" && slices.Contains([]string{"*", "1", "2", "4"}, minor)
	}
	return false
}

// maxMountEntries bounds the mount table entries parsed from one mountinfo file.
const maxMountEntries = 16384

type mountEntry struct {
	dev, root, point, fstype string
	rw                       bool
}

// HostMounts is the host's mount table, read once when first needed, to tell which host
// directories a running container's mounts really are.
type HostMounts struct {
	fsys     fs.FS
	read     bool
	entries  []mountEntry
	err      error
	reported bool
}

func NewHostMounts(fsys fs.FS) *HostMounts { return &HostMounts{fsys: fsys} }

func readMountEntries(fsys fs.FS, name string) ([]mountEntry, error) {
	lines, err := collector.ReadLines(fsys, name)
	if err != nil {
		return nil, err
	}
	var out []mountEntry
	for _, line := range lines {
		left, right, ok := strings.Cut(line, " - ")
		fields, tail := strings.Fields(left), strings.Fields(right)
		if !ok || len(fields) < 6 || len(tail) < 1 {
			continue
		}
		if len(out) == maxMountEntries {
			return out, fmt.Errorf("%s: more than %d mounts", name, maxMountEntries)
		}
		out = append(out, mountEntry{dev: fields[2], root: collector.UnescapeMount(fields[3]), point: collector.UnescapeMount(fields[4]), fstype: tail[0],
			rw: slices.Contains(strings.Split(fields[5], ","), "rw")})
	}
	return out, nil
}

// hostPaths are the paths where the part root of the filesystem dev appears on the host, one
// per host mount of it that contains that part.
func (h *HostMounts) hostPaths(dev, root string) []string {
	var out []string
	for _, e := range h.entries {
		if e.dev != dev {
			continue
		}
		rest, ok := strings.CutPrefix(root, e.root)
		if !ok || e.root != "/" && rest != "" && !strings.HasPrefix(rest, "/") {
			continue
		}
		if p := path.Join("/", e.point, rest); !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// pseudoFilesystems are the kernel's own; a container gets an instance of its own, or the
// host's read-only (sysfs with the host's network), at points the runtime chooses.
var pseudoFilesystems = []string{"proc", "sysfs", "cgroup", "cgroup2", "mqueue", "devpts"}

// kernelMounts reads the mount table of a running container's process and returns the host
// paths each of its mounts leads to: unlike the source written in its configuration, a link
// swapped before the start and put back after cannot change them. Every entry counts, not
// only those at the declared destinations: a link in the image moves a mount elsewhere, and a
// process chrooted into one sees it as "/". The reason is returned when the table cannot be
// read, as when the process chroots outside its mounts, which empties it.
func kernelMounts(fsys fs.FS, pid int, host *HostMounts, declared []Mount, issues *collector.Issues) ([]Mount, string) {
	if pid <= 0 || host == nil {
		return nil, ""
	}
	proc := "proc/" + strconv.Itoa(pid)
	if _, err := fs.Stat(fsys, proc); errors.Is(err, fs.ErrNotExist) {
		// The container stopped since its state was written.
		return nil, ""
	}
	entries, err := readMountEntries(fsys, proc+"/mountinfo")
	switch {
	case err != nil:
		return nil, "its mount table could not be read: " + err.Error()
	case len(entries) == 0:
		return nil, "its mount table is empty"
	}
	if !host.read {
		host.entries, host.err = readMountEntries(host.fsys, "proc/1/mountinfo")
		host.read = true
	}
	if host.err != nil {
		if !host.reported {
			issues.Add(fmt.Errorf("the host's mount table was not read whole, containers' mounts are not verified: %w", host.err))
			host.reported = true
		}
		return nil, "the host's mount table could not be read"
	}
	points := map[string]bool{}
	for _, m := range declared {
		points[path.Clean("/"+m.Destination)] = true
	}
	var out []Mount
	for _, e := range entries {
		if slices.Contains(pseudoFilesystems, e.fstype) && !points[e.point] {
			continue
		}
		for _, p := range host.hostPaths(e.dev, e.root) {
			m := Mount{Source: p, Destination: e.point, RW: e.rw, Undeclared: !points[e.point]}
			if !slices.Contains(out, m) {
				out = append(out, m)
			}
		}
	}
	return out, ""
}
