package system

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

// Mount is a directory or file of the host a container sees.
type Mount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw,omitempty"`
}

// Container is a Docker container as its daemon keeps it on disk. Only what gives it power over
// the host is collected: never its environment, which holds the application's secrets.
type Container struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Image      string `json:"image"`
	ImageID    string `json:"image_id,omitempty"`
	Created    string `json:"created,omitempty"`
	Running    bool   `json:"running,omitempty"`
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
	Mounts      []Mount  `json:"mounts,omitempty"`
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
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		c, ok := ReadContainer(src.FS, ref, &res.Issues)
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
	return res, nil
}

// ContainerRef is where a runtime keeps one container: Docker's directory of it, or the OCI
// bundle's config.json for the others.
type ContainerRef struct {
	Runtime string
	Path    string
}

// ContainerRefs lists the containers of every runtime found, up to the bound, without reading
// them: cheap enough to be done every second.
func ContainerRefs(fsys fs.FS, issues *collector.Issues) (refs []ContainerRef, truncated bool) {
	dir := path.Join(dockerRoot(fsys, issues), "containers")
	entries, _ := fs.ReadDir(fsys, dir)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if len(refs) == maxContainers {
			return refs, true
		}
		refs = append(refs, ContainerRef{Runtime: "docker", Path: path.Join(dir, e.Name())})
	}
	for _, b := range ociBundles {
		for _, name := range collector.Glob(fsys, b.glob) {
			if b.runtime == "containerd" && strings.Contains(name, "/io.containerd.runtime.v2.task/moby/") {
				continue
			}
			if len(refs) == maxContainers {
				return refs, true
			}
			refs = append(refs, ContainerRef{Runtime: b.runtime, Path: name})
		}
	}
	return refs, false
}

// ReadContainer reads one container; false when its configuration is not (yet) there or does
// not parse.
func ReadContainer(fsys fs.FS, ref ContainerRef, issues *collector.Issues) (Container, bool) {
	if ref.Runtime == "docker" {
		return readDockerContainer(fsys, ref.Path, issues)
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
	return ociContainer(ref.Runtime, ref.Path, cfg), true
}

// dockerFound says whether the daemon's state directory exists, though no container was read.
func dockerFound(fsys fs.FS) bool {
	var none collector.Issues
	_, err := fs.Stat(fsys, path.Join(dockerRoot(fsys, &none), "containers"))
	return err == nil
}

// dockerRoot is the daemon's data root, relative to the observed root.
func dockerRoot(fsys fs.FS, issues *collector.Issues) string {
	root := "var/lib/docker"
	data, err := fs.ReadFile(fsys, "etc/docker/daemon.json")
	if err != nil {
		return root
	}
	var cfg struct {
		DataRoot string `json:"data-root"`
		Graph    string `json:"graph"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		issues.Add(err)
		return root
	}
	if p := cmp.Or(cfg.DataRoot, cfg.Graph); path.IsAbs(p) {
		return collector.Rel(p)
	}
	return root
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
	}
	MountPoints map[string]struct {
		Source      string
		Destination string
		RW          bool
		Type        string
	}
}

type dockerHostConfig struct {
	Privileged  bool
	CapAdd      []string
	PidMode     string
	NetworkMode string
	IpcMode     string
	UsernsMode  string
	SecurityOpt []string
	Devices     []struct{ PathOnHost string }
	Binds       []string
}

func readDockerContainer(fsys fs.FS, dir string, issues *collector.Issues) (Container, bool) {
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
		// Named volumes live in the daemon's own directory; what matters is the host's tree.
		if m.Type != "" && m.Type != "bind" || m.Source == "" {
			continue
		}
		c.Mounts = append(c.Mounts, Mount{Source: m.Source, Destination: m.Destination, RW: m.RW})
	}
	if data, err := fs.ReadFile(fsys, path.Join(dir, "hostconfig.json")); err == nil {
		var hc dockerHostConfig
		if err := json.Unmarshal(data, &hc); err != nil {
			issues.Add(err)
		} else {
			c.Privileged, c.PIDMode, c.NetworkMode, c.IPCMode, c.UsernsMode = hc.Privileged, hc.PidMode, hc.NetworkMode, hc.IpcMode, hc.UsernsMode
			c.CapAdd, c.SecurityOpt = clipList(hc.CapAdd), clipList(hc.SecurityOpt)
			for _, d := range hc.Devices {
				c.Devices = append(c.Devices, d.PathOnHost)
			}
			c.Devices = clipList(c.Devices)
		}
	}
	slices.SortFunc(c.Mounts, func(a, b Mount) int { return strings.Compare(a.Destination, b.Destination) })
	c.Mounts = c.Mounts[:min(len(c.Mounts), maxContainerList)]
	return c, true
}

func clipList(l []string) []string {
	if len(l) > maxContainerList {
		l = l[:maxContainerList]
	}
	return l
}

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
	}
	Annotations map[string]string
}

// allCapabilities is how many capabilities a privileged container holds at least.
const allCapabilities = 38

func ociContainer(runtime, name string, cfg ociConfig) Container {
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
		c.CapAdd = clipList(caps)
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
		c.Mounts = append(c.Mounts, Mount{Source: m.Source, Destination: m.Destination, RW: !slices.Contains(m.Options, "ro")})
	}
	slices.SortFunc(c.Mounts, func(a, b Mount) int { return strings.Compare(a.Destination, b.Destination) })
	c.Mounts = c.Mounts[:min(len(c.Mounts), maxContainerList)]
	for _, d := range cfg.Linux.Devices {
		c.Devices = append(c.Devices, d.Path)
	}
	c.Devices = clipList(c.Devices)
	return c
}

// hostSockets are the sockets of container runtimes: a container that holds one can start a
// privileged container of its own.
var hostSockets = []string{"/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/var/run/crio/crio.sock", "/run/podman/podman.sock"}

// hostTrees are the host directories that give a container the host: its root, its
// configuration, root's home, the kernel's interfaces and the runtimes' state.
var hostTrees = []string{"/", "/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/var/lib/docker", "/var/lib/containerd", "/var/run", "/run", "/usr", "/lib", "/bin", "/sbin", "/home", "/var/spool/cron"}

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
		if slices.Contains(adminCaps, strings.TrimPrefix(strings.ToUpper(cp), "CAP_")) {
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
		if strings.HasSuffix(opt, "=unconfined") || strings.HasSuffix(opt, ":unconfined") {
			out = append(out, "security "+opt)
		}
	}
	for _, m := range c.Mounts {
		src := strings.TrimSuffix(m.Source, "/")
		switch {
		case slices.Contains(hostSockets, m.Source):
			out = append(out, "the runtime socket "+m.Source)
		case src == "" || slices.Contains(hostTrees, src):
			mode := "read-only"
			if m.RW {
				mode = "writable"
			}
			out = append(out, fmt.Sprintf("the host's %s, %s", cmpOrRoot(src), mode))
		}
	}
	for _, d := range c.Devices {
		if strings.HasPrefix(d, "/dev/sd") || strings.HasPrefix(d, "/dev/nvme") || strings.HasPrefix(d, "/dev/mem") || strings.HasPrefix(d, "/dev/kmem") {
			out = append(out, "device "+d)
		}
	}
	return out
}

func cmpOrRoot(p string) string {
	if p == "" {
		return "/"
	}
	return p
}
