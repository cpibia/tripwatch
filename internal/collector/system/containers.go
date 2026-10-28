package system

import (
	"cmp"
	"context"
	"encoding/json"
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
	// DeviceRules are the device cgroup rules that allow access ("b *:* rwm"): with the
	// CAP_MKNOD containers have by default, an allowed node can be created and opened.
	DeviceRules []string `json:"device_rules,omitempty"`
	Mounts      []Mount  `json:"mounts,omitempty"`
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
				kernelMounts(fsys, pid, host, c.Mounts)
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
			if !ok {
				continue
			}
			mount.Source, mount.Volume = device, m.Name
		} else if m.Type != "" && m.Type != "bind" || m.Source == "" {
			continue
		}
		c.Mounts = append(c.Mounts, resolveMount(fsys, mount))
	}
	if cfg.State.Running {
		kernelMounts(fsys, cfg.State.Pid, host, c.Mounts)
	}
	if data, err := fs.ReadFile(fsys, path.Join(dir, "hostconfig.json")); err == nil {
		var hc dockerHostConfig
		if err := json.Unmarshal(data, &hc); err != nil {
			issues.Add(err)
		} else {
			c.Privileged, c.PIDMode, c.NetworkMode, c.IPCMode, c.UsernsMode = hc.Privileged, hc.PidMode, hc.NetworkMode, hc.IpcMode, hc.UsernsMode
			c.CapAdd, c.SecurityOpt = hc.CapAdd, hc.SecurityOpt
			for _, d := range hc.Devices {
				c.Devices = append(c.Devices, d.PathOnHost)
			}
			c.DeviceRules = deviceRules(hc.DeviceCgroupRules)
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
		c.Devices = append(c.Devices, d.Path)
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

// hostTrees are the host directories that give a container the host as a whole: its root, its
// configuration, root's home, the kernel's interfaces and the runtimes' state.
var hostTrees = []string{"/", "/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/var", "/var/lib", "/var/lib/docker", "/var/lib/containerd",
	"/var/lib/containers", "/var/lib/kubelet", "/var/run", "/run", "/usr", "/lib", "/lib64", "/bin", "/sbin", "/home", "/var/spool", "/var/spool/cron"}

// systemTrees are those where any directory or file below is the host's too when writable: a
// cron.d, a unit directory, a library, root's keys, a cgroup's release_agent.
var systemTrees = []string{"/etc", "/root", "/boot", "/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc", "/sys",
	"/var/lib/docker", "/var/lib/containerd", "/var/lib/containers", "/var/lib/kubelet", "/var/spool/cron"}

// secretTrees are those where reading is enough: password hashes, private keys, the cluster's
// and the runtimes' credentials, and through /proc/<pid>/root the whole host.
var secretTrees = []string{"/root", "/etc/shadow", "/etc/gshadow", "/etc/ssh", "/etc/sudoers", "/etc/sudoers.d", "/etc/kubernetes",
	"/etc/docker", "/proc", "/var/lib/docker", "/var/lib/containerd", "/var/lib/containers", "/var/lib/kubelet", "/var/spool/cron"}

// harmlessFiles are host files commonly shared writable with containers that give no power
// over the host, and the time zone files /etc/localtime links to.
var harmlessFiles = []string{"/etc/localtime", "/etc/timezone", "/etc/hostname", "/etc/hosts", "/etc/resolv.conf", "/etc/machine-id", "/etc/os-release", "/usr/share/zoneinfo"}

// rawDisks are the device names of disks and memory: raw access to them bypasses every
// permission of the filesystems on top.
var rawDisks = []string{"/dev/sd", "/dev/hd", "/dev/vd", "/dev/xvd", "/dev/nvme", "/dev/dm-", "/dev/mapper/", "/dev/loop", "/dev/md",
	"/dev/mmcblk", "/dev/disk/", "/dev/nbd", "/dev/rbd", "/dev/zd", "/dev/mem", "/dev/kmem", "/dev/port"}

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
	case isRawDisk(src):
		return fmt.Sprintf("the host's disk %s, %s", name, mode)
	case under(src, harmlessFiles) || slices.Contains(harmlessFiles, path.Clean("/"+m.Source)):
		return ""
	case under(src, secretTrees) || m.RW && under(src, systemTrees):
		return fmt.Sprintf("the host's %s, %s", name, mode)
	}
	return ""
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

func isRawDisk(d string) bool {
	return slices.ContainsFunc(rawDisks, func(prefix string) bool { return strings.HasPrefix(d, prefix) })
}

// deviceRuleGrantsHost says whether a cgroup rule ("type major:minor access") lets the container
// read or write a disk or the host's memory: any block device, or the memory character devices
// (major 1: mem, kmem, port; the others of major 1 are /dev/null, zero and the random sources).
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
		return major == "*" || major == "1" && slices.Contains([]string{"*", "1", "2", "4"}, minor)
	}
	return false
}

// maxMountEntries bounds the mount table entries parsed from one mountinfo file.
const maxMountEntries = 16384

type mountEntry struct{ dev, root, point string }

// HostMounts is the host's mount table, read once when first needed, to tell which host
// directory a running container's mount really is.
type HostMounts struct {
	fsys    fs.FS
	read    bool
	entries []mountEntry
}

func NewHostMounts(fsys fs.FS) *HostMounts { return &HostMounts{fsys: fsys} }

func readMountEntries(fsys fs.FS, name string) []mountEntry {
	lines, err := collector.ReadLines(fsys, name)
	if err != nil {
		return nil
	}
	var out []mountEntry
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if len(out) == maxMountEntries {
			break
		}
		out = append(out, mountEntry{dev: fields[2], root: unescapeMount(fields[3]), point: unescapeMount(fields[4])})
	}
	return out
}

// hostPath is where the part root of the filesystem dev appears on the host: the shortest of
// the paths the host's mounts of that filesystem give it.
func (h *HostMounts) hostPath(dev, root string) (string, bool) {
	if !h.read {
		h.entries, h.read = readMountEntries(h.fsys, "proc/1/mountinfo"), true
	}
	best := ""
	for _, e := range h.entries {
		if e.dev != dev {
			continue
		}
		rest, ok := strings.CutPrefix(root, e.root)
		if !ok || e.root != "/" && rest != "" && !strings.HasPrefix(rest, "/") {
			continue
		}
		if p := path.Join("/", e.point, rest); best == "" || len(p) < len(best) {
			best = p
		}
	}
	return best, best != ""
}

// kernelMounts sets where each mount of a running container comes from as its kernel sees it,
// from the mount table of the container's process: unlike the source written in its
// configuration, a link swapped before the start and put back after cannot change it.
func kernelMounts(fsys fs.FS, pid int, host *HostMounts, mounts []Mount) {
	if pid <= 0 || host == nil || len(mounts) == 0 {
		return
	}
	byPoint := map[string]mountEntry{}
	for _, e := range readMountEntries(fsys, "proc/"+strconv.Itoa(pid)+"/mountinfo") {
		byPoint[e.point] = e
	}
	for i := range mounts {
		e, ok := byPoint[path.Clean("/"+mounts[i].Destination)]
		if !ok {
			continue
		}
		if p, ok := host.hostPath(e.dev, e.root); ok {
			mounts[i].Resolved = ""
			if p != path.Clean("/"+mounts[i].Source) {
				mounts[i].Resolved = p
			}
		}
	}
}
