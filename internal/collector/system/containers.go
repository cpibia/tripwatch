package system

import (
	"cmp"
	"context"
	"encoding/json"
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
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Image       string   `json:"image"`
	ImageID     string   `json:"image_id,omitempty"`
	Created     string   `json:"created,omitempty"`
	Running     bool     `json:"running,omitempty"`
	User        string   `json:"user,omitempty"`
	Privileged  bool     `json:"privileged,omitempty"`
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
// root's: its data root is read from daemon.json when it is moved. Podman and containerd are
// not read yet.
type Containers struct{}

func (Containers) Name() string { return "containers" }

func (Containers) Collect(ctx context.Context, src collector.Source) (any, error) {
	res := ContainersResult{Containers: []Container{}}
	dir := path.Join(dockerRoot(src.FS, &res.Issues), "containers")
	entries, err := fs.ReadDir(src.FS, dir)
	if err != nil {
		return res, nil
	}
	res.Runtime = "docker"
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if !e.IsDir() {
			continue
		}
		if len(res.Containers) == maxContainers {
			res.Truncated = true
			break
		}
		if c, ok := readDockerContainer(src.FS, path.Join(dir, e.Name()), &res.Issues); ok {
			res.Containers = append(res.Containers, c)
		}
	}
	return res, nil
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
