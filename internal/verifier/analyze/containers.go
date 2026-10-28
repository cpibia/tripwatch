package analyze

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector/system"
)

// hostSockets are the sockets of container runtimes: a container that holds one can start a
// privileged container of its own.
var hostSockets = []string{"/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/var/run/crio/crio.sock", "/run/podman/podman.sock"}

// hostTrees are the host directories that give a container the host: its root, its
// configuration, root's home, the kernel's interfaces and the runtimes' state.
var hostTrees = []string{"/", "/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/var/lib/docker", "/var/lib/containerd", "/var/run", "/run", "/usr", "/lib", "/bin", "/sbin", "/home", "/var/spool/cron"}

// adminCaps are the capabilities that let a container's root act as the host's.
var adminCaps = []string{"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH", "SYS_BOOT", "BPF", "PERFMON"}

// containerPowers lists what lets a container reach the host. A runtime's socket, the host's
// root, privileged mode or the host's process namespace each amount to root on the host.
func containerPowers(c system.Container) []string {
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

// containerFindings raises a container with power over the host when it appears: a new name,
// image or power. Long-lived ones with a runtime socket (a reverse proxy, a deploy agent) and
// their redeploys raise nothing new; a container started to escape does. Only snapshots that
// both read the containers are compared.
func containerFindings(prev *State, cur State) []Finding {
	if cur.Containers == nil || prev == nil || prev.Containers == nil {
		return nil
	}
	known := map[string]bool{}
	for _, c := range prev.Containers.Containers {
		known[containerKey(c, containerPowers(c))] = true
	}
	var out []Finding
	for _, c := range cur.Containers.Containers {
		powers := containerPowers(c)
		if len(powers) == 0 || known[containerKey(c, powers)] {
			continue
		}
		out = append(out, Finding{Kind: "containers", Owner: "root", Severity: "high",
			Fingerprint: "containers:new-power:" + containerKey(c, powers),
			Title:       "Container with access to the host: " + c.Name,
			Detail: fmt.Sprintf("Container %s (%s), image %s, created %s, running %v, has %s. Each of these is root on the host: whoever controls the container controls the server. Check that it is a container you started.",
				c.Name, c.ID, c.Image, c.Created, c.Running, strings.Join(powers, ", "))})
	}
	return out
}

func containerKey(c system.Container, powers []string) string {
	return c.Name + "|" + c.Image + "|" + strings.Join(powers, ",")
}
