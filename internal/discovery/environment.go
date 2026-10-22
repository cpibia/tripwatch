// Package discovery inventories what runs on the observed machine, so the sensor knows which
// collectors and profiles apply.
package discovery

import "io/fs"

// Kind is where the sensor process itself runs.
type Kind string

const (
	KindHost       Kind = "host"
	KindContainer  Kind = "container"
	KindKubernetes Kind = "kubernetes"
	KindFargate    Kind = "fargate"
)

// Environment describes where the sensor runs and which container runtimes the observed
// filesystem exposes.
type Environment struct {
	Kind              Kind     `json:"kind"`
	ContainerRuntimes []string `json:"container_runtimes,omitempty"`
}

var runtimeSockets = []struct {
	name string
	path string
}{
	{"docker", "run/docker.sock"},
	{"containerd", "run/containerd/containerd.sock"},
	{"cri-o", "run/crio/crio.sock"},
	{"podman", "run/podman/podman.sock"},
}

// DetectEnvironment inspects root, the filesystem being observed ("/" on a host, the host
// root mounted into the pod for a Kubernetes DaemonSet), and getenv, the sensor's own
// environment. Paths in root are relative, as io/fs requires.
func DetectEnvironment(root fs.FS, getenv func(string) string) Environment {
	return Environment{
		Kind:              detectKind(root, getenv),
		ContainerRuntimes: detectRuntimes(root),
	}
}

func detectKind(root fs.FS, getenv func(string) string) Kind {
	switch {
	case getenv("AWS_EXECUTION_ENV") == "AWS_ECS_FARGATE":
		return KindFargate
	case getenv("KUBERNETES_SERVICE_HOST") != "" || exists(root, "var/run/secrets/kubernetes.io/serviceaccount/token"):
		return KindKubernetes
	case exists(root, ".dockerenv") || exists(root, "run/.containerenv"):
		return KindContainer
	default:
		return KindHost
	}
}

func detectRuntimes(root fs.FS) []string {
	var found []string
	for _, rs := range runtimeSockets {
		// Most distributions symlink /var/run to /run; checking both covers the ones that don't.
		if exists(root, rs.path) || exists(root, "var/"+rs.path) {
			found = append(found, rs.name)
		}
	}
	return found
}

func exists(root fs.FS, name string) bool {
	_, err := fs.Stat(root, name)
	return err == nil
}
