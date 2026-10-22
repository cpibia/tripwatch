package discovery

import (
	"slices"
	"testing"
	"testing/fstest"
)

func envFrom(vars map[string]string) func(string) string {
	return func(key string) string { return vars[key] }
}

func TestDetectEnvironment(t *testing.T) {
	file := &fstest.MapFile{}

	tests := []struct {
		name         string
		root         fstest.MapFS
		env          map[string]string
		wantKind     Kind
		wantRuntimes []string
	}{
		{
			name:     "plain host",
			root:     fstest.MapFS{"etc/passwd": file},
			wantKind: KindHost,
		},
		{
			name:         "docker host with containerd",
			root:         fstest.MapFS{"run/docker.sock": file, "run/containerd/containerd.sock": file},
			wantKind:     KindHost,
			wantRuntimes: []string{"docker", "containerd"},
		},
		{
			name:         "socket only under var/run",
			root:         fstest.MapFS{"var/run/docker.sock": file},
			wantKind:     KindHost,
			wantRuntimes: []string{"docker"},
		},
		{
			name:     "inside docker",
			root:     fstest.MapFS{".dockerenv": file},
			wantKind: KindContainer,
		},
		{
			name:     "inside podman",
			root:     fstest.MapFS{"run/.containerenv": file},
			wantKind: KindContainer,
		},
		{
			name:     "kubernetes by env",
			root:     fstest.MapFS{".dockerenv": file},
			env:      map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"},
			wantKind: KindKubernetes,
		},
		{
			name:     "kubernetes by service account",
			root:     fstest.MapFS{"var/run/secrets/kubernetes.io/serviceaccount/token": file},
			wantKind: KindKubernetes,
		},
		{
			name:     "fargate",
			env:      map[string]string{"AWS_EXECUTION_ENV": "AWS_ECS_FARGATE", "KUBERNETES_SERVICE_HOST": "10.0.0.1"},
			wantKind: KindFargate,
		},
		{
			name:     "ecs on ec2 is not fargate",
			root:     fstest.MapFS{".dockerenv": file},
			env:      map[string]string{"AWS_EXECUTION_ENV": "AWS_ECS_EC2"},
			wantKind: KindContainer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectEnvironment(tt.root, envFrom(tt.env))
			if got.Kind != tt.wantKind {
				t.Errorf("kind = %q, want %q", got.Kind, tt.wantKind)
			}
			if !slices.Equal(got.ContainerRuntimes, tt.wantRuntimes) {
				t.Errorf("runtimes = %v, want %v", got.ContainerRuntimes, tt.wantRuntimes)
			}
		})
	}
}
