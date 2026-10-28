package analyze

import (
	"strings"
	"testing"

	"github.com/cpibia/tripwatch/internal/collector/system"
)

// A container with power over the host is raised when it appears; a redeploy of one already
// there (new ID, same name, image and powers) is not, and neither is a plain container.
func TestContainerFindings(t *testing.T) {
	proxy := system.Container{ID: "aaa", Name: "proxy", Image: "traefik:v3", Mounts: []system.Mount{{Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock"}}}
	prev := State{Containers: &system.ContainersResult{Containers: []system.Container{proxy}}}
	redeployed := proxy
	redeployed.ID = "bbb"
	cur := State{Containers: &system.ContainersResult{Containers: []system.Container{
		redeployed,
		{ID: "ccc", Name: "app", Image: "shop:42", Mounts: []system.Mount{{Source: "/srv/shop/storage", Destination: "/app/storage", RW: true}}},
		{ID: "ddd", Name: "x", Image: "alpine", Privileged: true, PIDMode: "host", Mounts: []system.Mount{{Source: "/", Destination: "/host", RW: true}}},
	}}}
	got := containerFindings(&prev, cur)
	if len(got) != 1 || got[0].Severity != "high" || !strings.Contains(got[0].Title, ": x") ||
		!strings.Contains(got[0].Detail, "privileged, the host's processes, the host's /, writable") {
		t.Fatalf("findings = %+v", got)
	}
	if f := containerFindings(nil, cur); f != nil {
		t.Errorf("first snapshot: %+v", f)
	}
	if f := containerFindings(&State{}, cur); f != nil {
		t.Errorf("previous snapshot without containers: %+v", f)
	}
}
