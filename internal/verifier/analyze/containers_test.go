package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/collector/system"
	"github.com/cpibia/tripwatch/internal/watch"
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

// The start of a container with power over the host, seen in real time, is raised with the
// snapshot rule's fingerprint and detail; its removal, and a container without powers, raise
// nothing.
func TestContainerEvents(t *testing.T) {
	c := system.Container{ID: "ddd", Name: "x", Image: "alpine", Created: "2026-10-28T10:00:00Z", Privileged: true}
	info := &watch.ContainerInfo{ID: c.ID, Name: c.Name, Image: c.Image, Created: c.Created, Runtime: "docker", Powers: system.ContainerPowers(c)}
	at := time.Date(2026, 10, 28, 10, 0, 1, 0, time.UTC)
	got := EvaluateEvents([]watch.Event{
		{At: at, Class: watch.ClassContainer, Op: watch.OpCreate, Path: "/var/lib/docker/containers/ddd", Container: info},
		{At: at, Class: watch.ClassContainer, Op: watch.OpDelete, Path: "/var/lib/docker/containers/ddd", Container: info},
		{At: at, Class: watch.ClassContainer, Op: watch.OpCreate, Path: "/var/lib/docker/containers/eee", Container: &watch.ContainerInfo{Name: "plain"}},
	}, true, nil)
	snap := containerFindings(&State{Containers: &system.ContainersResult{}}, State{Containers: &system.ContainersResult{Containers: []system.Container{c}}})
	if len(got) != 1 || len(snap) != 1 || got[0].Fingerprint != snap[0].Fingerprint || got[0].Detail != snap[0].Detail ||
		got[0].Severity != "high" || !strings.Contains(got[0].Title, "started: x") {
		t.Fatalf("event findings %+v, snapshot findings %+v", got, snap)
	}
}
