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

// The same name, tag and powers on another image is another program with root on the host.
func TestContainerWithPowerOnAnotherImage(t *testing.T) {
	proxy := system.Container{ID: "aaa", Name: "proxy", Image: "proxy:v2", ImageID: "sha256:1111", Mounts: []system.Mount{{Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock"}}}
	retagged := proxy
	retagged.ID, retagged.ImageID = "bbb", "sha256:2222"
	got := containerFindings(&State{Containers: &system.ContainersResult{Containers: []system.Container{proxy}}},
		State{Containers: &system.ContainersResult{Containers: []system.Container{retagged}}})
	if len(got) != 1 || got[0].Severity != "medium" || !strings.Contains(got[0].Detail, "sha256:2222 instead of sha256:1111") {
		t.Fatalf("findings = %+v", got)
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

// A start seen in real time on another image than the one of the same name, tag and powers
// before is the snapshot rule's medium, with its fingerprint and detail. The detail of a start
// does not change with the container's ID and creation time, so an acceptance holds for the
// same container started again.
func TestContainerEventsImageSwapAndStableDetail(t *testing.T) {
	proxy := system.Container{ID: "aaa", Name: "proxy", Image: "proxy:v2", ImageID: "sha256:1111", Mounts: []system.Mount{{Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock"}}}
	swapped := proxy
	swapped.ID, swapped.ImageID = "bbb", "sha256:2222"
	snap := containerFindings(&State{Containers: &system.ContainersResult{Containers: []system.Container{proxy}}},
		State{Containers: &system.ContainersResult{Containers: []system.Container{swapped}}})
	info := &watch.ContainerInfo{ID: swapped.ID, Name: swapped.Name, Image: swapped.Image, ImageID: swapped.ImageID, Replaces: proxy.ImageID,
		Runtime: "docker", Powers: system.ContainerPowers(swapped)}
	got := EvaluateEvents([]watch.Event{{At: time.Now(), Class: watch.ClassContainer, Op: watch.OpCreate, Path: "/var/lib/docker/containers/bbb", Container: info}}, true, nil)
	if len(got) != 1 || len(snap) != 1 || got[0].Fingerprint != snap[0].Fingerprint || got[0].Detail != snap[0].Detail || got[0].Severity != "medium" {
		t.Fatalf("event findings %+v, snapshot findings %+v", got, snap)
	}

	// Accepting a container never covers another image under its tag, whatever the window: the
	// digest is in the detail an acceptance is bound to. A runtime that reports no digest says so.
	good := containerFinding(watch.ContainerInfo{ID: "aaa", Name: "proxy", Image: "proxy:v2", ImageID: "sha256:good", Powers: []string{"privileged"}}, "Container with access to the host")
	backdoor := containerFinding(watch.ContainerInfo{ID: "bbb", Name: "proxy", Image: "proxy:v2", ImageID: "sha256:backdoor", Powers: []string{"privileged"}}, "Container with access to the host")
	unknown := containerFinding(watch.ContainerInfo{ID: "ccc", Name: "proxy", Image: "proxy:v2", Powers: []string{"privileged"}}, "Container with access to the host")
	if good.Fingerprint != backdoor.Fingerprint || good.Detail == backdoor.Detail || !strings.Contains(unknown.Detail, "digest not reported by the runtime") {
		t.Errorf("good %q, backdoor %q, without digest %q", good.Detail, backdoor.Detail, unknown.Detail)
	}

	first := containerFinding(watch.ContainerInfo{ID: "aaa", Name: "job", Image: "backup", Created: "2026-10-28T03:00:00Z", Powers: []string{"privileged"}}, "Container with access to the host started")
	again := containerFinding(watch.ContainerInfo{ID: "ccc", Name: "job", Image: "backup", Created: "2026-10-29T03:00:00Z", Powers: []string{"privileged"}}, "Container with access to the host started")
	if first.Fingerprint != again.Fingerprint || first.Detail != again.Detail || first.Title == again.Title || !strings.Contains(again.Title, "ccc") {
		t.Errorf("first %+v, again %+v", first, again)
	}
}

// A container list cut at its bound is an alert: what was left out is not checked.
func TestTruncatedContainersRaiseAnAlert(t *testing.T) {
	cur := State{Containers: &system.ContainersResult{Truncated: true}}
	for _, f := range Evaluate(nil, cur) {
		if f.Fingerprint == "containers:truncated" && f.Severity == "high" {
			return
		}
	}
	t.Error("no alert for a truncated container list")
}

// A runtime the sensor could not read is an alert: an empty list is not a host without
// containers.
func TestUnreadRuntimeRaisesAnAlert(t *testing.T) {
	cur := State{Containers: &system.ContainersResult{Issues: []string{system.RuntimeUnread + "dockerd"}}}
	for _, f := range Evaluate(nil, cur) {
		if f.Fingerprint == "containers:unread" && f.Severity == "medium" {
			return
		}
	}
	t.Error("no alert for a runtime whose containers were not found")
}
