package analyze

import (
	"fmt"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector/system"
	"github.com/cpibia/tripwatch/internal/watch"
)

// containerFindings raises a container with power over the host when it appears: a new name,
// image or power. Long-lived ones with a runtime socket (a reverse proxy, a deploy agent) and
// their redeploys raise nothing new; a container started to escape does. Only snapshots that
// both read the containers are compared.
func containerFindings(prev *State, cur State) []Finding {
	if cur.Containers == nil || prev == nil || prev.Containers == nil {
		return nil
	}
	known := map[string]bool{}
	images := map[string]string{}
	for _, c := range prev.Containers.Containers {
		key := containerKey(c, system.ContainerPowers(c))
		known[key] = true
		images[key] = c.ImageID
	}
	var out []Finding
	for _, c := range cur.Containers.Containers {
		powers := system.ContainerPowers(c)
		key := containerKey(c, powers)
		if len(powers) == 0 {
			continue
		}
		// The tag is a label whoever controls the daemon rewrites: the same name, tag and
		// powers on another image is another program holding root on the host. An update does
		// this too, hence medium.
		info := watch.ContainerInfo{ID: c.ID, Name: c.Name, Image: c.Image, ImageID: c.ImageID, Created: c.Created, Powers: powers}
		if was := images[key]; known[key] && was != "" && c.ImageID != "" && was != c.ImageID {
			info.Replaces = was
			out = append(out, containerImageFinding(info))
			continue
		}
		if known[key] {
			continue
		}
		out = append(out, containerFinding(info, "Container with access to the host"))
	}
	return out
}

// containerFinding is the alert of a container with power over the host, from a snapshot or
// from the event of its start. Both give it the same fingerprint and detail: what was accepted
// from one is not raised again by the other. The detail leaves out what changes with every
// start of the same container, its ID and creation time, which go in the title, so that an
// acceptance holds for a job container started again every day.
func containerFinding(c watch.ContainerInfo, title string) Finding {
	return Finding{Kind: "containers", Owner: "root", Severity: "high", Fingerprint: "containers:new-power:" + c.Key(),
		Title: fmt.Sprintf("%s: %s (%s, created %s)", title, c.Name, c.ID, orUnknown(c.Created)),
		Detail: fmt.Sprintf("Container %s, image %s, has %s. Each of these is root on the host: whoever controls the container controls the server. Check that it is a container you started.",
			c.Name, orUnknown(c.Image), strings.Join(c.Powers, ", "))}
}

// containerImageFinding is the alert of a container with power over the host that runs
// another image than the one of the same name, tag and powers before it, from a snapshot or
// from the event of its start, with the same fingerprint and detail.
func containerImageFinding(c watch.ContainerInfo) Finding {
	key := watch.ContainerInfo{Name: c.Name, Image: c.Image, Powers: c.Powers}.Key()
	return Finding{Kind: "containers", Owner: "root", Severity: "medium", Fingerprint: "containers:image:" + key + ":" + c.ImageID,
		Title: "Container with access to the host runs another image: " + c.Name,
		Detail: fmt.Sprintf("Container %s, image %s, now runs %s instead of %s, with %s. An update does this; so does an image retagged by whoever controls the daemon. Check that the new image is one you built or pulled.",
			c.Name, orUnknown(c.Image), c.ImageID, c.Replaces, strings.Join(c.Powers, ", "))}
}

func containerKey(c system.Container, powers []string) string {
	return watch.ContainerInfo{Name: c.Name, Image: c.Image, Powers: powers}.Key()
}
