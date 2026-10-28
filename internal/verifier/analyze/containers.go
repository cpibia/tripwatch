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
		if was := images[key]; known[key] && was != "" && c.ImageID != "" && was != c.ImageID {
			out = append(out, Finding{Kind: "containers", Owner: "root", Severity: "medium", Fingerprint: "containers:image:" + key + ":" + c.ImageID,
				Title: "Container with access to the host runs another image: " + c.Name,
				Detail: fmt.Sprintf("Container %s (%s), image %s, now runs %s instead of %s, with %s. An update does this; so does an image retagged by whoever controls the daemon. Check that the new image is one you built or pulled.",
					c.Name, c.ID, orUnknown(c.Image), c.ImageID, was, strings.Join(powers, ", "))})
			continue
		}
		if known[key] {
			continue
		}
		out = append(out, containerFinding(watch.ContainerInfo{ID: c.ID, Name: c.Name, Image: c.Image, Created: c.Created, Powers: powers},
			"Container with access to the host: "+c.Name))
	}
	return out
}

// containerFinding is the alert of a container with power over the host, from a snapshot or
// from the event of its start. Both give it the same fingerprint and detail: what was accepted
// from one is not raised again by the other.
func containerFinding(c watch.ContainerInfo, title string) Finding {
	return Finding{Kind: "containers", Owner: "root", Severity: "high", Fingerprint: "containers:new-power:" + c.Key(), Title: title,
		Detail: fmt.Sprintf("Container %s (%s), image %s, created %s, has %s. Each of these is root on the host: whoever controls the container controls the server. Check that it is a container you started.",
			c.Name, c.ID, orUnknown(c.Image), orUnknown(c.Created), strings.Join(c.Powers, ", "))}
}

func containerKey(c system.Container, powers []string) string {
	return watch.ContainerInfo{Name: c.Name, Image: c.Image, Powers: powers}.Key()
}
