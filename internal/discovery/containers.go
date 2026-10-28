package discovery

import (
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/system"
)

// containerView opens the filesystem a container's process sees; tests replace it.
var containerView = collector.ContainerSource

// InspectWithContainers is Inspect plus the web servers running in containers. A container's
// configuration is read from its own filesystem, as its server reads it, and every path in it
// is translated to where it lies on the host through the container's mounts: what the image
// itself holds is not on the host's disk and is left out, said in the issues.
func InspectWithContainers(src collector.Source) Inventory {
	inv := inspectSites(src.FS)
	sites, files, published, issues := containerSites(src)
	inv.Sites = nameProxied(append(inv.Sites, sites...), published)
	inv.Issues = append(inv.Issues, issues...)
	for _, name := range files {
		f, err := collector.Describe(src, name)
		inv.Issues.Add(err)
		if f.Path != "" {
			inv.ConfigFiles = append(inv.ConfigFiles, f)
		}
	}
	inv.Applications = FindApplications(src.FS, inv.Sites)
	inv.Runtimes = runningRuntimes(src.FS)
	return inv
}

// maxContainerSites bounds the sites read from all containers together.
const maxContainerSites = 1024

func containerSites(src collector.Source) (sites []Site, files []string, published map[string]string, issues collector.Issues) {
	published = map[string]string{}
	refs, _ := system.ContainerRefs(src.FS, &issues)
	if len(refs) == 0 {
		return nil, nil, published, issues
	}
	host := system.NewHostMounts(src.FS)
	hostMnt, _ := fs.ReadLink(src.FS, "proc/1/ns/mnt")
	var unread collector.Issues
	for _, ref := range refs {
		c, ok := system.ReadContainer(src.FS, ref, host, &unread)
		if !ok || !c.Running || c.PID <= 0 {
			continue
		}
		// A process sharing the host's mount namespace would show the host itself.
		if mnt, err := fs.ReadLink(src.FS, fmt.Sprintf("proc/%d/ns/mnt", c.PID)); err != nil || mnt == hostMnt {
			continue
		}
		for hostPort := range c.Published {
			published[hostPort] = c.Name
		}
		found, names, errs := readContainer(src, c)
		issues = append(issues, errs...)
		for _, s := range found {
			if len(sites) == maxContainerSites {
				issues = append(issues, fmt.Sprintf("more than %d sites in containers: the rest not read", maxContainerSites))
				return sites, files, published, issues
			}
			sites = append(sites, s)
		}
		for _, n := range names {
			if !slices.Contains(files, n) {
				files = append(files, n)
			}
		}
	}
	return sites, files, published, issues
}

// nameProxied gives the sites of a container the names of the sites that proxy to it. A
// container behind a proxy usually answers any name (server_name _): the domain is the proxy's,
// which sends it to a port of the loopback the container publishes.
func nameProxied(sites []Site, published map[string]string) []Site {
	if len(published) == 0 {
		return sites
	}
	names := map[string][]string{}
	for _, s := range sites {
		for _, u := range s.Upstreams {
			if c, ok := published[loopbackPort(u)]; ok {
				for _, n := range s.Names {
					if !anyName(n) && !slices.Contains(names[c], n) && len(names[c]) < maxProxiedNames {
						names[c] = append(names[c], n)
					}
				}
			}
		}
	}
	for i, s := range sites {
		if s.Container != "" && len(names[s.Container]) > 0 && !slices.ContainsFunc(s.Names, func(n string) bool { return !anyName(n) }) {
			sites[i].Names = append(slices.Clone(names[s.Container]), s.Names...)
		}
	}
	return sites
}

// maxProxiedNames bounds the names a container gets from the proxies in front of it.
const maxProxiedNames = 16

// anyName reports a server name that matches whatever the request asks for.
func anyName(n string) bool {
	return n == "_" || n == "" || n == "localhost" || n == "default_server"
}

// loopbackPort returns the port of an upstream on the loopback ("http://127.0.0.1:8101/"),
// or "" for any other upstream.
func loopbackPort(u string) string {
	if _, rest, ok := strings.Cut(u, "://"); ok {
		u = rest
	}
	u, _, _ = strings.Cut(u, "/")
	host, port, ok := strings.Cut(u, ":")
	if !ok || port == "" || host != "127.0.0.1" && host != "localhost" && host != "0.0.0.0" {
		return ""
	}
	return port
}

// readContainer parses the web server configurations inside one container and returns its
// sites with host paths, and the configuration files that lie on the host.
func readContainer(src collector.Source, c system.Container) ([]Site, []string, collector.Issues) {
	c.Mounts = append(slices.Clone(c.Mounts), c.Volumes...)
	view, release := containerView(src, c.PID)
	defer release()
	var issues collector.Issues
	var sites []Site
	var files []string
	for _, parse := range []func(fs.FS) ([]Site, []string, collector.Issues){NginxSites, ApacheSites, CaddySites} {
		found, names, errs := parse(view.FS)
		for _, e := range errs {
			issues = append(issues, "container "+c.Name+": "+e)
		}
		for _, n := range names {
			if p, ok := onHost("/"+n, c.Mounts); ok {
				files = append(files, collector.Rel(p))
			}
		}
		for _, s := range found {
			if s, ok := hostSite(s, c, &issues); ok {
				sites = append(sites, s)
			}
		}
	}
	return sites, files, issues
}

// hostSite translates a site read inside container c to the host's paths. A site whose root
// stays in the image keeps no root: its files are not on the host's disk.
func hostSite(s Site, c system.Container, issues *collector.Issues) (Site, bool) {
	s.Container = c.Name
	if p, ok := onHost(s.Config, c.Mounts); ok {
		s.Config = p
	}
	if s.Root != "" && !strings.Contains(s.Root, "$") {
		p, ok := onHost(s.Root, c.Mounts)
		if !ok {
			if len(s.Names) > 0 && s.Names[0] != "_" && s.Names[0] != "localhost" {
				*issues = append(*issues, fmt.Sprintf("container %s: %s is served from %s inside the image, not scanned", c.Name, s.Names[0], s.Root))
			}
			p = ""
		}
		s.Root = p
	}
	s.AccessLogs = hostPaths(s.AccessLogs, c.Mounts)
	s.ErrorLogs = hostPaths(s.ErrorLogs, c.Mounts)
	s.Locations = hostLocations(s.Locations, c.Mounts)
	for i, a := range s.aliases {
		if p, ok := onHost(a.dir, c.Mounts); ok {
			s.aliases[i].dir = p
		} else {
			// The alias leads into the image: what it serves cannot be told from the host.
			s.aliases[i].dir, s.opaque = "", true
		}
	}
	return s, s.Root != "" || len(s.AccessLogs) > 0
}

func hostLocations(locs []Location, mounts []system.Mount) []Location {
	out := slices.Clone(locs)
	for i := range out {
		if out[i].Root != "" {
			out[i].Root, _ = onHost(out[i].Root, mounts)
		}
		out[i].Locations = hostLocations(out[i].Locations, mounts)
	}
	return out
}

func hostPaths(list []string, mounts []system.Mount) []string {
	var out []string
	for _, p := range list {
		if h, ok := onHost(p, mounts); ok {
			out = append(out, h)
		}
	}
	return out
}

// onHost translates a path inside a container to the host's, through the deepest mount that
// holds it. Only mounts of a host directory or file translate: a path in the image, a tmpfs or
// a device has no place on the host's disk.
func onHost(p string, mounts []system.Mount) (string, bool) {
	if !path.IsAbs(p) || strings.Contains(p, "$") {
		return "", false
	}
	p = path.Clean(p)
	var best *system.Mount
	for i := range mounts {
		d := path.Clean(mounts[i].Destination)
		if (p == d || strings.HasPrefix(p, strings.TrimSuffix(d, "/")+"/")) && (best == nil || len(d) > len(path.Clean(best.Destination))) {
			best = &mounts[i]
		}
	}
	if best == nil {
		return "", false
	}
	source := best.Resolved
	if source == "" {
		source = best.Source
	}
	if !path.IsAbs(source) {
		return "", false
	}
	return path.Join(source, strings.TrimPrefix(p, path.Clean(best.Destination))), true
}
