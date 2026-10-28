package discovery

import (
	"io/fs"
	"slices"
	"strconv"
	"testing"
	"testing/fstest"

	"github.com/cpibia/tripwatch/internal/collector"
)

// A host serving its sites from containers, as shared hosting does: one nginx container per
// site, the code and the logs bind-mounted from the host, a second site in a named volume, and
// the proxy's own default page inside its image. Every site is found where it lies on the host,
// named after its container, and the applications under them carry their domains.
func TestSitesServedFromContainers(t *testing.T) {
	docker := func(id, name string, pid int, mounts string) (string, *fstest.MapFile) {
		return "var/lib/docker/containers/" + id + "/config.v2.json", text(`{"ID": "` + id + `", "Name": "/` + name + `",
			"Config": {"Image": "nginx:1.26-alpine"}, "State": {"Running": true, "Pid": ` + strconv.Itoa(pid) + `}, "MountPoints": {` + mounts + `}}`)
	}
	bind := func(src, dst string) string {
		return `"` + dst + `": {"Source": "` + src + `", "Destination": "` + dst + `", "Type": "bind"}`
	}
	host := fstest.MapFS{
		"proc/1/ns/mnt":   {Data: []byte("mnt:[1]"), Mode: fs.ModeSymlink},
		"proc/100/ns/mnt": {Data: []byte("mnt:[2]"), Mode: fs.ModeSymlink},
		"proc/200/ns/mnt": {Data: []byte("mnt:[3]"), Mode: fs.ModeSymlink},
		"proc/300/ns/mnt": {Data: []byte("mnt:[1]"), Mode: fs.ModeSymlink},

		"srv/hosting/sites/shop/index.php":               text("<?php"),
		"srv/hosting/sites/shop/wp-includes/version.php": text("<?php $wp_version = '6.6.2';"),
		"srv/hosting/stacks/shop/nginx/site.conf":        text(""),
		"var/lib/docker/volumes/blog/_data/index.php":    text("<?php"),
	}
	k, v := docker("a1", "shop-web-1", 100, bind("/srv/hosting/sites/shop", "/srv/www")+", "+
		bind("/srv/hosting/stacks/shop/nginx", "/etc/nginx/conf.d")+", "+bind("/srv/hosting/stacks/shop/logs", "/var/log/nginx"))
	host[k] = v
	k, v = docker("b2", "blog-web-1", 200, `"/var/www/html": {"Source": "/var/lib/docker/volumes/blog/_data", "Destination": "/var/www/html", "Name": "blog", "Driver": "local", "Type": "volume"}`)
	host[k] = v
	// A container sharing the host's mount namespace shows the host: not read twice.
	k, v = docker("c3", "tool-1", 300, "")
	host[k] = v

	views := map[int]fstest.MapFS{
		100: {
			"etc/nginx/nginx.conf":       text("http { include /etc/nginx/conf.d/*.conf; server { listen 8080; server_name _; } }"),
			"etc/nginx/conf.d/site.conf": text("server { server_name shop.example.com; root /srv/www; access_log /var/log/nginx/shop.log;\n location /media/ { alias /srv/www/wp-content/uploads/; } }"),
		},
		200: {"etc/nginx/nginx.conf": text("http { server { server_name blog.example.com; root /var/www/html; } }")},
		300: {"etc/nginx/nginx.conf": text("http { server { server_name host.example.com; root /var/www; } }")},
	}
	defer func(orig func(collector.Source, int) (collector.Source, func())) { containerView = orig }(containerView)
	containerView = func(_ collector.Source, pid int) (collector.Source, func()) {
		return collector.Source{FS: views[pid]}, func() {}
	}

	inv := InspectWithContainers(collector.Source{FS: host})
	got := map[string]Site{}
	for _, s := range inv.Sites {
		got[s.Names[0]] = s
	}
	shop, blog := got["shop.example.com"], got["blog.example.com"]
	if shop.Container != "shop-web-1" || shop.Root != "/srv/hosting/sites/shop" || shop.Config != "/srv/hosting/stacks/shop/nginx/site.conf" ||
		!slices.Equal(shop.AccessLogs, []string{"/srv/hosting/stacks/shop/logs/shop.log"}) || shop.Locations[0].Root != "/srv/hosting/sites/shop/wp-content/uploads" {
		t.Errorf("shop = %+v", shop)
	}
	if blog.Container != "blog-web-1" || blog.Root != "/var/lib/docker/volumes/blog/_data" {
		t.Errorf("blog = %+v", blog)
	}
	if _, ok := got["host.example.com"]; ok {
		t.Error("a container in the host's mount namespace was read as a container")
	}
	if def, ok := got["_"]; ok && def.Root != "" {
		t.Errorf("the image's default root became a host path: %+v", def)
	}
	apps := map[string]Application{}
	for _, a := range inv.Applications {
		apps[a.Path] = a
	}
	if a := apps["/srv/hosting/sites/shop"]; a.Framework != "wordpress" || a.Version != "6.6.2" || !slices.Equal(a.Sites, []string{"shop.example.com"}) {
		t.Errorf("shop application = %+v", a)
	}
	if a := apps["/var/lib/docker/volumes/blog/_data"]; !slices.Equal(a.Sites, []string{"blog.example.com"}) {
		t.Errorf("blog application = %+v (apps %v)", a, inv.Applications)
	}
	if !slices.ContainsFunc(inv.ConfigFiles, func(f collector.File) bool { return f.Path == "/srv/hosting/stacks/shop/nginx/site.conf" }) {
		t.Errorf("config files = %v", inv.ConfigFiles)
	}
}

// A proxy on the host sends a domain to a loopback port a container publishes, and the
// container's server answers any name: the container's site carries the proxy's domain.
func TestContainerSitesNamedByTheProxy(t *testing.T) {
	host := fstest.MapFS{
		"etc/nginx/nginx.conf": text("http { server { server_name shop.example.com www.shop.example.com; location / { proxy_pass http://127.0.0.1:8101; } }\n" +
			"server { server_name other.example.com; location / { proxy_pass http://127.0.0.1:9999/; } } }"),
		"proc/1/ns/mnt":      {Data: []byte("mnt:[1]"), Mode: fs.ModeSymlink},
		"proc/100/ns/mnt":    {Data: []byte("mnt:[2]"), Mode: fs.ModeSymlink},
		"srv/shop/index.php": text("<?php"),
		"var/lib/docker/containers/a1/config.v2.json": text(`{"ID": "a1", "Name": "/shop-web-1", "State": {"Running": true, "Pid": 100},
			"MountPoints": {"/srv/www": {"Source": "/srv/shop", "Destination": "/srv/www", "Type": "bind"}}}`),
		"var/lib/docker/containers/a1/hostconfig.json": text(`{"PortBindings": {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8101"}]}}`),
	}
	view := fstest.MapFS{"etc/nginx/nginx.conf": text("http { server { listen 80; server_name _; root /srv/www; } }")}
	defer func(orig func(collector.Source, int) (collector.Source, func())) { containerView = orig }(containerView)
	containerView = func(collector.Source, int) (collector.Source, func()) { return collector.Source{FS: view}, func() {} }

	inv := InspectWithContainers(collector.Source{FS: host})
	var shop Site
	for _, s := range inv.Sites {
		if s.Container == "shop-web-1" {
			shop = s
		}
	}
	if !slices.Equal(shop.Names, []string{"shop.example.com", "www.shop.example.com", "_"}) {
		t.Errorf("container site names = %v", shop.Names)
	}
	for _, a := range inv.Applications {
		if a.Path == "/srv/shop" && !slices.Equal(a.Sites, []string{"shop.example.com"}) {
			t.Errorf("application sites = %v", a.Sites)
		}
	}
}
