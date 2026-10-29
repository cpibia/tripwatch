package system

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
)

// systemHooks are files and directories that make code run at boot, at login, when a library
// is loaded, when a package is installed or when a network interface comes up: common places to
// hide persistence.
var systemHooks = []string{
	"etc/ld.so.preload",
	"etc/ld.so.conf",
	"etc/ld.so.conf.d/*",
	"etc/rc.local",
	"etc/rc.d/rc.local",
	"etc/init.d/*",
	"etc/profile",
	"etc/profile.d/*",
	"etc/bash.bashrc",
	"etc/bashrc",
	"etc/environment",
	"etc/pam.d/*",
	"etc/security/pam_env.conf",
	"etc/nsswitch.conf",
	"etc/hosts",
	"etc/resolv.conf",
	"etc/modules",
	"etc/modules-load.d/*",
	"etc/modprobe.d/*",
	"etc/udev/rules.d/*",
	"etc/update-motd.d/*",
	"etc/apt/apt.conf.d/*",
	"etc/yum/pluginconf.d/*",
	"etc/logrotate.d/*",
	"etc/xdg/autostart/*",
	"etc/sudo.conf",
	"etc/ssh/sshrc",
	"etc/bash_completion.d/*",
	"etc/network/interfaces",
	"etc/network/interfaces.d/*",
	"etc/network/if-*.d/*",
	"etc/NetworkManager/dispatcher.d/*",
	"etc/NetworkManager/dispatcher.d/*/*",
	"etc/networkd-dispatcher/*/*",
	"etc/dhcp/dhclient-enter-hooks.d/*",
	"etc/dhcp/dhclient-exit-hooks.d/*",
	"etc/ppp/ip-*.d/*",
}

var userHooks = []string{
	".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile",
	".config/autostart/*", ".ssh/rc",
}

// Bounds on the files described for one pattern: an account can fill its own
// .config/autostart by the thousand, and a snapshot that grows past what the verifier accepts
// is lost whole. The system's directories are root's, and hold a few dozen files each.
const (
	maxSystemHookFiles = 1024
	maxUserHookFiles   = 64
)

type HooksResult struct {
	Files []collector.File `json:"files"`
	// Preload lists the libraries in /etc/ld.so.preload, injected into every process.
	Preload []string `json:"preload,omitempty"`
	// Loader is where the dynamic loader looks for libraries, by its cache and its
	// configuration.
	Loader *LoaderPaths     `json:"loader,omitempty"`
	Issues collector.Issues `json:"issues,omitempty"`
}

// Hooks collects startup, login and loader hooks, system-wide and in every home directory.
type Hooks struct{}

func (Hooks) Name() string { return "hooks" }

func (Hooks) Collect(ctx context.Context, src collector.Source) (any, error) {
	var res HooksResult

	accounts, err := readAccounts(src, &res.Issues)
	if err != nil {
		return nil, err
	}

	type bounded struct {
		pattern string
		limit   int
	}
	patterns := make([]bounded, 0, len(systemHooks))
	for _, p := range systemHooks {
		patterns = append(patterns, bounded{p, maxSystemHookFiles})
	}
	for _, home := range homes(accounts) {
		for _, h := range userHooks {
			patterns = append(patterns, bounded{path.Join(home, h), maxUserHookFiles})
		}
	}

	for _, p := range patterns {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		names := collector.Glob(src.FS, p.pattern)
		if len(names) > p.limit {
			res.Issues = append(res.Issues, fmt.Sprintf("/%s: %d files, only the first %d described", p.pattern, len(names), p.limit))
			names = names[:p.limit]
		}
		for _, name := range names {
			res.Files = appendDescribed(res.Files, &res.Issues, src, name)
			// The verifier tells a file there all along from one written and dated back by it. A
			// link takes the later of its own change time and its target's: a link made now to a
			// file written long ago is new, and so is an old link whose target was just rewritten.
			if info, err := fs.Stat(src.FS, name); err == nil && len(res.Files) > 0 && res.Files[len(res.Files)-1].Path == "/"+name {
				f := &res.Files[len(res.Files)-1]
				if ns, ok := collector.ChangeTime(info); ok {
					f.ChangeTime = time.Unix(0, ns).UTC()
				}
				if link, err := fs.Lstat(src.FS, name); err == nil && link.Mode()&fs.ModeSymlink != 0 {
					if ns, ok := collector.ChangeTime(link); ok && time.Unix(0, ns).After(f.ChangeTime) {
						f.ChangeTime = time.Unix(0, ns).UTC()
					}
					f.Link, _ = fs.ReadLink(src.FS, name)
				}
			}
		}
	}

	res.Loader = readLoaderPaths(src.FS, &res.Issues)

	preload, err := collector.ReadLines(src.FS, "etc/ld.so.preload")
	res.Issues.Add(err)
	if len(preload) > 0 {
		res.Preload = directives(preload)
	}
	return res, nil
}
