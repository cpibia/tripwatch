package system

import (
	"context"
	"path"

	"github.com/cpibia/tripwatch/internal/collector"
)

// systemHooks are files and directories that make code run at boot, at login, when a library
// is loaded or when a package is installed: common places to hide persistence.
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
}

var userHooks = []string{
	".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile",
	".config/autostart/*",
}

type HooksResult struct {
	Files []collector.File `json:"files"`
	// Preload lists the libraries in /etc/ld.so.preload, injected into every process.
	Preload []string         `json:"preload,omitempty"`
	Issues  collector.Issues `json:"issues,omitempty"`
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

	patterns := append([]string{}, systemHooks...)
	for _, home := range homes(accounts) {
		for _, h := range userHooks {
			patterns = append(patterns, path.Join(home, h))
		}
	}

	for _, pattern := range patterns {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, name := range collector.Glob(src.FS, pattern) {
			res.Files = appendDescribed(res.Files, &res.Issues, src, name)
		}
	}

	preload, err := collector.ReadLines(src.FS, "etc/ld.so.preload")
	res.Issues.Add(err)
	if len(preload) > 0 {
		res.Preload = directives(preload)
	}
	return res, nil
}
