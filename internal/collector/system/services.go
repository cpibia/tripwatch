package system

import (
	"context"
	"io/fs"
	"path"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

var systemUnitDirs = []string{
	"etc/systemd/system",
	"run/systemd/system",
	"usr/lib/systemd/system",
	"lib/systemd/system",
	"usr/local/lib/systemd/system",
	"etc/systemd/user",
	"usr/lib/systemd/user",
}

var unitExtensions = []string{".service", ".timer", ".socket", ".path", ".mount", ".target"}

// Unit is a unit file or a drop-in override. Exec holds every Exec*= line, the commands the
// unit actually runs.
type Unit struct {
	collector.File
	Exec []string `json:"exec,omitempty"`
	User string   `json:"user,omitempty"`
}

// Link is a symlink in a unit directory: enablement (in *.wants) or masking (to /dev/null).
type Link struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

type ServicesResult struct {
	Units  []Unit           `json:"units"`
	Links  []Link           `json:"links"`
	Issues collector.Issues `json:"issues,omitempty"`
}

// Services collects systemd units, drop-ins and enablement links, system-wide and per user.
type Services struct{}

func (Services) Name() string { return "services" }

func (Services) Collect(ctx context.Context, src collector.Source) (any, error) {
	var res ServicesResult

	accounts, err := readAccounts(src, &res.Issues)
	if err != nil {
		return nil, err
	}

	dirs := []string{}
	for _, dir := range systemUnitDirs {
		// On merged-/usr systems lib is a symlink to usr/lib: walking it would list every unit twice.
		if dir == "lib/systemd/system" && isSymlink(src.FS, "lib") {
			continue
		}
		dirs = append(dirs, dir)
	}
	for _, home := range homes(accounts) {
		dirs = append(dirs, path.Join(home, ".config/systemd/user"))
	}

	for _, dir := range dirs {
		err := fs.WalkDir(src.FS, dir, func(name string, d fs.DirEntry, err error) error {
			if err != nil {
				if name != dir {
					res.Issues.Add(err)
				}
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			switch {
			case d.Type()&fs.ModeSymlink != 0:
				target, err := fs.ReadLink(src.FS, name)
				res.Issues.Add(err)
				res.Links = append(res.Links, Link{Path: "/" + name, Target: target})
			case d.Type().IsRegular() && isUnitFile(name):
				res.addUnit(src, name, d)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (res *ServicesResult) addUnit(src collector.Source, name string, d fs.DirEntry) {
	f, err := collector.DescribeEntry(src, name, d)
	res.Issues.Add(err)
	if f.Path == "" {
		return
	}
	lines, err := collector.ReadLines(src.FS, name)
	res.Issues.Add(err)

	u := Unit{File: f}
	for _, line := range directives(lines, "#") {
		if strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		switch {
		case strings.HasPrefix(key, "Exec"):
			u.Exec = append(u.Exec, key+"="+strings.TrimSpace(value))
		case key == "User":
			u.User = strings.TrimSpace(value)
		}
	}
	res.Units = append(res.Units, u)
}

// isUnitFile matches unit files and drop-in overrides (foo.service.d/override.conf), which
// can replace ExecStart without touching the original unit.
func isUnitFile(name string) bool {
	if strings.HasSuffix(name, ".conf") && strings.HasSuffix(path.Dir(name), ".d") {
		return true
	}
	for _, ext := range unitExtensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

func isSymlink(fsys fs.FS, name string) bool {
	info, err := fs.Lstat(fsys, name)
	if err != nil {
		return false
	}
	return info.Mode()&fs.ModeSymlink != 0
}
