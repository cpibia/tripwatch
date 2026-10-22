package system

import (
	"context"
	"crypto/md5"  //nolint:gosec // dpkg records MD5 checksums; it is used to compare, not to protect
	"crypto/sha1" //nolint:gosec // apk records SHA-1 checksums; same reason
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

const maxMissingReported = 200

// maxPackageFileSize bounds checksumming: no packaged file comes close, and a sparse file of
// terabytes in its place would otherwise be read in full on every run.
const maxPackageFileSize = 1 << 30

// Package managers.
const (
	ManagerDpkg = "dpkg"
	ManagerApk  = "apk"
	ManagerRpm  = "rpm"
)

// binDirs are checked for executables no package owns.
var binDirs = []string{"usr/bin", "usr/sbin", "bin", "sbin", "usr/local/bin", "usr/local/sbin"}

// Paths commonly stripped from minimal images and containers: missing files there are noise.
var excludedMissing = []string{"usr/share/doc/", "usr/share/man/", "usr/share/locale/", "usr/share/info/", "usr/share/lintian/"}

type ModifiedFile struct {
	Path    string `json:"path"`
	Package string `json:"package"`
	Config  bool   `json:"config,omitempty"`
}

type PackagesResult struct {
	Manager  string           `json:"manager"`
	Packages int              `json:"packages"`
	Checked  int              `json:"checked"`
	Modified []ModifiedFile   `json:"modified"`
	Missing  []string         `json:"missing,omitempty"`
	Unowned  []string         `json:"unowned"`
	Hidden   []string         `json:"hidden"`
	Issues   collector.Issues `json:"issues,omitempty"`
}

// expectedFile is a file a package installed, with the checksum the package manager recorded.
type expectedFile struct {
	path     string
	pkg      string
	checksum string
	config   bool
}

// Packages verifies installed files against the package manager database, the way debsums
// or rpm -V do, and lists executables and hidden entries no package accounts for.
type Packages struct{}

func (Packages) Name() string { return "packages" }

func (Packages) Collect(ctx context.Context, src collector.Source) (any, error) {
	var res PackagesResult
	var expected []expectedFile
	var owned map[string]bool
	var newHash func() hash.Hash
	var encode func([]byte) string

	switch {
	case exists(src.FS, "var/lib/dpkg/status"):
		res.Manager = ManagerDpkg
		expected, owned, res.Packages = readDpkg(src.FS, &res.Issues)
		newHash, encode = md5.New, hex.EncodeToString
	case exists(src.FS, "lib/apk/db/installed"):
		res.Manager = ManagerApk
		expected, owned, res.Packages = readApk(src.FS, &res.Issues)
		newHash = sha1.New
		encode = func(b []byte) string { return "Q1" + base64.StdEncoding.EncodeToString(b) }
	case exists(src.FS, "var/lib/rpm"):
		res.Manager = ManagerRpm
		res.Issues = append(res.Issues, "rpm database verification is not implemented yet")
	default:
		return res, nil
	}

	for _, f := range expected {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sum, err := checksum(src.FS, f.path, newHash)
		switch {
		case isNotExist(err):
			if !slices.ContainsFunc(excludedMissing, func(p string) bool { return strings.HasPrefix(f.path, p) }) &&
				len(res.Missing) < maxMissingReported {
				res.Missing = append(res.Missing, "/"+f.path)
			}
			continue
		case err != nil:
			res.Issues.Add(err)
			continue
		}
		res.Checked++
		if encode(sum) != f.checksum {
			res.Modified = append(res.Modified, ModifiedFile{Path: "/" + f.path, Package: f.pkg, Config: f.config})
		}
	}

	res.Unowned = unownedExecutables(src.FS, owned)
	res.Hidden = hiddenEntries(src.FS)
	return res, nil
}

func checksum(fsys fs.FS, name string, newHash func() hash.Hash) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fs.ErrNotExist
	}
	if info.Size() > maxPackageFileSize {
		return nil, fmt.Errorf("%s: %w (%d bytes)", name, collector.ErrTooLarge, info.Size())
	}
	h := newHash()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// readDpkg reads the checksums from info/*.md5sums and the conffiles from the status file.
// Conffiles are reported as modified like any other file, flagged as config: editing them
// is normal administration, but the verifier still wants to see the change.
func readDpkg(fsys fs.FS, issues *collector.Issues) ([]expectedFile, map[string]bool, int) {
	diverted := dpkgDiversions(fsys)
	owned := map[string]bool{}
	var expected []expectedFile

	status, err := fs.ReadFile(fsys, "var/lib/dpkg/status")
	issues.Add(err)
	installed := 0
	for _, stanza := range strings.Split(string(status), "\n\n") {
		var pkg string
		isInstalled, inConffiles := false, false
		for _, line := range strings.Split(stanza, "\n") {
			switch {
			case strings.HasPrefix(line, "Package: "):
				pkg = strings.TrimPrefix(line, "Package: ")
			case strings.HasPrefix(line, "Status: "):
				isInstalled = strings.HasSuffix(line, " installed")
			case line == "Conffiles:":
				inConffiles = true
				continue
			}
			if inConffiles {
				if !strings.HasPrefix(line, " ") {
					inConffiles = false
					continue
				}
				fields := strings.Fields(line)
				// Conffiles no longer shipped are marked obsolete and have no meaningful checksum.
				if len(fields) >= 2 && isInstalled && !slices.Contains(fields[2:], "obsolete") {
					p := collector.Rel(fields[0])
					if !diverted[p] {
						expected = append(expected, expectedFile{path: p, pkg: pkg, checksum: fields[1], config: true})
					}
				}
			}
		}
		if isInstalled {
			installed++
		}
	}

	for _, name := range collector.Glob(fsys, "var/lib/dpkg/info/*.md5sums") {
		pkg := strings.TrimSuffix(path.Base(name), ".md5sums")
		lines, err := collector.ReadLines(fsys, name)
		issues.Add(err)
		for _, line := range lines {
			sum, file, ok := strings.Cut(line, "  ")
			if !ok {
				continue
			}
			p := collector.Rel(file)
			if !diverted[p] {
				expected = append(expected, expectedFile{path: p, pkg: pkg, checksum: sum})
			}
		}
	}

	for _, name := range collector.Glob(fsys, "var/lib/dpkg/info/*.list") {
		lines, err := collector.ReadLines(fsys, name)
		issues.Add(err)
		for _, line := range lines {
			if line != "" {
				addOwned(owned, line)
			}
		}
	}
	for p := range diverted {
		addOwned(owned, p)
	}
	return expected, owned, installed
}

// dpkgDiversions returns the original paths of diverted files: the file found there now
// belongs to another package, so the original checksum no longer applies.
func dpkgDiversions(fsys fs.FS) map[string]bool {
	lines, _ := collector.ReadLines(fsys, "var/lib/dpkg/diversions")
	out := map[string]bool{}
	for i := 0; i+2 < len(lines); i += 3 {
		out[collector.Rel(lines[i])] = true
	}
	return out
}

// readApk parses lib/apk/db/installed: P is the package, F a directory, R a file in it and
// Z the checksum of that file.
func readApk(fsys fs.FS, issues *collector.Issues) ([]expectedFile, map[string]bool, int) {
	lines, err := collector.ReadLines(fsys, "lib/apk/db/installed")
	issues.Add(err)

	owned := map[string]bool{}
	var expected []expectedFile
	var pkg, dir string
	installed := 0
	for _, line := range lines {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "P":
			pkg, dir = value, ""
			installed++
		case "F":
			dir = value
		case "R":
			p := path.Join(dir, value)
			addOwned(owned, p)
			expected = append(expected, expectedFile{path: p, pkg: pkg})
		case "Z":
			if n := len(expected); n > 0 && expected[n-1].pkg == pkg {
				expected[n-1].checksum = value
			}
		}
	}

	// Files without a recorded checksum (symlinks, for instance) cannot be verified.
	expected = slices.DeleteFunc(expected, func(f expectedFile) bool { return f.checksum == "" })
	return expected, owned, installed
}

// addOwned records a packaged path. On merged-/usr systems a package listing /bin/ls really
// installs /usr/bin/ls, so both spellings count as owned.
func addOwned(owned map[string]bool, p string) {
	p = collector.Rel(p)
	owned[p] = true
	for _, top := range []string{"bin/", "sbin/", "lib/", "lib64/", "lib32/"} {
		if strings.HasPrefix(p, top) {
			owned["usr/"+p] = true
		}
	}
}

func unownedExecutables(fsys fs.FS, owned map[string]bool) []string {
	out := []string{}
	for _, dir := range binDirs {
		if isSymlink(fsys, dir) {
			continue
		}
		entries, err := fs.ReadDir(fsys, dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			p := path.Join(dir, e.Name())
			if e.Type().IsRegular() && !owned[p] {
				out = append(out, "/"+p)
			}
		}
	}
	return out
}

// hiddenEntries lists dot-named files and directories under /usr, where packages do not put
// any and attackers like to hide tools in dot-directories.
func hiddenEntries(fsys fs.FS) []string {
	out := []string{}
	_ = fs.WalkDir(fsys, "usr", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") && name != "usr" {
			out = append(out, "/"+name)
			if d.IsDir() {
				return fs.SkipDir
			}
		}
		return nil
	})
	return out
}

func exists(fsys fs.FS, name string) bool {
	_, err := fs.Stat(fsys, name)
	return err == nil
}

func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
