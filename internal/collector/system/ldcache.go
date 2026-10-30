package system

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

// LoaderPaths are the directories the dynamic loader searches through its cache, and those its
// configuration names. "ldconfig /dir" bakes a directory into the cache without any file of the
// configuration naming it: a library placed there with the soname of a system one is loaded
// instead of it until ldconfig runs again without arguments.
type LoaderPaths struct {
	CacheDirs  []string `json:"cache_dirs"`
	ConfigDirs []string `json:"config_dirs"`
	// Libc lists where the cache puts libc.so.6, once per architecture on a sane system: the
	// verifier takes the system's own library directories from it rather than from a pattern a
	// directory created for the occasion can match. Never nil, so that an empty list is told
	// apart from a sensor that did not report it.
	Libc []LibcCopy `json:"libc"`
	// Native is the flags of a libc6 entry for the architecture the sensor runs on: a libc of
	// another one, a 32-bit copy put in a directory of its own, tells nothing of where the
	// system's libraries are.
	Native uint32 `json:"native,omitempty"`
	// Truncated says the cache or the configuration held more than the bounds read;
	// ConfigTruncated that the configuration did, so that what it names is incomplete.
	Truncated       bool `json:"truncated,omitempty"`
	ConfigTruncated bool `json:"config_truncated,omitempty"`
}

// LibcCopy is a libc.so.6 the cache lists: its directory and the entry's flags, which carry
// the library's type and architecture.
type LibcCopy struct {
	Dir   string `json:"dir"`
	Flags uint32 `json:"flags"`
}

// Bounds on what is read of the loader's cache and configuration: real caches list a few
// thousand libraries in a few dozen directories.
const (
	maxCacheEntries   = 65536
	maxLoaderDirs     = 512
	maxLoaderConfFile = 256
	maxIncludeDepth   = 8
)

var (
	oldCacheMagic = []byte("ld.so-1.7.0")
	newCacheMagic = []byte("glibc-ld.so.cache1.1")
	errCache      = errors.New("ld.so.cache: unknown or damaged format")
)

// Sizes of glibc's cache structures (dl-cache.h): the old header and entries, kept before the
// new format for compatibility by older ldconfig versions, then the new header and entries.
const (
	oldHeaderSize = 16
	oldEntrySize  = 12
	newHeaderSize = 48
	newEntrySize  = 24
)

// readLoaderPaths reads the cache and the configuration; it returns nil where there is no cache
// (musl, or a system without ldconfig).
func readLoaderPaths(fsys fs.FS, issues *collector.Issues) *LoaderPaths {
	data, err := fs.ReadFile(fsys, "etc/ld.so.cache")
	if errors.Is(err, collector.ErrTooLarge) {
		// The loader still uses a cache past what is read: that it is too large is reported,
		// with the configuration, instead of nothing.
		issues.Add(err)
		lp := &LoaderPaths{Libc: []LibcCopy{}, Native: nativeLibcFlags, Truncated: true}
		files := 0
		lp.ConfigTruncated = loaderConfig(fsys, "etc/ld.so.conf", 0, &files, map[string]bool{}, &lp.ConfigDirs)
		slices.Sort(lp.ConfigDirs)
		return lp
	}
	if err != nil {
		issues.Add(err)
		return nil
	}
	lp := &LoaderPaths{Native: nativeLibcFlags}
	lp.CacheDirs, lp.Libc, lp.Truncated, err = cacheDirs(data)
	if err != nil {
		issues.Add(err)
		return nil
	}
	seen := map[string]bool{}
	files := 0
	lp.ConfigTruncated = loaderConfig(fsys, "etc/ld.so.conf", 0, &files, seen, &lp.ConfigDirs)
	lp.Truncated = lp.Truncated || lp.ConfigTruncated
	slices.Sort(lp.ConfigDirs)
	return lp
}

// cacheDirs lists the directories of the libraries in a cache of glibc's new format, alone or
// after the old one, and the copies of libc.so.6 in it. Integers are in the machine's order:
// the sensor runs where the cache was written, and only on little-endian architectures.
func cacheDirs(data []byte) (dirs []string, libc []LibcCopy, truncated bool, err error) {
	base := 0
	if bytes.HasPrefix(data, oldCacheMagic) {
		if len(data) < oldHeaderSize {
			return nil, nil, false, errCache
		}
		n := int(binary.LittleEndian.Uint32(data[12:]))
		if n > maxCacheEntries {
			return nil, nil, false, errCache
		}
		base = oldHeaderSize + n*oldEntrySize
		base = (base + 7) &^ 7
	}
	if base+newHeaderSize > len(data) || !bytes.Equal(data[base:base+len(newCacheMagic)], newCacheMagic) {
		return nil, nil, false, errCache
	}
	n := int(binary.LittleEndian.Uint32(data[base+20:]))
	if n > maxCacheEntries {
		n, truncated = maxCacheEntries, true
	}
	// String offsets count from the start of the new header.
	strs := data[base:]
	seen := map[string]bool{}
	libc = []LibcCopy{}
	for i := range n {
		at := base + newHeaderSize + i*newEntrySize
		if at+newEntrySize > len(data) {
			return nil, nil, false, errCache
		}
		off := int(binary.LittleEndian.Uint32(data[at+8:]))
		if off <= 0 || off >= len(strs) {
			return nil, nil, false, errCache
		}
		end := bytes.IndexByte(strs[off:], 0)
		if end < 0 {
			return nil, nil, false, errCache
		}
		file := string(strs[off : off+end])
		dir := path.Dir(file)
		// Past the bound on directories the entries are still read for libc: a cache padded
		// with directories must not hide where the system's libraries are.
		if path.Base(file) == "libc.so.6" && len(libc) < maxLoaderDirs {
			libc = append(libc, LibcCopy{Dir: dir, Flags: binary.LittleEndian.Uint32(data[at:])})
		}
		if !seen[dir] {
			if len(dirs) == maxLoaderDirs {
				truncated = true
				continue
			}
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	slices.Sort(dirs)
	return dirs, libc, truncated, nil
}

// loaderConfig collects the directories a configuration file names, following its includes as
// ldconfig does (glob patterns, relative to the file's directory). It reports whether a bound
// left part of it unread.
func loaderConfig(fsys fs.FS, name string, depth int, files *int, seen map[string]bool, dirs *[]string) bool {
	if depth > maxIncludeDepth || *files >= maxLoaderConfFile {
		return true
	}
	*files++
	lines, _ := collector.ReadLines(fsys, name)
	truncated := false
	for _, line := range lines {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == ':' || r == ',' })
		if len(fields) == 0 || fields[0] == "hwcap" {
			continue
		}
		if fields[0] == "include" {
			for _, pattern := range fields[1:] {
				if !strings.HasPrefix(pattern, "/") {
					pattern = path.Join("/", path.Dir(name), pattern)
				}
				for _, inc := range collector.Glob(fsys, strings.TrimPrefix(path.Clean(pattern), "/")) {
					truncated = loaderConfig(fsys, inc, depth+1, files, seen, dirs) || truncated
				}
			}
			continue
		}
		for _, f := range fields {
			// Old configurations could follow a directory with "=TYPE".
			dir, _, _ := strings.Cut(f, "=")
			if dir = path.Clean(dir); strings.HasPrefix(dir, "/") && !seen[dir] {
				if len(*dirs) == maxLoaderDirs {
					return true
				}
				seen[dir] = true
				*dirs = append(*dirs, dir)
			}
		}
	}
	return truncated
}
