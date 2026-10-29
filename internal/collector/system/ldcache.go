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
	// Truncated says the cache or the configuration held more than the bounds read.
	Truncated bool `json:"truncated,omitempty"`
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
	if err != nil {
		issues.Add(err)
		return nil
	}
	lp := &LoaderPaths{}
	lp.CacheDirs, lp.Truncated, err = cacheDirs(data)
	if err != nil {
		issues.Add(err)
		return nil
	}
	seen := map[string]bool{}
	files := 0
	lp.Truncated = loaderConfig(fsys, "etc/ld.so.conf", 0, &files, seen, &lp.ConfigDirs) || lp.Truncated
	slices.Sort(lp.ConfigDirs)
	return lp
}

// cacheDirs lists the directories of the libraries in a cache of glibc's new format, alone or
// after the old one. Integers are in the machine's order: the sensor runs where the cache was
// written, and only on little-endian architectures.
func cacheDirs(data []byte) (dirs []string, truncated bool, err error) {
	base := 0
	if bytes.HasPrefix(data, oldCacheMagic) {
		if len(data) < oldHeaderSize {
			return nil, false, errCache
		}
		n := int(binary.LittleEndian.Uint32(data[12:]))
		if n > maxCacheEntries {
			return nil, false, errCache
		}
		base = oldHeaderSize + n*oldEntrySize
		base = (base + 7) &^ 7
	}
	if base+newHeaderSize > len(data) || !bytes.Equal(data[base:base+len(newCacheMagic)], newCacheMagic) {
		return nil, false, errCache
	}
	n := int(binary.LittleEndian.Uint32(data[base+20:]))
	if n > maxCacheEntries {
		n, truncated = maxCacheEntries, true
	}
	// String offsets count from the start of the new header.
	strs := data[base:]
	seen := map[string]bool{}
	for i := range n {
		at := base + newHeaderSize + i*newEntrySize
		if at+newEntrySize > len(data) {
			return nil, false, errCache
		}
		off := int(binary.LittleEndian.Uint32(data[at+8:]))
		if off <= 0 || off >= len(strs) {
			return nil, false, errCache
		}
		end := bytes.IndexByte(strs[off:], 0)
		if end < 0 {
			return nil, false, errCache
		}
		dir := path.Dir(string(strs[off : off+end]))
		if !seen[dir] {
			if len(dirs) == maxLoaderDirs {
				truncated = true
				break
			}
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	slices.Sort(dirs)
	return dirs, truncated, nil
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
