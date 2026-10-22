package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// MaxHashSize bounds how much of a file is read to hash it; larger files are reported
// without a hash rather than stalling the collection.
const MaxHashSize = 64 << 20

// ErrAttrsUnsupported is returned where inode flags cannot be read.
var ErrAttrsUnsupported = errors.New("collector: file attributes not supported on this platform")

// Attrs are inode-level properties that io/fs does not expose.
type Attrs struct {
	Immutable    bool `json:"immutable,omitempty"`
	AppendOnly   bool `json:"append_only,omitempty"`
	Capabilities bool `json:"capabilities,omitempty"`
}

// Any reports whether any attribute is set.
func (a Attrs) Any() bool {
	return a.Immutable || a.AppendOnly || a.Capabilities
}

// Source is the filesystem the collectors observe. Paths are relative to its root, as io/fs
// requires.
type Source struct {
	FS    fs.FS
	Attrs func(name string) (Attrs, error)
}

// NewSource observes the filesystem rooted at dir through a view that unprivileged users
// cannot use to block or exhaust the sensor (see rootFS).
func NewSource(dir string) Source {
	return Source{
		FS: rootFS{dir: dir},
		Attrs: func(name string) (Attrs, error) {
			return ReadAttrs(filepath.Join(dir, filepath.FromSlash(name)))
		},
	}
}

// Rel converts an absolute path, as found in configuration files, to a Source path.
func Rel(p string) string {
	p = strings.TrimPrefix(path.Clean("/"+p), "/")
	if p == "" {
		return "."
	}
	return p
}

// File describes a file on the observed machine.
type File struct {
	Path    string    `json:"path"`
	Mode    string    `json:"mode"`
	UID     *uint32   `json:"uid,omitempty"`
	GID     *uint32   `json:"gid,omitempty"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mtime"`
	SHA256  string    `json:"sha256,omitempty"`
	Attrs
}

// Describe stats name and hashes it when it is a regular file. Symlinks are followed.
func Describe(src Source, name string) (File, error) {
	info, err := fs.Stat(src.FS, name)
	if err != nil {
		return File{}, err
	}
	return describeInfo(src, name, info)
}

// DescribeEntry is Describe for an entry found while walking, without following symlinks.
func DescribeEntry(src Source, name string, d fs.DirEntry) (File, error) {
	info, err := d.Info()
	if err != nil {
		return File{}, err
	}
	return describeInfo(src, name, info)
}

func describeInfo(src Source, name string, info fs.FileInfo) (File, error) {
	f := File{
		Path:    "/" + name,
		Mode:    info.Mode().String(),
		Size:    info.Size(),
		ModTime: info.ModTime().UTC(),
	}
	f.UID, f.GID = owner(info)

	if src.Attrs != nil {
		if attrs, err := src.Attrs(name); err == nil {
			f.Attrs = attrs
		}
	}

	if info.Mode().IsRegular() && info.Size() <= MaxHashSize {
		sum, err := hashFile(src.FS, name)
		if err != nil {
			return f, fmt.Errorf("hash %s: %w", f.Path, err)
		}
		f.SHA256 = sum
	}
	return f, nil
}

func hashFile(fsys fs.FS, name string) (string, error) {
	r, err := fsys.Open(name)
	if err != nil {
		return "", err
	}
	defer func() { _ = r.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(r, MaxHashSize)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ReadLines returns the content of name split into lines. A missing file yields no lines
// and no error, since most of the locations collectors check are optional.
func ReadLines(fsys fs.FS, name string) ([]string, error) {
	data, err := fs.ReadFile(fsys, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n"), nil
}

// Glob is fs.Glob limited to regular files and symlinks, sorted.
func Glob(fsys fs.FS, pattern string) []string {
	matches, _ := fs.Glob(fsys, pattern)
	var out []string
	for _, m := range matches {
		if info, err := fs.Stat(fsys, m); err == nil && !info.IsDir() {
			out = append(out, m)
		}
	}
	return out
}

// Issues accumulates non-fatal problems met during a collection, such as unreadable files.
type Issues []string

// Add records err unless it only says the file does not exist.
func (is *Issues) Add(err error) {
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		*is = append(*is, err.Error())
	}
}
