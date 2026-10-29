package collector

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// MaxHashSize bounds how much of a file is read to hash it. Larger files are reported without
// a hash, with an explicit error, rather than stalling the collection: a sparse file of
// terabytes costs nothing to create and hours to read.
const MaxHashSize = 512 << 20

// ErrAttrsUnsupported is returned where inode flags cannot be read.
var ErrAttrsUnsupported = errors.New("collector: file attributes not supported on this platform")

// Attrs are inode-level properties that io/fs does not expose.
type Attrs struct {
	Immutable    bool `json:"immutable,omitempty"`
	AppendOnly   bool `json:"append_only,omitempty"`
	Capabilities bool `json:"capabilities,omitempty"`
	// ACL fingerprints the file's extended POSIX ACLs, empty when it has none: an ACL can let
	// another account write a file whose mode says it cannot.
	ACL string `json:"acl,omitempty"`
	// ACLWrite is set when an ACL entry for a named user or group, through the mask, allows
	// writing.
	ACLWrite bool `json:"acl_write,omitempty"`
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
	// Root is the directory FS is rooted at on the machine running the sensor, for the few
	// things that cannot go through FS, such as connecting to a Unix socket. Empty in tests.
	Root string
}

// NewSource observes the filesystem rooted at dir through a view that unprivileged users
// cannot use to block or exhaust the sensor (see rootFS).
func NewSource(dir string) Source {
	return Source{
		Root:  dir,
		FS:    rootFS{dir: dir},
		Attrs: func(name string) (Attrs, error) { return attrsIn(dir, name) },
	}
}

// ContainerSource observes the filesystem a container's process sees, through
// /proc/<pid>/root: its image with the volumes and directories mounted in it, links resolved
// inside it. release frees the root, which is held open until then.
func ContainerSource(src Source, pid int) (view Source, release func()) {
	dir := filepath.Join(cmp.Or(src.Root, "/"), "proc", strconv.Itoa(pid), "root")
	return NewSource(dir), func() { releaseRoot(dir) }
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
	// ChangeTime is the inode's change time, which no one sets back short of changing the
	// clock: set where telling an old file from one dated back matters.
	ChangeTime time.Time `json:"ctime,omitzero"`
	SHA256     string    `json:"sha256,omitempty"`
	// Link is where the path leads when it is a symlink, set where it matters: the rest of
	// the description is then the target's.
	Link string `json:"link,omitempty"`
	// Mount names, for a file on a filesystem an unprivileged user mounted (FUSE), its type and
	// the user: the owner and mode it reports are whatever that user chose.
	Mount string `json:"mount,omitempty"`
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

// DescribeNoFollow is Describe without following a final symlink: a link is described as a link
// and what it points to is never opened.
func DescribeNoFollow(src Source, name string) (File, error) {
	info, err := fs.Lstat(src.FS, name)
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

// Metadata describes a file from its FileInfo alone, without opening it.
func Metadata(name string, info fs.FileInfo) File {
	f := File{Path: "/" + name, Mode: info.Mode().String(), Size: info.Size(), ModTime: info.ModTime().UTC()}
	f.UID, f.GID = owner(info)
	return f
}

func describeInfo(src Source, name string, info fs.FileInfo) (File, error) {
	f := File{
		Path:    "/" + name,
		Mode:    info.Mode().String(),
		Size:    info.Size(),
		ModTime: info.ModTime().UTC(),
	}
	f.UID, f.GID = owner(info)

	if src.Attrs != nil && (info.Mode().IsRegular() || info.IsDir()) {
		if attrs, err := src.Attrs(name); err == nil {
			f.Attrs = attrs
		}
	}

	if info.Mode().IsRegular() && info.Size() > MaxHashSize {
		return f, fmt.Errorf("%s not hashed: %w (%d bytes)", f.Path, ErrTooLarge, info.Size())
	}
	if info.Mode().IsRegular() {
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

const maxResolveLinks = 40

// ResolvePath follows the symlinks of name inside fsys component by component, the way the
// kernel would with the observed root as "/", and returns where it leads ("." for the root).
// It is for decisions that depend on the final location, such as whether a linked directory
// stays inside an application: comparing the text of a link target is not enough when the
// target itself goes through further links.
func ResolvePath(fsys fs.FS, name string) (string, error) {
	pending := strings.Split(name, "/")
	cur := ""
	links := 0
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if cur = path.Dir(cur); cur == "." {
				cur = ""
			}
			continue
		}
		next := path.Join(cur, part)
		info, err := fs.Lstat(fsys, next)
		if err != nil {
			return "", err
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		if links++; links > maxResolveLinks {
			return "", fmt.Errorf("resolve %s: too many links", name)
		}
		target, err := fs.ReadLink(fsys, next)
		if err != nil {
			return "", err
		}
		if path.IsAbs(target) {
			cur = ""
		}
		pending = append(strings.Split(strings.TrimPrefix(target, "/"), "/"), pending...)
	}
	if cur == "" {
		return ".", nil
	}
	return cur, nil
}
