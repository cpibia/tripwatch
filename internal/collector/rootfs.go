package collector

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
)

// MaxReadSize bounds ReadFile: configuration files, crontabs and keys are small, and anything
// larger is either an attack on the sensor or not what the caller expects.
const MaxReadSize = 16 << 20

// MaxDirEntries bounds ReadDir: a directory with millions of entries is reported, not loaded.
// Collectors that do not need a sorted listing stream large directories instead.
var MaxDirEntries = 200_000

var (
	// ErrNotRegular is returned when opening something that is neither a regular file nor a
	// directory: a FIFO would block a reader forever and a device such as /dev/zero never ends.
	ErrNotRegular = errors.New("not a regular file or directory")
	// ErrTooLarge is returned by ReadFile for files over MaxReadSize.
	ErrTooLarge = errors.New("file too large to read")
	// ErrTooManyEntries is returned with the first MaxDirEntries entries of a larger directory.
	ErrTooManyEntries = errors.New("directory has too many entries, listing truncated")
)

// rootFS is a read-only view of a directory tree that is safe against files planted by an
// unprivileged attacker: only regular files and directories are ever opened, their type is
// checked on the descriptor, reads are bounded, and on Linux symlinks are resolved inside the
// root. The platform files provide statIn, openIn, lstatIn and readlinkIn.
type rootFS struct {
	dir string
}

func pathError(op, name string, err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return &fs.PathError{Op: op, Path: name, Err: err}
}

func (r rootFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, pathError("open", name, fs.ErrInvalid)
	}
	f, _, err := openIn(r.dir, name)
	if err != nil {
		return nil, pathError("open", name, err)
	}
	return f, nil
}

func (r rootFS) Stat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, pathError("stat", name, fs.ErrInvalid)
	}
	info, err := statIn(r.dir, name)
	if err != nil {
		return nil, pathError("stat", name, err)
	}
	return info, nil
}

func (r rootFS) ReadFile(name string) ([]byte, error) {
	if !fs.ValidPath(name) {
		return nil, pathError("read", name, fs.ErrInvalid)
	}
	f, info, err := openIn(r.dir, name)
	if err != nil {
		return nil, pathError("read", name, err)
	}
	defer func() { _ = f.Close() }()

	if info.IsDir() {
		return nil, pathError("read", name, errors.New("is a directory"))
	}
	if info.Size() > MaxReadSize {
		return nil, pathError("read", name, fmt.Errorf("%w (%d bytes)", ErrTooLarge, info.Size()))
	}
	// The size can grow after fstat: the limit applies to what is actually read, and a file
	// over it is an error, never a silently shortened result.
	data, err := io.ReadAll(io.LimitReader(f, MaxReadSize+1))
	if err != nil {
		return nil, pathError("read", name, err)
	}
	if len(data) > MaxReadSize {
		return nil, pathError("read", name, ErrTooLarge)
	}
	return data, nil
}

func (r rootFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, pathError("readdir", name, fs.ErrInvalid)
	}
	f, info, err := openIn(r.dir, name)
	if err != nil {
		return nil, pathError("readdir", name, err)
	}
	defer func() { _ = f.Close() }()
	if !info.IsDir() {
		return nil, pathError("readdir", name, errors.New("not a directory"))
	}

	var entries []fs.DirEntry
	var readErr error
	for {
		batch, err := f.ReadDir(4096)
		entries = append(entries, batch...)
		if errors.Is(err, io.EOF) || (err == nil && len(batch) == 0) {
			break
		}
		if err != nil {
			readErr = err
			break
		}
		if len(entries) > MaxDirEntries {
			entries = entries[:MaxDirEntries]
			readErr = ErrTooManyEntries
			break
		}
	}
	// fs.ReadDirFS requires sorted entries; the code tree hash depends on a stable order.
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	for i, e := range entries {
		entries[i] = confinedEntry{DirEntry: e, fsys: r, name: path.Join(name, e.Name())}
	}
	if readErr != nil {
		return entries, pathError("readdir", name, readErr)
	}
	return entries, nil
}

// confinedEntry answers Info through the confined Lstat: the standard entry would lstat a
// path built from the directory's name, outside the root's resolution rules.
type confinedEntry struct {
	fs.DirEntry
	fsys rootFS
	name string
}

func (e confinedEntry) Info() (fs.FileInfo, error) {
	return e.fsys.Lstat(e.name)
}

func (r rootFS) ReadLink(name string) (string, error) {
	if !fs.ValidPath(name) {
		return "", pathError("readlink", name, fs.ErrInvalid)
	}
	target, err := readlinkIn(r.dir, name)
	if err != nil {
		return "", pathError("readlink", name, err)
	}
	return target, nil
}

func (r rootFS) Lstat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, pathError("lstat", name, fs.ErrInvalid)
	}
	info, err := lstatIn(r.dir, name)
	if err != nil {
		return nil, pathError("lstat", name, err)
	}
	return info, nil
}
