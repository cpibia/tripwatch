package collector

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// MaxReadSize bounds ReadFile: configuration files, crontabs and keys are small, and anything
// larger is either an attack on the sensor or not what the caller expects.
const MaxReadSize = 16 << 20

var (
	// ErrNotRegular is returned when opening something that is neither a regular file nor a
	// directory: a FIFO would block a reader forever and a device such as /dev/zero never ends.
	ErrNotRegular = errors.New("not a regular file or directory")
	// ErrTooLarge is returned by ReadFile for files over MaxReadSize.
	ErrTooLarge = errors.New("file too large to read")
)

// rootFS is a read-only view of a directory tree that is safe against files planted by an
// unprivileged attacker. Every open is non-blocking and checked with fstat on the opened
// descriptor, so swapping a file for a FIFO or a device between listing and opening does not
// help; ReadFile refuses files over MaxReadSize; on Linux, symlinks are resolved inside the
// root (see openInRoot).
type rootFS struct {
	dir string
}

func (r rootFS) path(name string) (string, error) {
	if !fs.ValidPath(name) {
		return "", fs.ErrInvalid
	}
	return filepath.Join(r.dir, filepath.FromSlash(name)), nil
}

// openAny opens name without restricting its type.
func (r rootFS) openAny(op, name string) (*os.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	f, err := openInRoot(r.dir, name)
	if err != nil {
		return nil, &fs.PathError{Op: op, Path: name, Err: unwrapPathError(err)}
	}
	return f, nil
}

func (r rootFS) Open(name string) (fs.File, error) {
	f, err := r.openAny("open", name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		_ = f.Close()
		return nil, &fs.PathError{Op: "open", Path: name, Err: ErrNotRegular}
	}
	return f, nil
}

func (r rootFS) Stat(name string) (fs.FileInfo, error) {
	f, err := r.openAny("stat", name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return f.Stat()
}

func (r rootFS) ReadFile(name string) ([]byte, error) {
	f, err := r.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, &fs.PathError{Op: "read", Path: name, Err: errors.New("is a directory")}
	}
	if info.Size() > MaxReadSize {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fmt.Errorf("%w (%d bytes)", ErrTooLarge, info.Size())}
	}
	// The size can grow after fstat: the limit applies to what is actually read.
	data, err := io.ReadAll(io.LimitReader(f, MaxReadSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxReadSize {
		return nil, &fs.PathError{Op: "read", Path: name, Err: ErrTooLarge}
	}
	return data, nil
}

func (r rootFS) ReadDir(name string) ([]fs.DirEntry, error) {
	f, err := r.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	dir, ok := f.(*os.File)
	if !ok {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	return dir.ReadDir(-1)
}

func (r rootFS) ReadLink(name string) (string, error) {
	p, err := r.path(name)
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: err}
	}
	return os.Readlink(p)
}

func (r rootFS) Lstat(name string) (fs.FileInfo, error) {
	p, err := r.path(name)
	if err != nil {
		return nil, &fs.PathError{Op: "lstat", Path: name, Err: err}
	}
	return os.Lstat(p)
}

func unwrapPathError(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
