package system

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
)

// Decoys reports the state of the decoy files the operator named: files nothing legitimate reads,
// whose read is an alert in real time. Only their metadata is taken, never their content: the
// sensor reading a decoy would report itself. An intruder who finds one and removes or rewrites it
// changes what this reports.
type Decoys struct {
	Paths []string
	// Err is why the decoys' configuration could not be read: reported with an empty list, so the
	// verifier sees the decoys it knew go.
	Err error
}

// DecoyState is one decoy as a snapshot finds it.
type DecoyState struct {
	Path       string    `json:"path"`
	Missing    bool      `json:"missing,omitempty"`
	Size       int64     `json:"size,omitempty"`
	Mode       string    `json:"mode,omitempty"`
	ModTime    time.Time `json:"mtime,omitzero"`
	ChangeTime int64     `json:"ctime,omitempty"`
	Inode      uint64    `json:"inode,omitempty"`
	// Links counts the file's hard links: a second one is another path to the decoy, which the
	// sensor never reads either.
	Links uint64 `json:"links,omitempty"`
}

// DecoysResult is the decoys' state.
type DecoysResult struct {
	Decoys []DecoyState `json:"decoys"`
	// Aliases are the other paths a collector or watcher found leading to a decoy, and left unread.
	Aliases []string `json:"aliases,omitempty"`
}

// maxDecoys bounds the decoys watched.
const maxDecoys = 100

func (Decoys) Name() string { return "decoys" }

// Refresh records the decoys' current files, so that no collector or watcher opens them. The
// sensor calls it once before it reads anything, and each snapshot again: a decoy put back by
// another file is that file.
func (d Decoys) Refresh(src collector.Source) []string {
	var rel []string
	for _, p := range d.Paths[:min(len(d.Paths), maxDecoys)] {
		rel = append(rel, strings.TrimPrefix(path.Clean("/"+p), "/"))
	}
	collector.SetDecoys(src, rel)
	return rel
}

func (d Decoys) Collect(_ context.Context, src collector.Source) (any, error) {
	rel := d.Refresh(src)
	res := DecoysResult{Decoys: []DecoyState{}}
	lstat, _ := src.FS.(interface {
		Lstat(string) (fs.FileInfo, error)
	})
	for _, name := range rel {
		st := DecoyState{Path: "/" + name}
		var info fs.FileInfo
		var err error
		if lstat != nil {
			info, err = lstat.Lstat(name)
		} else {
			info, err = fs.Stat(src.FS, name)
		}
		if err != nil {
			st.Missing = true
			res.Decoys = append(res.Decoys, st)
			continue
		}
		st.Size, st.Mode, st.ModTime = info.Size(), info.Mode().String(), info.ModTime().UTC()
		st.ChangeTime, _ = collector.ChangeTime(info)
		if sys, ok := info.Sys().(*syscall.Stat_t); ok {
			st.Inode, st.Links = sys.Ino, uint64(sys.Nlink) //nolint:unconvert // Nlink's type differs between platforms
		}
		res.Decoys = append(res.Decoys, st)
	}
	res.Aliases = collector.DecoyAliases()
	return res, d.Err
}

// maxDecoysFile bounds the decoys' configuration file.
const maxDecoysFile = 64 << 10

// LoadDecoys reads the decoys' configuration: one absolute path a line, blank lines and lines
// starting with # ignored. The file must belong to the user the sensor runs as (root) and be
// unreadable by others: the list is what an intruder looks for, and the command line any local
// user can read is no place for it. A missing file is no decoys.
func LoadDecoys(name string) ([]string, error) {
	f, err := os.Open(name) //nolint:gosec // the operator's configuration
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("%s is not a regular file", name)
	case !ok || int(st.Uid) != os.Geteuid():
		return nil, fmt.Errorf("%s must belong to the user the sensor runs as", name)
	case info.Mode().Perm()&0o077 != 0:
		return nil, fmt.Errorf("%s must be readable by its owner only (mode 0600)", name)
	case info.Size() > maxDecoysFile:
		return nil, fmt.Errorf("%s is larger than %d bytes", name, maxDecoysFile)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxDecoysFile))
	if err != nil {
		return nil, err
	}
	var paths []string
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !path.IsAbs(line) {
			return nil, fmt.Errorf("%s: %q is not an absolute path", name, line)
		}
		if len(paths) == maxDecoys {
			return paths, fmt.Errorf("%s: more than %d decoys, the rest ignored", name, maxDecoys)
		}
		paths = append(paths, line)
	}
	return paths, nil
}
