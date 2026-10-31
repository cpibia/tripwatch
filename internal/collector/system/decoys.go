package system

import (
	"context"
	"io/fs"
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
}

// DecoysResult is the decoys' state.
type DecoysResult struct {
	Decoys []DecoyState `json:"decoys"`
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
			st.Inode = sys.Ino
		}
		res.Decoys = append(res.Decoys, st)
	}
	return res, nil
}
