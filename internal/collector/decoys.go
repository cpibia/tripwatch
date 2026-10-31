package collector

import (
	"errors"
	"io/fs"
	"sync"
	"syscall"
)

// ErrDecoy is a file the sensor must not open: a decoy, whose every read is an alert, would report
// the sensor itself.
var ErrDecoy = errors.New("decoy file, never opened by the sensor")

// fileID is a file's identity, the same whatever path or link leads to it.
type fileID struct{ dev, ino uint64 }

// decoys are the identities of the decoy files, refreshed at each snapshot: a decoy replaced by
// another file gets the new file's identity.
var decoys struct {
	sync.RWMutex
	ids map[fileID]bool
}

// SetDecoys records the files of src named by paths, relative to its root, as decoys: no
// collector or watcher opens them from then on, through any path or link.
func SetDecoys(src Source, paths []string) {
	ids := map[fileID]bool{}
	for _, p := range paths {
		if info, err := statIn(src.Root, p); err == nil {
			if id, ok := identity(info); ok {
				ids[id] = true
			}
		}
	}
	decoys.Lock()
	decoys.ids = ids
	decoys.Unlock()
}

// isDecoy reports a file whose identity is a decoy's.
func isDecoy(info fs.FileInfo) bool {
	id, ok := identity(info)
	if !ok {
		return false
	}
	decoys.RLock()
	defer decoys.RUnlock()
	return decoys.ids[id]
}

func identity(info fs.FileInfo) (fileID, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}
	return fileID{dev: uint64(st.Dev), ino: st.Ino}, true //nolint:unconvert,gosec // Dev's type differs between platforms
}
