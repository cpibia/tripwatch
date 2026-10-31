package collector

import (
	"errors"
	"io/fs"
	"slices"
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
	// names are the decoys' own paths; aliases the other paths found leading to one.
	names   map[string]bool
	aliases map[string]bool
}

// maxDecoyAliases bounds the other paths to decoys remembered.
const maxDecoyAliases = 100

// SetDecoys records the files of src named by paths, relative to its root, as decoys: no
// collector or watcher opens them from then on, through any path or link.
func SetDecoys(src Source, paths []string) {
	ids, names := map[fileID]bool{}, map[string]bool{}
	for _, p := range paths {
		names[p] = true
		if info, err := statIn(src.Root, p); err == nil {
			if id, ok := identity(info); ok {
				ids[id] = true
			}
		}
	}
	decoys.Lock()
	decoys.ids, decoys.names = ids, names
	decoys.Unlock()
}

// refuseDecoy is the error for name, found to be a decoy: a path other than the decoy's own is
// remembered, since a hard link to a decoy hides whatever is written to it from every reader.
func refuseDecoy(name string) error {
	decoys.Lock()
	defer decoys.Unlock()
	if !decoys.names[name] && len(decoys.aliases) < maxDecoyAliases {
		if decoys.aliases == nil {
			decoys.aliases = map[string]bool{}
		}
		decoys.aliases[name] = true
	}
	return ErrDecoy
}

// DecoyAliases returns the paths other than the decoys' own found leading to a decoy, sorted.
func DecoyAliases() []string {
	decoys.RLock()
	defer decoys.RUnlock()
	var out []string
	for name := range decoys.aliases {
		out = append(out, "/"+name)
	}
	slices.Sort(out)
	return out
}

// isDecoy reports a file whose identity is a decoy's.
func isDecoy(info fs.FileInfo) bool {
	id, ok := identity(info)
	if !ok {
		return false
	}
	return isDecoyID(id)
}

func isDecoyID(id fileID) bool {
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
