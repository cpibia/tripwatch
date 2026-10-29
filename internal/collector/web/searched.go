package web

import (
	"crypto/sha256"
	"fmt"
	"io/fs"

	"github.com/cpibia/tripwatch/internal/collector"
)

// maxSearchedFiles bounds the data files remembered as searched: a few megabytes of memory.
const maxSearchedFiles = 1 << 16

// searchedFiles remembers, between the runs of a sensor, the data files searched through to their
// end and found free of code. A host keeping more large documents than one run's budget can
// search would otherwise spend every run on the same first files and never reach the others: the
// files remembered cost nothing, so the budget goes to the new and changed ones. A file is known
// by its path, size, inode, modification and change time: any write moves the change time, which
// only root can set back.
type searchedFiles struct {
	keys map[[16]byte]uint64
	run  uint64
}

// begin starts a run, forgetting the files no recent run has seen: removed or changed.
func (f *searchedFiles) begin() {
	f.run++
	for k, last := range f.keys {
		if last+2 < f.run {
			delete(f.keys, k)
		}
	}
}

func searchedKey(name string, info fs.FileInfo) ([16]byte, bool) {
	ctime, okC := collector.ChangeTime(info)
	ino, okI := collector.Inode(info)
	if !okC || !okI {
		return [16]byte{}, false
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%d\x00%d\x00%d\x00%d", name, info.Size(), info.ModTime().UnixNano(), ctime, ino)
	var k [16]byte
	copy(k[:], h.Sum(nil))
	return k, true
}

// clean reports whether the file, as it is now, was searched and found free of code.
func (f *searchedFiles) clean(name string, info fs.FileInfo) bool {
	if f == nil {
		return false
	}
	k, ok := searchedKey(name, info)
	if !ok {
		return false
	}
	if _, ok := f.keys[k]; !ok {
		return false
	}
	f.keys[k] = f.run
	return true
}

// add remembers a file searched to its end without finding code. When the bound is reached new
// files are not remembered: they are searched again, as without memory.
func (f *searchedFiles) add(name string, info fs.FileInfo) {
	if f == nil || len(f.keys) >= maxSearchedFiles {
		return
	}
	k, ok := searchedKey(name, info)
	if !ok {
		return
	}
	if f.keys == nil {
		f.keys = map[[16]byte]uint64{}
	}
	f.keys[k] = f.run
}
