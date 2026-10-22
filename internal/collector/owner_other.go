//go:build !unix

package collector

import "io/fs"

func owner(fs.FileInfo) (uid, gid *uint32) {
	return nil, nil
}

// Inode is not available on this platform.
func Inode(fs.FileInfo) (uint64, bool) {
	return 0, false
}

// FileID is not available on this platform.
func FileID(fs.FileInfo) (string, bool) {
	return "", false
}

// Owner is not available on this platform.
func Owner(fs.FileInfo) (uint32, bool) {
	return 0, false
}

// Allocated is not available on this platform.
func Allocated(fs.FileInfo) (int64, bool) {
	return 0, false
}
