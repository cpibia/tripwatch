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
