//go:build !unix

package collector

import "io/fs"

func owner(fs.FileInfo) (uid, gid *uint32) {
	return nil, nil
}
