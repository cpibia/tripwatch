//go:build !linux && !darwin

package collector

import "io/fs"

// ChangeTime is not available on this platform.
func ChangeTime(fs.FileInfo) (int64, bool) {
	return 0, false
}
