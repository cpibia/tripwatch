//go:build !unix

package pki

import "io/fs"

// checkPrivate has no ownership model to check outside Unix; the sensor runs on Linux.
func checkPrivate(fs.FileInfo) error { return nil }
