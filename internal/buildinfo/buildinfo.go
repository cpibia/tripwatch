// Package buildinfo exposes the version stamped into the binaries at link time.
package buildinfo

import "fmt"

// Set with -ldflags "-X github.com/cpibia/tripwatch/internal/buildinfo.Version=...".
var (
	Version = "dev"
	Commit  = "none"
)

// String returns a one-line version description for the named binary.
func String(binary string) string {
	return fmt.Sprintf("%s %s (%s)", binary, Version, Commit)
}
