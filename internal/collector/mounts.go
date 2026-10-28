package collector

import (
	"slices"
	"strconv"
	"strings"
)

// networkFilesystems are the mount types whose content lives on another machine. Walking one
// costs a network round trip per entry and can hang on a read no deadline interrupts: a WebDAV
// or S3 share mounted in a home is enough to keep a whole-filesystem walk from ever finishing.
var networkFilesystems = []string{
	"nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs", "afs", "9p", "davfs",
	"fuse.davfs", "fuse.sshfs", "fuse.s3fs", "fuse.rclone", "fuse.goofys", "fuse.gcsfuse", "fuse.mountpoint-s3", "fuse.glusterfs", "fuse.cephfs",
}

// Mount is a mount point of the observed host, without its leading slash, with its type and
// whether it disables setuid and file capabilities.
type Mount struct {
	Point  string
	Type   string
	NoSUID bool
}

// NetworkMounts returns the network filesystems mounted on the observed host, read from the
// mount table of its init process.
func NetworkMounts(src Source) ([]Mount, error) {
	lines, err := ReadLines(src.FS, "proc/1/mountinfo")
	if err != nil {
		return nil, err
	}
	var out []Mount
	for _, line := range lines {
		left, right, ok := strings.Cut(line, " - ")
		fields, tail := strings.Fields(left), strings.Fields(right)
		if !ok || len(fields) < 6 || len(tail) < 1 || !slices.Contains(networkFilesystems, tail[0]) {
			continue
		}
		point := strings.Trim(UnescapeMount(fields[4]), "/")
		if point == "" {
			continue
		}
		out = append(out, Mount{Point: point, Type: tail[0], NoSUID: slices.Contains(strings.Split(fields[5], ","), "nosuid")})
	}
	return out, nil
}

// UnescapeMount decodes the octal escapes mountinfo uses for spaces and the like.
func UnescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
