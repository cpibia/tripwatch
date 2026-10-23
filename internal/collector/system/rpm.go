package system

import (
	"bytes"
	"crypto/md5"  //nolint:gosec // older rpm packages record MD5 file digests; same reason as dpkg
	"crypto/sha1" //nolint:gosec // and some SHA-1
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

// The rpm database is read directly, never through the host's rpm binary: running a program
// of the observed host as root would trust what verification is meant to check. Two formats
// are in use: Berkeley DB (RHEL/CentOS 7 and 8, Amazon Linux 2) and SQLite (RHEL 9, Amazon
// Linux 2023, Fedora). Both readers only go forward through pages they bound-check, and the
// database is only writable by root, but a corrupt file must still end in an issue, not a hang.
var rpmDatabases = []string{
	"var/lib/rpm/rpmdb.sqlite",
	"usr/lib/sysimage/rpm/rpmdb.sqlite",
	"var/lib/rpm/Packages",
	"usr/lib/sysimage/rpm/Packages",
}

// rpm refuses headers this large itself; real ones stay under a few megabytes.
const (
	maxRpmHeader     = 64 << 20
	maxRpmHeaderTags = 1 << 16
)

var errRpmHeader = errors.New("malformed rpm header")

// Header tags and file flags, from rpm's rpmtag.h and rpmfiles.h.
const (
	rpmTagName           = 1000
	rpmTagFileModes      = 1030
	rpmTagFileStates     = 1029
	rpmTagFileDigests    = 1035
	rpmTagFileFlags      = 1037
	rpmTagFileVerify     = 1045
	rpmTagDirIndexes     = 1116
	rpmTagBaseNames      = 1117
	rpmTagDirNames       = 1118
	rpmTagFileDigestAlgo = 5011

	rpmFileConfig    = 1 << 0
	rpmFileMissingOK = 1 << 3
	rpmFileGhost     = 1 << 6

	// Packages exclude files rewritten at runtime, such as caches, with %verify(not md5).
	rpmVerifyDigest = 1 << 0

	// FILESTATES other than normal mean rpm did not install the file: a language or
	// documentation left out by configuration, or a file another package replaced.
	rpmFileStateNormal = 0
)

// rpmDigests maps rpm's digest algorithm numbers (OpenPGP hash ids) to hash functions. A
// header without the tag uses MD5.
var rpmDigests = map[uint32]func() hash.Hash{
	1:  md5.New,
	2:  sha1.New,
	8:  sha256.New,
	9:  sha512.New384,
	10: sha512.New,
}

type rpmFile struct {
	path   string
	digest string
	flags  uint32
	verify uint32
	state  byte
	mode   uint16
}

type rpmPackage struct {
	name   string
	algo   uint32
	files  []rpmFile
	hasher func() hash.Hash
}

// readRpm returns the files installed by rpm, the paths it owns and the package count, plus
// the database file read so that its fingerprint covers the same data.
func readRpm(fsys fs.FS, issues *collector.Issues) ([]expectedFile, map[string]bool, int, string) {
	owned := map[string]bool{}
	var expected []expectedFile
	installed := 0

	db := ""
	for _, name := range rpmDatabases {
		if info, err := fs.Stat(fsys, name); err == nil && info.Mode().IsRegular() {
			db = name
			break
		}
	}
	if db == "" {
		if exists(fsys, "var/lib/rpm/Packages.db") || exists(fsys, "usr/lib/sysimage/rpm/Packages.db") {
			issues.Add(errors.New("rpm ndb database (SUSE) is not supported yet"))
		} else {
			issues.Add(errors.New("rpm database not found"))
		}
		return nil, owned, 0, ""
	}

	each := func(blob []byte) error {
		pkg, err := parseRpmHeader(blob)
		if err != nil {
			return err
		}
		// gpg-pubkey entries are keys imported into rpm, not installed software.
		if pkg.name == "gpg-pubkey" {
			return nil
		}
		installed++
		for _, f := range pkg.files {
			addOwned(owned, f.path)
			if f.digest == "" || f.flags&rpmFileGhost != 0 || f.verify&rpmVerifyDigest == 0 || f.state != rpmFileStateNormal || f.mode&0o170000 != 0o100000 {
				continue
			}
			expected = append(expected, expectedFile{
				path: collector.Rel(f.path), pkg: pkg.name, checksum: f.digest,
				config: f.flags&rpmFileConfig != 0, missingOK: f.flags&rpmFileMissingOK != 0, newHash: pkg.hasher,
			})
		}
		return nil
	}

	var err error
	if strings.HasSuffix(db, ".sqlite") {
		err = sqliteRpmHeaders(fsys, db, each)
	} else {
		err = bdbRpmHeaders(fsys, db, each)
	}
	if err != nil {
		issues.Add(fmt.Errorf("/%s: %w", db, err))
	}
	return expected, owned, installed, db
}

// parseRpmHeader decodes a header blob as rpm stores it in its database: the index entry
// count and data length, the entries, then the data they point into. Everything is big-endian.
func parseRpmHeader(blob []byte) (rpmPackage, error) {
	var pkg rpmPackage
	if len(blob) < 8 {
		return pkg, errRpmHeader
	}
	il, dl := binary.BigEndian.Uint32(blob), binary.BigEndian.Uint32(blob[4:])
	if il > maxRpmHeaderTags || uint64(dl) > maxRpmHeader || uint64(len(blob)) < 8+16*uint64(il)+uint64(dl) {
		return pkg, errRpmHeader
	}
	data := blob[8+16*il : 8+16*il+dl]

	type entry struct{ typ, offset, count uint32 }
	entries := map[uint32]entry{}
	for i := range il {
		e := blob[8+16*i:]
		entries[binary.BigEndian.Uint32(e)] = entry{binary.BigEndian.Uint32(e[4:]), binary.BigEndian.Uint32(e[8:]), binary.BigEndian.Uint32(e[12:])}
	}
	// strings returns count NUL-terminated strings starting at the entry's offset.
	stringsOf := func(tag uint32) ([]string, error) {
		e, ok := entries[tag]
		if !ok {
			return nil, nil
		}
		if e.offset > dl || e.count > dl {
			return nil, errRpmHeader
		}
		out := make([]string, 0, e.count)
		rest := data[e.offset:]
		for range e.count {
			end := bytes.IndexByte(rest, 0)
			if end < 0 {
				return nil, errRpmHeader
			}
			out = append(out, string(rest[:end]))
			rest = rest[end+1:]
		}
		return out, nil
	}
	fixed := func(tag uint32, size int) ([]byte, int, error) {
		e, ok := entries[tag]
		if !ok {
			return nil, 0, nil
		}
		start, count := int(e.offset), int(e.count)
		if start > len(data) || count > (len(data)-start)/size {
			return nil, 0, errRpmHeader
		}
		return data[start : start+count*size], count, nil
	}

	names, err := stringsOf(rpmTagName)
	if err != nil || len(names) != 1 {
		return pkg, errRpmHeader
	}
	pkg.name = names[0]
	pkg.hasher = md5.New
	if b, n, err := fixed(rpmTagFileDigestAlgo, 4); err != nil {
		return pkg, err
	} else if n > 0 {
		pkg.algo = binary.BigEndian.Uint32(b)
		pkg.hasher = rpmDigests[pkg.algo]
	}

	base, err := stringsOf(rpmTagBaseNames)
	if err != nil {
		return pkg, err
	}
	dirs, err := stringsOf(rpmTagDirNames)
	if err != nil {
		return pkg, err
	}
	digests, err := stringsOf(rpmTagFileDigests)
	if err != nil {
		return pkg, err
	}
	indexes, nIndexes, err := fixed(rpmTagDirIndexes, 4)
	if err != nil {
		return pkg, err
	}
	flags, nFlags, err := fixed(rpmTagFileFlags, 4)
	if err != nil {
		return pkg, err
	}
	verify, nVerify, err := fixed(rpmTagFileVerify, 4)
	if err != nil {
		return pkg, err
	}
	states, nStates, err := fixed(rpmTagFileStates, 1)
	if err != nil {
		return pkg, err
	}
	modes, nModes, err := fixed(rpmTagFileModes, 2)
	if err != nil {
		return pkg, err
	}
	n := len(base)
	if nIndexes != n {
		if n == 0 {
			return pkg, nil
		}
		return pkg, errRpmHeader
	}

	pkg.files = make([]rpmFile, 0, n)
	for i := range n {
		di := int(binary.BigEndian.Uint32(indexes[4*i:]))
		if di >= len(dirs) {
			return pkg, errRpmHeader
		}
		f := rpmFile{path: dirs[di] + base[i], verify: ^uint32(0)}
		// A package with an unknown digest algorithm still owns its files; they are only
		// left out of verification.
		if len(digests) == n && pkg.hasher != nil {
			f.digest = digests[i]
		}
		if nFlags == n {
			f.flags = binary.BigEndian.Uint32(flags[4*i:])
		}
		if nVerify == n {
			f.verify = binary.BigEndian.Uint32(verify[4*i:])
		}
		if nStates == n {
			f.state = states[i]
		}
		if nModes == n {
			f.mode = binary.BigEndian.Uint16(modes[2*i:])
		}
		pkg.files = append(pkg.files, f)
	}
	return pkg, nil
}

// openReaderAt opens name for random access: both database formats are read page by page,
// and the files are far larger than collector.MaxReadSize.
func openReaderAt(fsys fs.FS, name string) (io.ReaderAt, int64, func(), error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, 0, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, nil, err
	}
	ra, ok := f.(io.ReaderAt)
	if !ok || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, 0, nil, fmt.Errorf("%s: not a seekable regular file", name)
	}
	return ra, info.Size(), func() { _ = f.Close() }, nil
}

func readPage(r io.ReaderAt, off int64, size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := r.ReadAt(buf, off); err != nil {
		return nil, err
	}
	return buf, nil
}
