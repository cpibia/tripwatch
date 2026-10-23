package system

import (
	"crypto/md5" //nolint:gosec // matches the rpm digest format under test
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	_ "modernc.org/sqlite"

	"github.com/cpibia/tripwatch/internal/collector"
)

type rpmTestFile struct {
	path    string
	content string // recorded digest is computed from this
	flags   uint32
	verify  uint32
	state   byte
	mode    uint16
}

const (
	modeRegular = 0o100644
	modeDir     = 0o040755
	modeLink    = 0o120777
)

// rpmHeader builds a header blob the way rpm stores it in its database. algo 0 leaves the
// digest algorithm tag out, which means MD5.
func rpmHeader(name string, algo uint32, files []rpmTestFile) []byte {
	type entry struct {
		tag, typ uint32
		data     []byte
		count    uint32
		align    int
	}
	strs := func(ss []string) []byte {
		var b []byte
		for _, s := range ss {
			b = append(append(b, s...), 0)
		}
		return b
	}
	u32s := func(vs []uint32) []byte {
		b := make([]byte, 4*len(vs))
		for i, v := range vs {
			binary.BigEndian.PutUint32(b[4*i:], v)
		}
		return b
	}

	var dirs, bases, digests []string
	var indexes, flags, verify []uint32
	var states []byte
	modes := []byte{}
	for _, f := range files {
		dir, base := path.Dir(f.path)+"/", path.Base(f.path)
		di := slices.Index(dirs, dir)
		if di < 0 {
			dirs, di = append(dirs, dir), len(dirs)
		}
		digest := ""
		if f.mode == modeRegular {
			if algo == 8 {
				sum := sha256.Sum256([]byte(f.content))
				digest = hex.EncodeToString(sum[:])
			} else {
				sum := md5.Sum([]byte(f.content)) //nolint:gosec // see import
				digest = hex.EncodeToString(sum[:])
			}
		}
		bases, digests, indexes = append(bases, base), append(digests, digest), append(indexes, u32(di))
		flags, verify, states = append(flags, f.flags), append(verify, f.verify), append(states, f.state)
		modes = binary.BigEndian.AppendUint16(modes, f.mode)
	}
	n := u32(len(files))
	entries := []entry{{rpmTagName, 6, strs([]string{name}), 1, 1}}
	if n > 0 {
		entries = append(entries,
			entry{rpmTagDirNames, 8, strs(dirs), u32(len(dirs)), 1},
			entry{rpmTagBaseNames, 8, strs(bases), n, 1},
			entry{rpmTagFileDigests, 8, strs(digests), n, 1},
			entry{rpmTagDirIndexes, 4, u32s(indexes), n, 4},
			entry{rpmTagFileFlags, 4, u32s(flags), n, 4},
			entry{rpmTagFileVerify, 4, u32s(verify), n, 4},
			entry{rpmTagFileStates, 1, states, n, 1},
			entry{rpmTagFileModes, 3, modes, n, 2},
		)
	}
	if algo != 0 {
		entries = append(entries, entry{rpmTagFileDigestAlgo, 4, u32s([]uint32{algo}), 1, 4})
	}

	var index, data []byte
	for _, e := range entries {
		for len(data)%e.align != 0 {
			data = append(data, 0)
		}
		index = append(index, u32s([]uint32{e.tag, e.typ, u32(len(data)), e.count})...)
		data = append(data, e.data...)
	}
	return append(append(u32s([]uint32{u32(len(entries)), u32(len(data))}), index...), data...)
}

// u32 converts the small lengths of the test fixtures.
func u32(n int) uint32 { return uint32(n) } //nolint:gosec // fixture sizes only

func all(f rpmTestFile) rpmTestFile {
	f.verify = ^uint32(0)
	if f.mode == 0 {
		f.mode = modeRegular
	}
	return f
}

// rpmHostHeaders and rpmHostFiles describe a host with one package verified by SHA-256, one
// older package with MD5 digests, and an imported signing key.
func rpmHostHeaders() [][]byte {
	return [][]byte{
		rpmHeader("openssh-server", 8, []rpmTestFile{
			all(rpmTestFile{path: "/usr/sbin/sshd", content: "sshd"}),
			all(rpmTestFile{path: "/etc/ssh/sshd_config", content: "config", flags: rpmFileConfig}),
			all(rpmTestFile{path: "/usr/lib64/.libssh.so.hmac", content: "hmac"}),
			{path: "/usr/lib64/gconv-modules.cache", content: "cache", mode: modeRegular},
			all(rpmTestFile{path: "/usr/share/locale/it/sshd.mo", content: "it", state: 2}),
			all(rpmTestFile{path: "/var/log/lastlog", flags: rpmFileGhost}),
			all(rpmTestFile{path: "/etc/sysconfig/sshd-extra", content: "x", flags: rpmFileMissingOK | rpmFileConfig}),
			all(rpmTestFile{path: "/usr/bin/scp", content: "scp"}),
			all(rpmTestFile{path: "/usr/lib/.build-id", mode: modeDir}),
			all(rpmTestFile{path: "/usr/lib/.build-id/ab/cdef", mode: modeLink}),
		}),
		rpmHeader("legacy-tools", 0, []rpmTestFile{all(rpmTestFile{path: "/usr/bin/old", content: "old"})}),
		rpmHeader("gpg-pubkey", 0, nil),
	}
}

func rpmHostFiles() fstest.MapFS {
	return fstest.MapFS{
		"usr/sbin/sshd":                                            text("sshd with a backdoor"),
		"etc/ssh/sshd_config":                                      text("edited"),
		"usr/lib64/.libssh.so.hmac":                                text("hmac"),
		"usr/lib64/gconv-modules.cache":                            text("rebuilt at runtime"),
		"usr/bin/old":                                              text("old"),
		"usr/lib/.build-id/ab/cdef":                                link("../../../../usr/sbin/sshd"),
		"usr/lib/.build-id/ab/planted":                             text("dropped in a packaged hidden directory"),
		"usr/lib/.syslib/fnd":                                      text("find"),
		"usr/local/src/imagick/.git/HEAD":                          text("ref: refs/heads/master"),
		"usr/local/src/imagick/.travis.yml":                        text(""),
		"usr/local/lib/node_modules/a/.bin/x":                      text(""),
		"usr/lib/python3.9/site-packages/botocore/.changes/1.json": text("{}"),
	}
}

func checkRpmHost(t *testing.T, res PackagesResult) {
	t.Helper()
	if res.Manager != ManagerRpm || res.Packages < 2 || len(res.Issues) != 0 {
		t.Fatalf("manager = %q packages = %d issues = %v", res.Manager, res.Packages, res.Issues)
	}
	want := []ModifiedFile{
		{Path: "/usr/sbin/sshd", Package: "openssh-server"},
		{Path: "/etc/ssh/sshd_config", Package: "openssh-server", Config: true},
	}
	if !slices.Equal(res.Modified, want) {
		t.Errorf("modified = %+v, want %+v; files excluded with %%verify(not md5) are not checked", res.Modified, want)
	}
	if !slices.Contains(res.Missing, "/usr/bin/scp") || slices.ContainsFunc(res.Missing, func(p string) bool { return p != "/usr/bin/scp" }) {
		t.Errorf("missing = %v; ghost, missingok and files rpm did not install are not missing", res.Missing)
	}
	if !slices.Equal(res.Hidden, []string{"/usr/lib/.build-id/ab/planted", "/usr/lib/.syslib"}) {
		t.Errorf("hidden = %v; packaged entries, source checkouts and language package trees are skipped", res.Hidden)
	}
	if len(res.DatabaseSHA256) != 64 {
		t.Errorf("database hash = %q", res.DatabaseSHA256)
	}
}

// sqliteRpmDB writes headers into a SQLite database shaped like rpm's. The last header is
// committed to the write-ahead log only, as after a transaction rpm has not checkpointed yet.
// The database stays open until the test ends, so the -wal file is still there.
func sqliteRpmDB(t *testing.T, headers [][]byte) (string, *sql.DB) {
	t.Helper()
	dir := t.TempDir()
	name := filepath.Join(dir, "rpmdb.sqlite")
	db, err := sql.Open("sqlite", "file:"+name+"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
	exec("CREATE TABLE 'Basenames' (key TEXT NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL)")
	for _, h := range headers[:len(headers)-1] {
		exec("INSERT INTO Packages (blob) VALUES (?)", h)
	}
	exec("PRAGMA wal_checkpoint(TRUNCATE)")
	exec("INSERT INTO Packages (blob) VALUES (?)", headers[len(headers)-1])
	return dir, db
}

func readDir(t *testing.T, dir, into string, fsys fstest.MapFS) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // the test's own temporary directory
		if err != nil {
			t.Fatal(err)
		}
		fsys[path.Join(into, e.Name())] = &fstest.MapFile{Data: data, Mode: 0o644}
	}
}

// Enough packages, some larger than a page, for interior b-tree pages and overflow chains.
func fillerHeaders() [][]byte {
	var out [][]byte
	for i := range 300 {
		out = append(out, rpmHeader(fmt.Sprintf("filler-%d", i), 8, []rpmTestFile{
			all(rpmTestFile{path: fmt.Sprintf("/opt/filler/%d/%s", i, strings.Repeat("f", 40*(i%200))), mode: modeDir}),
		}))
	}
	return out
}

func TestPackagesRpmSQLite(t *testing.T) {
	headers := append(fillerHeaders(), rpmHostHeaders()...)
	dir, _ := sqliteRpmDB(t, headers)
	fsys := rpmHostFiles()
	readDir(t, dir, "var/lib/rpm", fsys)
	if f := fsys["var/lib/rpm/rpmdb.sqlite-wal"]; f == nil || len(f.Data) == 0 {
		t.Fatal("fixture: the last package should be in the write-ahead log")
	}
	res := collect[PackagesResult](t, Packages{}, collector.Source{FS: fsys})
	checkRpmHost(t, res)
	// The fillers, openssh-server and legacy-tools, read from the log; the key is not a package.
	if res.Packages != 302 {
		t.Errorf("packages = %d, want 302", res.Packages)
	}
}

// bdbFile lays headers out as a Berkeley DB hash database: the metadata page, one hash page
// with an inline key and an off-page value per record, and the overflow pages holding the values.
func bdbFile(headers [][]byte) []byte {
	const ps = 4096
	le := binary.LittleEndian
	pages := [][]byte{make([]byte, ps), make([]byte, ps)}
	hash := pages[1]
	hash[25] = bdbHash
	end := ps
	var offsets []uint16
	addItem := func(item []byte) {
		end -= len(item)
		copy(hash[end:], item)
		offsets = append(offsets, uint16(end)) //nolint:gosec // within one 4 KiB page
	}
	// rpm's instance counter under key 0, inline.
	addItem([]byte{bdbItemKeyData, 0, 0, 0, 0})
	addItem([]byte{bdbItemKeyData, 1, 0, 0, 0})
	for i, h := range headers {
		addItem([]byte{bdbItemKeyData, byte(i + 1), 0, 0, 0})
		first := u32(len(pages))
		for off := 0; off < len(h); off += ps - bdbPageHeader {
			p := make([]byte, ps)
			p[25] = bdbOverflow
			n := copy(p[bdbPageHeader:], h[off:])
			le.PutUint16(p[22:], uint16(n)) //nolint:gosec // within one 4 KiB page
			if off+n < len(h) {
				le.PutUint32(p[16:], u32(len(pages)+1))
			}
			pages = append(pages, p)
		}
		item := make([]byte, 12)
		item[0] = bdbItemOffPage
		le.PutUint32(item[4:], first)
		le.PutUint32(item[8:], u32(len(h)))
		addItem(item)
	}
	le.PutUint16(hash[20:], uint16(len(offsets))) //nolint:gosec // a handful of entries
	for i, o := range offsets {
		le.PutUint16(hash[bdbPageHeader+2*i:], o)
	}
	meta := pages[0]
	le.PutUint32(meta[12:], bdbHashMagic)
	le.PutUint32(meta[20:], ps)
	meta[25] = bdbHashMeta
	le.PutUint32(meta[32:], u32(len(pages)-1))
	var out []byte
	for _, p := range pages {
		out = append(out, p...)
	}
	return out
}

func TestPackagesRpmBerkeleyDB(t *testing.T) {
	fsys := rpmHostFiles()
	fsys["var/lib/rpm/Packages"] = &fstest.MapFile{Data: bdbFile(rpmHostHeaders()), Mode: 0o644}
	res := collect[PackagesResult](t, Packages{}, collector.Source{FS: fsys})
	checkRpmHost(t, res)
	if res.Packages != 2 {
		t.Errorf("packages = %d, want 2", res.Packages)
	}
}

// A corrupt database ends in an issue, never a hang: here an overflow chain points back to
// its own page, and a b-tree page is its own child.
func TestPackagesRpmCorruptDatabase(t *testing.T) {
	headers := rpmHostHeaders()
	bdb := bdbFile(headers)
	le := binary.LittleEndian
	item := int(le.Uint16(bdb[4096+bdbPageHeader+2*3:]))
	le.PutUint32(bdb[4096+item+8:], u32(3*len(headers[0])+1))
	le.PutUint32(bdb[2*4096+16:], 2)

	dir, db := sqliteRpmDB(t, append(fillerHeaders(), rpmHostHeaders()...))
	if _, err := db.ExecContext(t.Context(), "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	sq := fstest.MapFS{}
	readDir(t, dir, "var/lib/rpm", sq)
	data := sq["var/lib/rpm/rpmdb.sqlite"].Data
	ps := int(binary.BigEndian.Uint16(data[16:]))
	// The Packages table is the first one created: its root is page 2, an interior page.
	root := data[ps : 2*ps]
	if root[0] != sqliteInteriorTable {
		t.Fatalf("fixture: page 2 is type %#x, want an interior table page", root[0])
	}
	binary.BigEndian.PutUint32(root[8:], 2)

	for name, fsys := range map[string]fstest.MapFS{
		"bdb loop":    {"var/lib/rpm/Packages": {Data: bdb}},
		"sqlite loop": sq,
		"truncated":   {"var/lib/rpm/rpmdb.sqlite": {Data: data[:150]}},
		"empty":       {"var/lib/rpm/rpmdb.sqlite": text("")},
		"ndb":         {"var/lib/rpm/Packages.db": text("")},
	} {
		res := collect[PackagesResult](t, Packages{}, collector.Source{FS: fsys})
		if res.Manager != ManagerRpm || len(res.Issues) == 0 {
			t.Errorf("%s: manager = %q issues = %v", name, res.Manager, res.Issues)
		}
	}
}
