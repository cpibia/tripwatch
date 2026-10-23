package system

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// A minimal read-only SQLite reader, enough for rpm's database: one table, Packages(hnum
// INTEGER PRIMARY KEY, blob BLOB), found through the schema table on page 1. Pulling in a SQL
// engine would add megabytes of transpiled C to a static binary running as root for the sake
// of one table walk. The file format is documented at https://www.sqlite.org/fileformat.html.
//
// rpm keeps the database in WAL mode, so recent transactions may still sit in the -wal file:
// committed frames are laid over the main file, otherwise files updated by the last
// transaction would show as modified.
const (
	sqliteHeader        = 100
	sqliteLeafTable     = 0x0d
	sqliteInteriorTable = 0x05
	sqliteMaxDepth      = 64
	walHeader           = 32
	walFrameHeader      = 24
)

var errSQLite = errors.New("malformed SQLite file")

type sqliteDB struct {
	r        io.ReaderAt
	pageSize int
	usable   int
	pages    int64
	wal      io.ReaderAt
	walPages map[int64]int64
}

func sqliteRpmHeaders(fsys fs.FS, name string, each func([]byte) error) error {
	r, size, closeFile, err := openReaderAt(fsys, name)
	if err != nil {
		return err
	}
	defer closeFile()

	hdr, err := readPage(r, 0, sqliteHeader)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(hdr, []byte("SQLite format 3\x00")) {
		return fmt.Errorf("%w: bad magic", errSQLite)
	}
	ps := int(binary.BigEndian.Uint16(hdr[16:]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 || ps&(ps-1) != 0 || int(hdr[20]) >= ps-480 {
		return fmt.Errorf("%w: bad page size", errSQLite)
	}
	db := &sqliteDB{r: r, pageSize: ps, usable: ps - int(hdr[20]), pages: size / int64(ps)}

	if wr, wsize, closeWal, err := openReaderAt(fsys, name+"-wal"); err == nil {
		defer closeWal()
		if err := db.loadWAL(wr, wsize); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	root := int64(0)
	err = db.walk(1, func(rec []byte) error {
		cols, err := sqliteRecord(rec)
		if err != nil || len(cols) < 4 {
			return err
		}
		if string(cols[0].text) == "table" && string(cols[1].text) == "Packages" && cols[3].int > 0 {
			root = cols[3].int
		}
		return nil
	})
	if err != nil {
		return err
	}
	if root == 0 {
		return fmt.Errorf("%w: no Packages table", errSQLite)
	}
	return db.walk(root, func(rec []byte) error {
		cols, err := sqliteRecord(rec)
		if err != nil {
			return err
		}
		if len(cols) < 2 || cols[1].text == nil {
			return fmt.Errorf("%w: unexpected Packages row", errSQLite)
		}
		return each(cols[1].text)
	})
}

// loadWAL indexes the pages of committed transactions in the write-ahead log. Frames count
// only while their salts match the header and their checksums chain; frames after the last
// commit belong to a transaction in progress and are ignored, as SQLite itself does.
func (db *sqliteDB) loadWAL(r io.ReaderAt, size int64) error {
	if size < walHeader {
		return nil
	}
	hdr, err := readPage(r, 0, walHeader)
	if err != nil {
		return err
	}
	magic := binary.BigEndian.Uint32(hdr)
	if magic&^1 != 0x377f0682 {
		return fmt.Errorf("%w: bad WAL magic", errSQLite)
	}
	if int(binary.BigEndian.Uint32(hdr[8:])) != db.pageSize {
		return fmt.Errorf("%w: WAL page size differs", errSQLite)
	}
	var order binary.ByteOrder = binary.LittleEndian
	if magic&1 == 1 {
		order = binary.BigEndian
	}
	s0, s1 := walChecksum(order, hdr[:24], 0, 0)
	if s0 != binary.BigEndian.Uint32(hdr[24:]) || s1 != binary.BigEndian.Uint32(hdr[28:]) {
		return nil
	}
	salt := hdr[16:24]

	committed := map[int64]int64{}
	pending := map[int64]int64{}
	frameSize := int64(walFrameHeader + db.pageSize)
	for off := int64(walHeader); off+frameSize <= size; off += frameSize {
		frame, err := readPage(r, off, int(frameSize))
		if err != nil {
			return err
		}
		if !bytes.Equal(frame[8:16], salt) {
			break
		}
		s0, s1 = walChecksum(order, frame[:8], s0, s1)
		s0, s1 = walChecksum(order, frame[walFrameHeader:], s0, s1)
		if s0 != binary.BigEndian.Uint32(frame[16:]) || s1 != binary.BigEndian.Uint32(frame[20:]) {
			break
		}
		pending[int64(binary.BigEndian.Uint32(frame))] = off + walFrameHeader
		if dbSize := binary.BigEndian.Uint32(frame[4:]); dbSize != 0 {
			for p, o := range pending {
				committed[p] = o
			}
			clear(pending)
			db.pages = int64(dbSize)
		}
	}
	if len(committed) > 0 {
		db.wal, db.walPages = r, committed
	}
	return nil
}

func walChecksum(order binary.ByteOrder, b []byte, s0, s1 uint32) (uint32, uint32) {
	for i := 0; i+8 <= len(b); i += 8 {
		s0 += order.Uint32(b[i:]) + s1
		s1 += order.Uint32(b[i+4:]) + s0
	}
	return s0, s1
}

func (db *sqliteDB) page(n int64) ([]byte, error) {
	if n == 0 || n > db.pages {
		return nil, fmt.Errorf("%w: page %d out of range", errSQLite, n)
	}
	if off, ok := db.walPages[n]; ok {
		return readPage(db.wal, off, db.pageSize)
	}
	return readPage(db.r, (n-1)*int64(db.pageSize), db.pageSize)
}

// walk calls fn with the payload of every row of the table b-tree rooted at root. Depth and
// the number of pages visited are bounded, so a cycle in a corrupt file ends in an error.
func (db *sqliteDB) walk(root int64, fn func([]byte) error) error {
	type item struct {
		page  int64
		depth int
	}
	stack := []item{{root, 0}}
	visited := int64(0)
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited++; visited > db.pages || it.depth > sqliteMaxDepth {
			return fmt.Errorf("%w: b-tree loops", errSQLite)
		}
		p, err := db.page(it.page)
		if err != nil {
			return err
		}
		h := 0
		if it.page == 1 {
			h = sqliteHeader
		}
		if h+12 > len(p) {
			return fmt.Errorf("%w: page %d too small", errSQLite, it.page)
		}
		kind, cells := p[h], int(binary.BigEndian.Uint16(p[h+3:]))
		ptrs := h + 8
		if kind == sqliteInteriorTable {
			ptrs = h + 12
		} else if kind != sqliteLeafTable {
			return fmt.Errorf("%w: page %d is not a table page", errSQLite, it.page)
		}
		if ptrs+2*cells > db.usable {
			return fmt.Errorf("%w: page %d: too many cells", errSQLite, it.page)
		}

		if kind == sqliteInteriorTable {
			// Children are pushed right to left so rows come out in rowid order.
			stack = append(stack, item{int64(binary.BigEndian.Uint32(p[h+8:])), it.depth + 1})
			for i := cells - 1; i >= 0; i-- {
				c := int(binary.BigEndian.Uint16(p[ptrs+2*i:]))
				if c+4 > db.usable {
					return fmt.Errorf("%w: page %d: bad cell", errSQLite, it.page)
				}
				stack = append(stack, item{int64(binary.BigEndian.Uint32(p[c:])), it.depth + 1})
			}
			continue
		}
		for i := range cells {
			c := int(binary.BigEndian.Uint16(p[ptrs+2*i:]))
			payload, err := db.cellPayload(p, c)
			if err != nil {
				return fmt.Errorf("page %d: %w", it.page, err)
			}
			if err := fn(payload); err != nil {
				return err
			}
		}
	}
	return nil
}

// cellPayload returns the record of a table leaf cell, following its overflow pages.
func (db *sqliteDB) cellPayload(p []byte, c int) ([]byte, error) {
	if c >= db.usable {
		return nil, fmt.Errorf("%w: bad cell offset", errSQLite)
	}
	total, n := sqliteVarint(p[c:db.usable])
	if n <= 0 || total > maxRpmHeader+1024 {
		return nil, fmt.Errorf("%w: bad payload size", errSQLite)
	}
	c += n
	if _, n = sqliteVarint(p[c:db.usable]); n <= 0 {
		return nil, fmt.Errorf("%w: bad rowid", errSQLite)
	}
	c += n

	u := db.usable
	maxLocal := u - 35
	local := int(total)
	if local > maxLocal {
		minLocal := (u-12)*32/255 - 23
		local = minLocal + (int(total)-minLocal)%(u-4)
		if local > maxLocal {
			local = minLocal
		}
	}
	if c+local > u {
		return nil, fmt.Errorf("%w: cell overruns the page", errSQLite)
	}
	out := make([]byte, 0, total)
	out = append(out, p[c:c+local]...)
	if local == int(total) {
		return out, nil
	}
	if c+local+4 > u {
		return nil, fmt.Errorf("%w: cell overruns the page", errSQLite)
	}
	next := int64(binary.BigEndian.Uint32(p[c+local:]))
	for len(out) < int(total) {
		op, err := db.page(next)
		if err != nil {
			return nil, err
		}
		n := min(int(total)-len(out), u-4)
		out = append(out, op[4:4+n]...)
		next = int64(binary.BigEndian.Uint32(op))
	}
	return out, nil
}

// sqliteVarint decodes SQLite's big-endian varint: up to eight bytes of seven bits, then one
// byte of eight. It is not the encoding of encoding/binary.
func sqliteVarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i] < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

type sqliteValue struct {
	int  int64
	text []byte // text or blob
}

// sqliteRecord decodes a record into its columns: integers, and text or blobs as bytes.
func sqliteRecord(rec []byte) ([]sqliteValue, error) {
	hlen, n := sqliteVarint(rec)
	if n <= 0 || hlen > uint64(len(rec)) || hlen < uint64(n) {
		return nil, fmt.Errorf("%w: bad record header", errSQLite)
	}
	hdr, body := rec[n:hlen], rec[hlen:]
	var out []sqliteValue
	for len(hdr) > 0 {
		st, n := sqliteVarint(hdr)
		if n <= 0 {
			return nil, fmt.Errorf("%w: bad serial type", errSQLite)
		}
		hdr = hdr[n:]
		var size uint64
		switch {
		case st <= 4:
			size = st
		case st == 5:
			size = 6
		case st == 6 || st == 7:
			size = 8
		case st == 8 || st == 9:
		case st >= 12:
			size = (st - 12) / 2
		default:
			return nil, fmt.Errorf("%w: reserved serial type", errSQLite)
		}
		if size > uint64(len(body)) {
			return nil, fmt.Errorf("%w: record overruns its payload", errSQLite)
		}
		var v sqliteValue
		switch {
		case st >= 1 && st <= 6:
			for _, b := range body[:size] {
				v.int = v.int<<8 | int64(b)
			}
			// Sign-extend from the stored width.
			shift := 64 - 8*size
			v.int = v.int << shift >> shift
		case st == 9:
			v.int = 1
		case st >= 12:
			v.text = body[:size:size]
		}
		body = body[size:]
		out = append(out, v)
	}
	return out, nil
}
