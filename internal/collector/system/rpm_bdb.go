package system

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// Berkeley DB hash database, as rpm's Packages file: page 0 is the hash metadata, every
// record sits on a hash page as a key and a value item, and a value as large as an rpm header
// is stored off-page in a chain of overflow pages. Records are read by scanning every hash
// page in order rather than by following buckets: it needs no hash function and reaches each
// page once. Page fields are in the byte order of the machine that created the file, which
// the magic number tells; rpm's header blob inside is big-endian regardless.
const (
	bdbHashMagic   = 0x061561
	bdbPageHeader  = 26
	bdbHashMeta    = 8
	bdbHash        = 13
	bdbHashUnsort  = 2
	bdbOverflow    = 7
	bdbItemKeyData = 1
	bdbItemOffPage = 3
)

var errBDB = errors.New("malformed Berkeley DB file")

func bdbRpmHeaders(fsys fs.FS, name string, each func([]byte) error) error {
	r, size, closeFile, err := openReaderAt(fsys, name)
	if err != nil {
		return err
	}
	defer closeFile()

	meta, err := readPage(r, 0, 512)
	if err != nil {
		return err
	}
	var order binary.ByteOrder = binary.LittleEndian
	switch {
	case binary.LittleEndian.Uint32(meta[12:]) == bdbHashMagic:
	case binary.BigEndian.Uint32(meta[12:]) == bdbHashMagic:
		order = binary.BigEndian
	default:
		return fmt.Errorf("%w: not a hash database", errBDB)
	}
	pageSize := order.Uint32(meta[20:])
	lastPage := order.Uint32(meta[32:])
	if meta[25] != bdbHashMeta || pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 ||
		int64(lastPage)+1 > size/int64(pageSize) {
		return fmt.Errorf("%w: bad metadata", errBDB)
	}

	ps := int(pageSize)
	for pgno := uint32(1); pgno <= lastPage; pgno++ {
		page, err := readPage(r, int64(pgno)*int64(ps), ps)
		if err != nil {
			return err
		}
		if page[25] != bdbHash && page[25] != bdbHashUnsort {
			continue
		}
		entries := int(order.Uint16(page[20:]))
		if bdbPageHeader+2*entries > ps {
			return fmt.Errorf("%w: page %d: too many entries", errBDB, pgno)
		}
		offsets := make([]int, entries)
		for i := range offsets {
			offsets[i] = int(order.Uint16(page[bdbPageHeader+2*i:]))
		}
		// Entries alternate key and value; only values are needed, rpm's key is the package
		// instance number.
		for i := 1; i < entries; i += 2 {
			off := offsets[i]
			if off < bdbPageHeader+2*entries || off >= ps {
				return fmt.Errorf("%w: page %d: bad item offset", errBDB, pgno)
			}
			var value []byte
			switch page[off] {
			case bdbItemOffPage:
				if off+12 > ps {
					return fmt.Errorf("%w: page %d: truncated item", errBDB, pgno)
				}
				value, err = bdbOverflowChain(r, order, ps, lastPage, order.Uint32(page[off+4:]), order.Uint32(page[off+8:]))
				if err != nil {
					return err
				}
			case bdbItemKeyData:
				// Items are packed from the end of the page; an inline item ends where the
				// next one above it starts.
				end := ps
				for _, o := range offsets {
					if o > off && o < end {
						end = o
					}
				}
				value = page[off+1 : end]
			default:
				continue
			}
			// The record under key 0 holds rpm's instance counter, not a header.
			if len(value) <= 8 {
				continue
			}
			if err := each(value); err != nil {
				return fmt.Errorf("page %d: %w", pgno, err)
			}
		}
	}
	return nil
}

// bdbOverflowChain reads a value of length total from the overflow pages starting at pgno.
// The chain is followed at most as many pages as the value needs, so a loop cannot spin.
func bdbOverflowChain(r io.ReaderAt, order binary.ByteOrder, ps int, lastPage, pgno, total uint32) ([]byte, error) {
	if total > maxRpmHeader {
		return nil, fmt.Errorf("%w: value of %d bytes", errBDB, total)
	}
	want := int(total)
	out := make([]byte, 0, want)
	for len(out) < want {
		if pgno == 0 || pgno > lastPage {
			return nil, fmt.Errorf("%w: overflow chain leaves the file", errBDB)
		}
		page, err := readPage(r, int64(pgno)*int64(ps), ps)
		if err != nil {
			return nil, err
		}
		n := int(order.Uint16(page[22:]))
		if page[25] != bdbOverflow || n == 0 || bdbPageHeader+n > ps || len(out)+n > want {
			return nil, fmt.Errorf("%w: bad overflow page %d", errBDB, pgno)
		}
		out = append(out, page[bdbPageHeader:bdbPageHeader+n]...)
		pgno = order.Uint32(page[16:])
	}
	return out, nil
}
