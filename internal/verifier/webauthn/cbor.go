// Package webauthn checks the security keys and passkeys of the console's users: the
// registration of a new credential and the assertion given at sign-in (W3C Web Authentication,
// level 2). It does no I/O: the caller keeps credentials and challenges.
//
// Everything it parses comes from a browser driven by whoever holds the session, so every
// decoder is strict and bounded: sizes, nesting and item counts are capped before anything is
// allocated, and only the CBOR the ceremonies need is understood.
package webauthn

import (
	"encoding/binary"
	"errors"
	"math"
)

var errCBOR = errors.New("webauthn: malformed CBOR")

const (
	// maxDepth and maxItems bound a CBOR document: the attestation object nests three levels
	// (attestation map, statement map, its arrays), a COSE key has five entries.
	maxDepth = 4
	maxItems = 64
)

type kind uint8

const (
	kindUint kind = iota
	kindNeg
	kindBytes
	kindText
	kindArray
	kindMap
	kindSimple
)

// value is a decoded CBOR item. Integers are kept as int64: a key or algorithm outside that
// range is not one this package accepts anyway.
type value struct {
	kind  kind
	int   int64
	bytes []byte
	items []value
	// keys and items pair up for a map.
	keys []value
}

// decoder reads one item and leaves the rest of the input, as the authenticator data carries a
// COSE key followed by extensions with no length in between.
type decoder struct {
	data  []byte
	items int
}

func decodeCBOR(data []byte) (value, []byte, error) {
	d := &decoder{data: data}
	v, err := d.item(0)
	return v, d.data, err
}

// head reads an item's major type and argument. Indefinite lengths, and the reserved additional
// information values, are refused.
func (d *decoder) head() (byte, uint64, error) {
	if len(d.data) == 0 {
		return 0, 0, errCBOR
	}
	major, info := d.data[0]>>5, d.data[0]&0x1f
	d.data = d.data[1:]
	if info < 24 {
		return major, uint64(info), nil
	}
	size := 0
	switch info {
	case 24:
		size = 1
	case 25:
		size = 2
	case 26:
		size = 4
	case 27:
		size = 8
	default:
		return 0, 0, errCBOR
	}
	if len(d.data) < size {
		return 0, 0, errCBOR
	}
	var arg uint64
	for _, b := range d.data[:size] {
		arg = arg<<8 | uint64(b)
	}
	d.data = d.data[size:]
	return major, arg, nil
}

func (d *decoder) item(depth int) (value, error) {
	if depth > maxDepth {
		return value{}, errCBOR
	}
	if d.items++; d.items > maxItems {
		return value{}, errCBOR
	}
	major, arg, err := d.head()
	if err != nil {
		return value{}, err
	}
	switch major {
	case 0:
		if arg > math.MaxInt64 {
			return value{}, errCBOR
		}
		return value{kind: kindUint, int: int64(arg)}, nil
	case 1:
		if arg > math.MaxInt64 {
			return value{}, errCBOR
		}
		return value{kind: kindNeg, int: -1 - int64(arg)}, nil
	case 2, 3:
		// The length is checked against what is left before anything is sliced, so a header
		// claiming gigabytes allocates nothing.
		if arg > uint64(len(d.data)) {
			return value{}, errCBOR
		}
		b := d.data[:arg:arg]
		d.data = d.data[arg:]
		if major == 2 {
			return value{kind: kindBytes, bytes: b}, nil
		}
		return value{kind: kindText, bytes: b}, nil
	case 4, 5:
		// Each entry takes one byte at least: a count above the bytes left is a lie.
		if arg > uint64(len(d.data)) || arg > maxItems {
			return value{}, errCBOR
		}
		v := value{kind: kindArray}
		if major == 5 {
			v.kind = kindMap
		}
		for range arg {
			if major == 5 {
				k, err := d.item(depth + 1)
				if err != nil {
					return value{}, err
				}
				if k.kind != kindUint && k.kind != kindNeg && k.kind != kindText {
					return value{}, errCBOR
				}
				for _, seen := range v.keys {
					if sameKey(seen, k) {
						return value{}, errCBOR
					}
				}
				v.keys = append(v.keys, k)
			}
			e, err := d.item(depth + 1)
			if err != nil {
				return value{}, err
			}
			v.items = append(v.items, e)
		}
		return v, nil
	case 7:
		// false, true and null are what extension outputs use; floats and the rest are not
		// needed and are refused.
		if arg < 20 || arg > 22 {
			return value{}, errCBOR
		}
		return value{kind: kindSimple, int: int64(arg)}, nil
	}
	// Tags (6) have no place in these documents.
	return value{}, errCBOR
}

func sameKey(a, b value) bool {
	if a.kind != b.kind {
		return false
	}
	if a.kind == kindText {
		return string(a.bytes) == string(b.bytes)
	}
	return a.int == b.int
}

// get returns a map's entry for an integer key.
func (v value) get(key int64) (value, bool) {
	for i, k := range v.keys {
		if (k.kind == kindUint || k.kind == kindNeg) && k.int == key {
			return v.items[i], true
		}
	}
	return value{}, false
}

// field returns a map's entry for a text key.
func (v value) field(key string) (value, bool) {
	for i, k := range v.keys {
		if k.kind == kindText && string(k.bytes) == key {
			return v.items[i], true
		}
	}
	return value{}, false
}

func (v value) isInt() bool { return v.kind == kindUint || v.kind == kindNeg }

// u16 and u32 read the big-endian fields of the authenticator data.
func u16(b []byte) int    { return int(binary.BigEndian.Uint16(b)) }
func u32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }
