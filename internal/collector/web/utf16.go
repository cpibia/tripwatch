package web

import (
	"bufio"
	"io"
	"unicode/utf16"
	"unicode/utf8"
)

// utf16Sniff is how much of a script's start is looked at to tell UTF-16 without a byte order
// mark.
const utf16Sniff = 512

// textReader returns r read as UTF-8: a script in UTF-16, told by its byte order mark or, without
// one, by the zero byte beside each ASCII character, is decoded as a browser decodes it, so that
// the skimmer search does not read every other byte as noise. guessed says UTF-16 was told without
// a mark, which a file in UTF-8 can imitate: it is to be read as it is too.
func textReader(r io.Reader) (_ io.Reader, guessed bool) {
	br := bufio.NewReaderSize(r, 4096)
	head, _ := br.Peek(utf16Sniff)
	switch {
	case len(head) >= 2 && head[0] == 0xff && head[1] == 0xfe:
		_, _ = br.Discard(2)
		return &utf16Reader{r: br, little: true}, false
	case len(head) >= 2 && head[0] == 0xfe && head[1] == 0xff:
		_, _ = br.Discard(2)
		return &utf16Reader{r: br}, false
	}
	if little, ok := utf16Guess(head); ok {
		return &utf16Reader{r: br, little: little}, true
	}
	return br, false
}

// utf16Guess tells UTF-16 without a byte order mark from the start of a file: nearly every pair
// of bytes holds one zero byte, always on the same side, as ASCII text in UTF-16 does and UTF-8
// text never does.
func utf16Guess(head []byte) (little, ok bool) {
	pairs := len(head) / 2
	if pairs < 16 {
		return false, false
	}
	low, high := 0, 0
	for i := 0; i+1 < len(head); i += 2 {
		switch {
		case head[i] != 0 && head[i+1] == 0:
			low++
		case head[i] == 0 && head[i+1] != 0:
			high++
		}
	}
	switch {
	case low*10 >= pairs*9:
		return true, true
	case high*10 >= pairs*9:
		return false, true
	}
	return false, false
}

// utf16Reader decodes UTF-16 into UTF-8, surrogate pairs joined and lone ones replaced.
type utf16Reader struct {
	r       *bufio.Reader
	little  bool
	pending []byte
	pair    rune
}

func (u *utf16Reader) Read(p []byte) (int, error) {
	for len(u.pending) == 0 {
		var unit [2]byte
		if _, err := io.ReadFull(u.r, unit[:]); err != nil {
			if u.pair != 0 {
				u.pending, u.pair = utf8.AppendRune(u.pending, utf8.RuneError), 0
				break
			}
			if err == io.ErrUnexpectedEOF {
				err = io.EOF
			}
			return 0, err
		}
		c := rune(unit[0])<<8 | rune(unit[1])
		if u.little {
			c = rune(unit[1])<<8 | rune(unit[0])
		}
		if u.pair != 0 {
			high := u.pair
			u.pair = 0
			if r := utf16.DecodeRune(high, c); r != utf8.RuneError {
				u.pending = utf8.AppendRune(u.pending, r)
				continue
			}
			// A high surrogate without its low one: replaced, and this unit read on its own.
			u.pending = utf8.AppendRune(u.pending, utf8.RuneError)
		}
		if c >= 0xd800 && c < 0xdc00 {
			u.pair = c
			continue
		}
		u.pending = utf8.AppendRune(u.pending, c)
	}
	n := copy(p, u.pending)
	u.pending = u.pending[n:]
	return n, nil
}
