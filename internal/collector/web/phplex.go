package web

import (
	"bytes"
	"slices"
	"strings"
)

// codeSearch finds the PHP a data file would run if it were included, in content given in one
// piece or in many: it follows PHP's lexer from one piece to the next (outside PHP, in code, in
// a string, a shell command, a comment or a heredoc), so a block is judged whole however far its
// code sits from its open tag. Each block's code, without its comments and with runs of blanks
// folded, is matched against the signatures; a block longer than maxBlockCode is matched in
// parts that overlap. The cost stays linear in the size of the file.
//
// Binary data (a PDF, an archive) holds "<?=" or "<? " every few megabytes by chance, and the
// random "code" after it soon holds a backtick or a word like "exec(". Such a block also holds
// control bytes outside its strings, which PHP 8 refuses to compile, failing the whole file: the
// weak signals of a block like that (backtick_exec, dangerous_call) are dropped, the named
// signatures still count. PHP 7 only warned about those bytes; it is past its end of life.
type codeSearch struct {
	// shortTags opens a block on "<?" whatever follows, as PHP does with short_open_tag on.
	// Under it a block that cannot compile makes the whole file fail, so it is dropped unread.
	shortTags bool
	mode      int
	heredoc   []byte // identifier closing the open heredoc or nowdoc
	nowdoc    bool   // the open heredoc is a nowdoc, which interpolates nothing
	atLine    bool   // in a heredoc, nothing but indentation seen on this line yet
	// nested are the strings an interpolation ("{$" or "${") left for code, innermost last:
	// the code runs to its matching brace, and may hold strings of its own.
	nested   []interpolation
	code     []byte
	backtick bool
	// call says a dangerous call was seen in the block, broken that it cannot compile.
	call   bool
	broken bool
	carry  []byte
	sigs   []string
	// codeLeft, when set, is the budget of code matched; exhausted says it ran out.
	codeLeft  *int64
	exhausted bool
}

type interpolation struct {
	mode    int // the string mode to go back to
	braces  int // braces opened in the interpolated code and not yet closed
	heredoc []byte
}

// Modes of the lexer.
const (
	lexText = iota
	lexCode
	lexSingle
	lexDouble
	lexBacktick
	lexBlockComment
	lexLineComment
	lexHeredoc
)

const (
	maxBlockCode     = 1 << 20
	blockOverlap     = 4 << 10
	maxHeredocIDSize = 128
	// maxNested bounds interpolations inside interpolations; deeper nesting has no use in a
	// data file and is reported rather than followed.
	maxNested = 64
)

// codeInData returns the signatures of the PHP content would run if included, and whether the
// budget of code ran out before the end.
func codeInData(content []byte, codeLeft *int64) (sigs []string, exhausted bool) {
	d := newDataSearch(codeLeft)
	d.feed(content, true)
	return d.signatures(), d.exhausted()
}

// dataSearch lexes content twice, since whether short open tags are on is php.ini's choice: with
// them off a "<?" followed by code is text, with them on it opens a block that can swallow, up
// to its "?>", a block that the other setting runs.
type dataSearch struct{ long, short codeSearch }

func newDataSearch(codeLeft *int64) *dataSearch {
	return &dataSearch{long: codeSearch{codeLeft: codeLeft}, short: codeSearch{codeLeft: codeLeft, shortTags: true}}
}

func (d *dataSearch) feed(p []byte, final bool) {
	d.long.feed(p, final)
	d.short.feed(p, final)
}

func (d *dataSearch) exhausted() bool { return d.long.exhausted || d.short.exhausted }

// signatures joins the two passes. From the short one only the named signatures count: there a
// "<?" quoted in a log (an XML processing instruction) opens a block that runs to the end of the
// file, through stack traces full of call_user_func_array(; the weak signals of real code are
// found by the long pass, where the open tag is unambiguous.
func (d *dataSearch) signatures() []string {
	sigs := slices.Clone(d.long.sigs)
	for _, sig := range d.short.sigs {
		if !slices.Contains(sigs, sig) && !slices.Contains(weakCodeSignals, sig) {
			sigs = append(sigs, sig)
		}
	}
	return sigs
}

// feed lexes the next piece of the content; final marks the last one.
func (c *codeSearch) feed(p []byte, final bool) {
	data := p
	if len(c.carry) > 0 {
		data = append(c.carry, p...)
		c.carry = nil
	}
	i := 0
	for i < len(data) && !c.exhausted {
		n := c.step(data, i, final)
		if n == 0 {
			// The next token needs bytes not given yet.
			c.carry = append([]byte(nil), data[i:]...)
			return
		}
		i += n
	}
	if final {
		c.endBlock()
	}
}

// step lexes the token at i and returns its length, or 0 when deciding needs more bytes.
func (c *codeSearch) step(d []byte, i int, final bool) int {
	more := func(n int) bool { return i+n <= len(d) || final }
	b := d[i]
	switch c.mode {
	case lexText:
		if b != '<' {
			j := bytes.IndexByte(d[i:], '<')
			if j < 0 {
				return len(d) - i
			}
			return j
		}
		if !more(6) {
			return 0
		}
		if i+1 < len(d) && d[i+1] == '?' {
			if n, ok := openTagLen(d[i+2:], c.shortTags); ok {
				c.mode = lexCode
				return 2 + n
			}
		}
		return 1
	case lexCode:
		return c.stepCode(d, i, final)
	case lexSingle, lexDouble, lexBacktick:
		quote := map[int]byte{lexSingle: '\'', lexDouble: '"', lexBacktick: '`'}[c.mode]
		if b == '\\' {
			if !more(2) {
				return 0
			}
			c.emit(d[i:min(i+2, len(d))])
			return min(2, len(d)-i)
		}
		if c.mode != lexSingle && (b == '{' || b == '$') {
			if !more(2) {
				return 0
			}
			if n := c.interpolates(d, i); n != 0 {
				return n
			}
		}
		if b == quote {
			c.mode = lexCode
		}
		c.emit(d[i : i+1])
		return 1
	case lexBlockComment:
		j := bytes.Index(d[i:], []byte("*/"))
		if j < 0 {
			if final {
				return len(d) - i
			}
			// Keep the last byte: it may be the "*" of the end.
			if n := len(d) - i - 1; n > 0 {
				return n
			}
			return 0
		}
		c.mode = lexCode
		c.emit([]byte(" "))
		return j + 2
	case lexLineComment:
		// The line ends the comment, and so does "?>", which ends the block too. A carriage
		// return alone ends a line for PHP as a line feed does.
		if b == '\n' || b == '\r' {
			c.mode = lexCode
			c.emit([]byte("\n"))
			return 1
		}
		if b == '?' {
			if !more(2) {
				return 0
			}
			if i+1 < len(d) && d[i+1] == '>' {
				c.endBlock()
				return 2
			}
		}
		return 1
	case lexHeredoc:
		return c.stepHeredoc(d, i, final)
	}
	return 1
}

func (c *codeSearch) stepCode(d []byte, i int, final bool) int {
	more := func(n int) bool { return i+n <= len(d) || final }
	switch b := d[i]; b {
	case '{', '}':
		if len(c.nested) > 0 {
			top := &c.nested[len(c.nested)-1]
			switch {
			case b == '{':
				top.braces++
			case top.braces > 0:
				top.braces--
			default:
				c.mode, c.heredoc, c.nowdoc, c.atLine = top.mode, top.heredoc, false, false
				c.nested = c.nested[:len(c.nested)-1]
			}
		}
	case '?':
		if !more(2) {
			return 0
		}
		// Inside an interpolation "?>" cannot end the block: the string around it is still open.
		if i+1 < len(d) && d[i+1] == '>' && len(c.nested) == 0 {
			c.endBlock()
			return 2
		}
	case '\'', '"', '`':
		c.mode = map[byte]int{'\'': lexSingle, '"': lexDouble, '`': lexBacktick}[b]
		if b == '`' {
			c.backtick = true
		}
	case '/':
		if !more(2) {
			return 0
		}
		if i+1 < len(d) && d[i+1] == '*' {
			c.mode = lexBlockComment
			return 2
		}
		if i+1 < len(d) && d[i+1] == '/' {
			c.mode = lexLineComment
			return 2
		}
	case '#':
		if !more(2) {
			return 0
		}
		if i+1 >= len(d) || d[i+1] != '[' {
			c.mode = lexLineComment
			return 1
		}
	case '<':
		if !more(3 + maxHeredocIDSize + 4) {
			return 0
		}
		if id, n, ok := heredocStart(d[i:]); ok {
			c.emit(d[i : i+n])
			c.mode, c.heredoc, c.atLine = lexHeredoc, id, true
			c.nowdoc = bytes.Contains(d[i:i+n], []byte("'"))
			return n
		}
	case '_':
		// PHP compiles nothing after __halt_compiler: what follows cannot break the block.
		if !more(len(haltCompiler)) {
			return 0
		}
		if c.halts(d, i) {
			c.emit(d[i : i+len(haltCompiler)])
			c.endBlock()
			return len(haltCompiler)
		}
	case ' ', '\t', '\n', '\r':
		if len(c.code) > 0 && c.code[len(c.code)-1] == ' ' {
			return 1
		}
		c.emit([]byte(" "))
		return 1
	}
	if uncompilable(d[i]) {
		c.broken = true
	}
	c.emit(d[i : i+1])
	return 1
}

// interpolates starts the code of an interpolation at i ("{$" or "${") in a string that
// interpolates, and returns its length; 0 when there is none.
func (c *codeSearch) interpolates(d []byte, i int) int {
	if i+2 > len(d) || string(d[i:i+2]) != "{$" && string(d[i:i+2]) != "${" {
		return 0
	}
	if len(c.nested) == maxNested {
		c.add("nested_interpolation")
		return 0
	}
	c.nested = append(c.nested, interpolation{mode: c.mode, heredoc: c.heredoc})
	c.mode = lexCode
	c.emit(d[i : i+2])
	return 2
}

var haltCompiler = []byte("__halt_compiler")

// halts reports whether the code at i is the keyword __halt_compiler, not part of a longer name, a
// variable, a property, a method or a namespaced name.
func (c *codeSearch) halts(d []byte, i int) bool {
	end := i + len(haltCompiler)
	if end > len(d) || !bytes.EqualFold(d[i:end], haltCompiler) || (end < len(d) && identByte(d[end])) {
		return false
	}
	before := bytes.TrimRight(c.code, " ")
	if len(before) == 0 {
		return true
	}
	last := before[len(before)-1]
	return !identByte(last) && !strings.ContainsRune("$>:\\", rune(last))
}

// uncompilable reports whether PHP 8 refuses a byte in code, outside strings and comments: the
// control characters other than the blanks it skips. Vertical tab and form feed are left out:
// whether every version refuses them is not worth an evasion.
func uncompilable(b byte) bool {
	return b <= 0x08 || (b >= 0x0e && b <= 0x1f) || b == 0x7f
}

// stepHeredoc looks for the line that closes the heredoc: its identifier, indented or not,
// followed by anything that cannot continue an identifier.
func (c *codeSearch) stepHeredoc(d []byte, i int, final bool) int {
	b := d[i]
	if b == '\n' || b == '\r' {
		c.atLine = true
		c.emit(d[i : i+1])
		return 1
	}
	if !c.atLine {
		if !c.nowdoc && (b == '{' || b == '$') {
			if i+2 > len(d) && !final {
				return 0
			}
			if n := c.interpolates(d, i); n != 0 {
				return n
			}
			c.emit(d[i : i+1])
			return 1
		}
		stops := "\r\n"
		if !c.nowdoc {
			stops = "\r\n{$"
		}
		j := bytes.IndexAny(d[i:], stops)
		if j < 0 {
			j = len(d) - i
		}
		c.emit(d[i : i+j])
		return j
	}
	if b == ' ' || b == '\t' {
		return 1
	}
	c.atLine = false
	if i+len(c.heredoc)+1 > len(d) && !final {
		c.atLine = true
		return 0
	}
	if bytes.HasPrefix(d[i:], c.heredoc) && (i+len(c.heredoc) == len(d) || !identByte(d[i+len(c.heredoc)])) {
		c.mode = lexCode
		c.emit(c.heredoc)
		return len(c.heredoc)
	}
	return 0 + c.stepHeredoc(d, i, final)
}

// openTagLen returns the length of what follows "<?" in an open tag PHP runs: "php" and a blank,
// "=", or a blank alone. With short tags "<?" opens a block whatever follows, but for "php" and
// "xml" glued to more text: "<?xml version" makes PHP refuse the file and "<?php+" runs as the
// undefined constant php and stops there, while "<?php:" is a goto label and "<?php::class;"
// compiles, so those two run what follows.
func openTagLen(t []byte, short bool) (int, bool) {
	blank := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	word := func(w string) bool { return len(t) >= len(w) && bytes.EqualFold(t[:len(w)], []byte(w)) }
	switch {
	case word("php") && len(t) > 3 && blank(t[3]):
		return 4, true
	case len(t) > 0 && (t[0] == '=' || blank(t[0])):
		return 1, true
	case !short:
		return 0, false
	case word("xml") || word("php"):
		return 0, len(t) > 3 && t[3] == ':'
	}
	return 0, true
}

// heredocStart reads "<<<ID", "<<<\"ID\"" or "<<<'ID'" and the line break after it.
func heredocStart(d []byte) (id []byte, n int, ok bool) {
	if !bytes.HasPrefix(d, []byte("<<<")) {
		return nil, 0, false
	}
	j := 3
	for j < len(d) && (d[j] == ' ' || d[j] == '\t') {
		j++
	}
	var quote byte
	if j < len(d) && (d[j] == '"' || d[j] == '\'') {
		quote = d[j]
		j++
	}
	start := j
	for j < len(d) && j-start < maxHeredocIDSize && identByte(d[j]) && (j > start || d[j] < '0' || d[j] > '9') {
		j++
	}
	if j == start {
		return nil, 0, false
	}
	id = d[start:j]
	if quote != 0 {
		if j >= len(d) || d[j] != quote {
			return nil, 0, false
		}
		j++
	}
	// PHP takes "\r\n", "\n" and a carriage return alone for the end of the line.
	switch {
	case j+1 < len(d) && d[j] == '\r' && d[j+1] == '\n':
		j += 2
	case j < len(d) && (d[j] == '\n' || d[j] == '\r'):
		j++
	default:
		return nil, 0, false
	}
	return append([]byte(nil), id...), j, true
}

func identByte(c byte) bool { return isWordByte(c) || c >= 0x80 }

// emit adds code of the current block, matching it in parts when it grows too long.
func (c *codeSearch) emit(p []byte) {
	if c.broken && c.shortTags {
		return
	}
	c.code = append(c.code, p...)
	if len(c.code) > maxBlockCode {
		c.match()
		c.code = append(c.code[:0], c.code[len(c.code)-blockOverlap:]...)
	}
}

// endBlock matches what is left of the block, adds its weak signals unless it cannot compile,
// and goes back to text.
func (c *codeSearch) endBlock() {
	if c.mode != lexText && (!c.broken || !c.shortTags) {
		c.match()
		if !c.exhausted && !c.broken {
			if c.backtick {
				c.add("backtick_exec")
			}
			if c.call && len(c.sigs) == 0 {
				c.add("dangerous_call")
			}
		}
	}
	c.mode, c.code, c.backtick, c.heredoc, c.call, c.broken = lexText, c.code[:0], false, nil, false, false
	c.nested, c.nowdoc = c.nested[:0], false
}

func (c *codeSearch) add(sig string) {
	if !slices.Contains(c.sigs, sig) {
		c.sigs = append(c.sigs, sig)
	}
}

func (c *codeSearch) match() {
	if c.codeLeft != nil {
		if *c.codeLeft < int64(len(c.code)) {
			c.exhausted = true
			return
		}
		*c.codeLeft -= int64(len(c.code))
	}
	for _, sig := range matchSignatures(c.code, true) {
		if sig != "encoded_blob" {
			c.add(sig)
		}
	}
	if dangerousCall.Match(c.code) {
		c.call = true
	}
}
