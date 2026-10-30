package web

import (
	"bytes"
	"regexp"
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
	// document ends a block at documentBlockCode: in a document's compressed streams "<?="
	// comes by chance every few megabytes, and the block it opens, never closed, would run to
	// the end of the file, while code planted there is short. blockLen counts the open block.
	document bool
	blockLen int
	mode     int
	heredoc  []byte // identifier closing the open heredoc or nowdoc
	nowdoc   bool   // the open heredoc is a nowdoc, which interpolates nothing
	atLine   bool   // in a heredoc, nothing but indentation seen on this line yet
	// nested are the strings an interpolation ("{$" or "${") left for code, innermost last:
	// the code runs to its matching brace, and may hold strings of its own.
	nested   []interpolation
	code     []byte
	backtick bool
	// call says a dangerous call was seen in the block, broken that it cannot compile.
	call   bool
	broken bool
	// glued says the block was opened by "<?" glued to a name PHP does not go on from, such as
	// an XML processing instruction quoted in a log ("<?mso-application"): it runs to the end of
	// the file, through stack traces full of call_user_func_array(, so only named signatures
	// count.
	glued bool
	// loose says the block was opened by "<?" alone or glued as above, as SQL dumps and logs
	// quote it: there a backtick around a bare word is how SQL quotes a name.
	loose bool
	// ran says a block PHP runs was opened earlier in the file: it may have defined any constant.
	ran bool
	// bareTick says a loose block holds a backtick, varCall that the block calls through a
	// variable.
	bareTick, varCall bool
	// named says the block was opened by "<?" glued to code rather than by a real open tag: as
	// the minified scripts a cache holds quote "<?(" in a regular expression, and run on through
	// their template literals, a backtick there counts only when it interpolates a variable.
	named bool
	carry []byte
	sigs  []string
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
	maxBlockCode = 1 << 20
	// documentBlockCode is the longest block read in a document, far more than any payload.
	documentBlockCode = 64 << 10
	blockOverlap      = 4 << 10
	maxHeredocIDSize  = 128
	maxHeredocBlanks  = 16
	// maxNested bounds interpolations inside interpolations; deeper nesting has no use in a
	// data file and is reported rather than followed.
	maxNested = 64
)

// codeInData returns the signatures of the PHP content would run if included, and whether the
// budget of code ran out before the end. document says content is a document, an archive or a
// dump, as documentLike tells.
func codeInData(content []byte, codeLeft *int64, document bool) (sigs []string, exhausted bool) {
	d := newDataSearch(codeLeft, document)
	d.feed(content, true)
	return d.signatures(), d.exhausted()
}

// dataSearch lexes content twice, since whether short open tags are on is php.ini's choice: with
// them off a "<?" followed by code is text, with them on it opens a block that can swallow, up
// to its "?>", a block that the other setting runs.
//
// A document or an archive (by its first bytes) gets the first pass only, with its blocks cut at
// documentBlockCode: its compressed streams hold "<?" and a blank every few kilobytes and "<?="
// every few megabytes, each opening a block that runs to the next "?>" and spends the run's
// budget on noise, while only signatures count in documents, code planted to run there opens
// with a full tag, and it is short.
type dataSearch struct {
	long, short codeSearch
	document    bool
}

func newDataSearch(codeLeft *int64, document bool) *dataSearch {
	return &dataSearch{long: codeSearch{codeLeft: codeLeft, document: document}, short: codeSearch{codeLeft: codeLeft, shortTags: true}, document: document}
}

func (d *dataSearch) feed(p []byte, final bool) {
	d.long.feed(p, final)
	if !d.document {
		d.short.feed(p, final)
	}
}

func (d *dataSearch) exhausted() bool { return d.long.exhausted || d.short.exhausted }

// signatures joins the two passes.
func (d *dataSearch) signatures() []string {
	sigs := slices.Clone(d.long.sigs)
	for _, sig := range d.short.sigs {
		if !slices.Contains(sigs, sig) {
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
		look := 6
		if c.shortTags {
			look = openTagLook + 3
		}
		if !more(look) {
			return 0
		}
		if i+1 < len(d) && d[i+1] == '?' {
			n, kind := openTagLen(d[i+2:], c.shortTags)
			// A name PHP stops on as an undefined constant can be defined by a block that ran
			// before it in the same file ("<?php define('foo', 1); ?>" and then "<?foo>1;"):
			// after one, every name glued to the tag is code.
			switch {
			case kind == tagExact && c.ran, kind == tagGlued && c.ran:
				kind = tagName
			case kind == tagExact:
				kind = tagNone
			}
			if kind != tagNone {
				c.mode, c.glued, c.loose, c.named = lexCode, kind == tagGlued, kind == tagGlued || kind == tagShort, kind == tagName
				c.ran = c.ran || kind != tagGlued
				return 2 + n
			}
		}
		return 1
	case lexCode:
		return c.stepCode(d, i, final)
	case lexSingle, lexDouble, lexBacktick:
		quote := map[int]byte{lexSingle: '\'', lexDouble: '"', lexBacktick: '`'}[c.mode]
		// A backtick around a bare word is how SQL quotes a name (a dump's `wp_posts`); one that
		// runs a command worth planting there passes it input or arguments.
		if c.mode == lexBacktick && b != '`' && !identByte(b) && !c.named {
			c.backtick = true
		}
		if c.mode == lexBacktick && c.named && (b == '$' || b == '{') {
			if !more(3) {
				return 0
			}
			if v := d[i+1:]; b == '$' && len(v) > 0 && identStart(v[0]) || b == '{' && len(v) > 1 && v[0] == '$' && identStart(v[1]) {
				c.backtick = true
			}
		}
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
		// In a block a real open tag started, any backtick runs a command: one word is enough
		// after putenv() has pointed PATH at the attacker's directory.
		if b == '`' && !c.loose && !c.named {
			c.backtick = true
		}
		if b == '`' && c.loose {
			c.bareTick = true
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
		if !more(3 + maxHeredocBlanks + 1 + maxHeredocIDSize + 4) {
			return 0
		}
		if id, n, ok := heredocStart(d[i:]); ok {
			c.emit(d[i : i+n])
			c.mode, c.heredoc, c.atLine = lexHeredoc, id, true
			c.nowdoc = bytes.Contains(d[i:i+n], []byte("'"))
			return n
		}
		// PHP takes a label of any length, and a body the lexer cannot follow as a string can
		// open a comment or close the block in front of the code after it. No data file needs
		// a label this long: it is named.
		if longHeredocLabel(d[i:]) {
			c.add("long_heredoc_label")
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
	if uncompilable(d[i]) || c.named && neverCompiles(c.code, d[i]) {
		c.broken = true
	}
	c.emit(d[i : i+1])
	return 1
}

// neverCompiles reports whether PHP refuses b after code: "{" after "=>" and "^" after "[",
// where it needs an expression, as in the arrow functions and regular expressions of the
// scripts a cache holds, which a "<?(" quoted in them can open as a block.
func neverCompiles(code []byte, b byte) bool {
	code = bytes.TrimSuffix(code, []byte(" "))
	return b == '{' && bytes.HasSuffix(code, []byte("=>")) || b == '^' && bytes.HasSuffix(code, []byte("["))
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

// Kinds of open tag, for how much of the block's content counts.
const (
	tagNone = iota
	// tagFull is "<?php" and a blank, or "<?=": PHP runs the block whatever its settings.
	tagFull
	// tagShort is "<?" and a blank, which only short_open_tag opens.
	tagShort
	// tagName is code glued to "<?" that PHP goes on from: a constant ("<?PHP_EOL;"), a call,
	// a namespaced class ("<?php\\x::class;"), a goto label ("<?phpinfo:"), a variable
	// ("<?$c=..."), an operator, a comment, anything but a processing instruction.
	tagName
	// tagGlued is an XML processing instruction glued to "<?" ("<?mso-application progid=",
	// "<?xml-stylesheet href=", "<?mso-application>"): PHP stops on it, so the block counts only
	// for named signatures.
	tagGlued
	// tagExact is "php" or "xml" glued to "<?" and to what follows ("<?php>", "<?php;"): PHP
	// stops on the undefined constant, and opens nothing for the search.
	tagExact
)

// openTagLen returns the length of what follows "<?" in an open tag, and its kind. With
// short_open_tag off only "<?php" and a blank and "<?=" open a block: a blank alone is text, and
// a block opened there would let a comment after it swallow the real "<?php" block that follows.
// With short tags "<?" opens a block whatever follows, except "php" and "xml" alone, on which
// PHP fails first ("<?xml version" makes it refuse the file, "<?php+" runs as the undefined
// constant php and stops there) unless a label, a call or a comment follows them.
func openTagLen(t []byte, short bool) (int, int) {
	blank := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	word := func(w string) bool { return len(t) >= len(w) && bytes.EqualFold(t[:len(w)], []byte(w)) }
	switch {
	case word("php") && len(t) > 3 && blank(t[3]):
		return 4, tagFull
	case len(t) > 0 && t[0] == '=':
		return 1, tagFull
	case !short:
		return 0, tagNone
	case len(t) > 0 && blank(t[0]):
		return 1, tagShort
	case len(t) > 0 && strings.IndexByte(">)]},*|^%:", t[0]) >= 0:
		// No statement starts with these: "<?>" is a parse error, not a block.
		return 0, tagNone
	}
	j := 0
	for j < len(t) && (identByte(t[j]) || t[j] == '\\') {
		if j == openTagLook {
			return 0, tagName
		}
		j++
	}
	exact := j == 3 && (word("php") || word("xml"))
	k := j
	for k < len(t) && blank(t[k]) {
		if k == openTagLook {
			return 0, tagName
		}
		k++
	}
	goesOn := j > 0 && k < len(t) && strings.IndexByte(":(/#;\\", t[k]) >= 0
	switch {
	case exact && goesOn && t[k] != ';':
		return 0, tagName
	case exact && k == j && k < len(t):
		return 0, tagExact
	case exact && !bytes.HasPrefix(bytes.ToLower(t[k:]), []byte("version")):
		// Only a real XML prolog is never code; "xml" or "php" then a blank and anything else is,
		// once a block that ran could have defined the name.
		return 0, tagExact
	case exact:
		return 0, tagNone
	case goesOn:
		return 0, tagName
	}
	if processingInstruction(t) && !runsFirst(t) {
		return 0, tagGlued
	}
	return 0, tagName
}

// runsFirst reports a name glued to "<?" that PHP evaluates without failing: a keyword ("<?echo",
// "<?const X=1;"), true, false or null, or a name of the shape of the constants PHP and its
// extensions define (upper case or an underscore: "<?PHP_EOL>1;", "<?E_ALL"). Since PHP 8 any
// other name is an undefined constant, an Error at the block's first statement before anything
// after it runs, as the lower-case targets of processing instructions are.
func runsFirst(t []byte) bool {
	j := 0
	for j < len(t) && j < openTagLook && identByte(t[j]) {
		j++
	}
	name := string(t[:j])
	return slices.Contains(phpKeywords, strings.ToLower(name)) || strings.ContainsAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_")
}

// phpKeywords are the words that start a statement or an expression without naming a constant.
var phpKeywords = []string{"abstract", "and", "array", "as", "break", "callable", "case", "catch", "class", "clone", "const", "continue",
	"declare", "default", "die", "do", "echo", "else", "elseif", "empty", "enum", "eval", "exit", "extends", "false", "final", "finally",
	"fn", "for", "foreach", "function", "global", "goto", "if", "implements", "include", "include_once", "instanceof", "insteadof",
	"interface", "isset", "list", "match", "namespace", "new", "null", "or", "parent", "print", "private", "protected", "public",
	"readonly", "require", "require_once", "return", "self", "static", "switch", "throw", "trait", "true", "try", "unset", "use",
	"var", "while", "xor", "yield"}

// processingInstruction reports whether what follows "<?" is shaped as an XML processing
// instruction: a target, a name starting with a letter, then "?>", ">" or a blank and a
// pseudo-attribute ("name=" or "name ="). No target starts with "$", "@", "(", "/" or a quote, and
// PHP runs whatever does; a target followed by anything else ("<?PHP_EOL.$c", "<?E_ALL|$c") is
// code PHP goes on from. Data that ends within the target is left as an instruction, as before
// the rest of it is seen.
func processingInstruction(t []byte) bool {
	piByte := func(c byte) bool { return identByte(c) || c == '-' || c == '.' }
	blank := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	if len(t) == 0 || !identStart(t[0]) {
		return false
	}
	i := 0
	for i < len(t) && i < openTagLook && piByte(t[i]) {
		i++
	}
	switch {
	case i == len(t):
		return true
	case t[i] == '>' || bytes.HasPrefix(t[i:], []byte("?>")):
		return true
	case !blank(t[i]):
		return false
	}
	for i < len(t) && i < 2*openTagLook && blank(t[i]) {
		i++
	}
	if bytes.HasPrefix(t[i:], []byte("?>")) {
		return true
	}
	start := i
	for i < len(t) && i < 3*openTagLook && piByte(t[i]) {
		i++
	}
	for i < len(t) && i < 3*openTagLook && blank(t[i]) {
		i++
	}
	return i > start && i < len(t) && t[i] == '=' || i == len(t)
}

// openTagLook bounds how far after "<?" the short pass reads to judge a word glued to the tag.
const openTagLook = 64

// heredocStart reads "<<<ID", "<<<\"ID\"" or "<<<'ID'" and the line break after it.
func heredocStart(d []byte) (id []byte, n int, ok bool) {
	if !bytes.HasPrefix(d, []byte("<<<")) {
		return nil, 0, false
	}
	j := 3
	for j < len(d) && j-3 < maxHeredocBlanks && (d[j] == ' ' || d[j] == '\t') {
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

// longHeredocLabel reports "<<<" followed by a label longer than the lexer follows, or by more
// blanks before it than it looks ahead for.
func longHeredocLabel(d []byte) bool {
	if !bytes.HasPrefix(d, []byte("<<<")) {
		return false
	}
	j := 3
	for j < len(d) && (d[j] == ' ' || d[j] == '\t') {
		j++
	}
	if j-3 > maxHeredocBlanks {
		return true
	}
	if j < len(d) && (d[j] == '"' || d[j] == '\'') {
		j++
	}
	start := j
	for j < len(d) && j-start <= maxHeredocIDSize && identByte(d[j]) && (j > start || identStart(d[j])) {
		j++
	}
	return j-start > maxHeredocIDSize
}

func identByte(c byte) bool { return isWordByte(c) || c >= 0x80 }

// identStart reports a byte a PHP name can start with.
func identStart(c byte) bool { return identByte(c) && (c < '0' || c > '9') }

// emit adds code of the current block, matching it in parts when it grows too long.
func (c *codeSearch) emit(p []byte) {
	if c.broken && c.shortTags {
		return
	}
	c.code = append(c.code, p...)
	c.blockLen += len(p)
	if c.document && c.blockLen > documentBlockCode {
		c.endBlock()
		return
	}
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
		if !c.exhausted && !c.broken && !c.glued {
			// In a block a dump or a log opens, a backtick around a bare word is a quoted name;
			// one next to a call through a variable, which can be putenv() under a built name,
			// runs a command found on a PATH the attacker set.
			if c.backtick || c.loose && c.bareTick && c.varCall {
				c.add("backtick_exec")
			}
			if c.call && len(c.sigs) == 0 {
				c.add("dangerous_call")
			}
		}
	}
	c.mode, c.code, c.backtick, c.heredoc, c.call, c.broken, c.glued, c.loose, c.named = lexText, c.code[:0], false, nil, false, false, false, false, false
	c.bareTick, c.varCall = false, false
	c.nested, c.nowdoc, c.blockLen = c.nested[:0], false, 0
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
	if variableCall.Match(c.code) {
		c.varCall = true
	}
}

// variableCall is a call that hides the name of what it calls: through a variable ("$f(",
// "$a[0](", "${'f'}("), through an expression or a string ("(...)(", "'putenv'("), handing a
// callback to a function that calls it (array_map, call_user_func, a filter's FILTER_CALLBACK...),
// or through a method that calls what it was given (ReflectionFunction's invoke, a closure's or an
// anonymous class's __invoke).
var variableCall = regexp.MustCompile(`\$[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]* ?(?:\[[^\]]*\] ?)*\(|\$\{[^}]*\} ?\(|\) ?\(|['"] ?\(|` +
	`(?i)\b(?:array_map|array_filter|array_walk(?:_recursive)?|array_reduce|call_user_func(?:_array)?|forward_static_call(?:_array)?|usort|uasort|uksort|` +
	`register_shutdown_function|register_tick_function|iterator_apply|ob_start|set_error_handler|set_exception_handler|spl_autoload_register|preg_replace_callback(?:_array)?) ?\(|` +
	`(?i)\bReflection(?:Function|Method)\b|-> ?(?:invoke(?:Args)?|__invoke|call|bindTo) ?\(|:: ?fromCallable ?\(|` +
	`\bFILTER_CALLBACK\b|\bnew class\b|(?i)\barray_(?:find(?:_key)?|any|all) ?\(`)
