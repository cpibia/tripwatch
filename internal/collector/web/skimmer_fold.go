package web

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Bounds of the folding of a script's string expressions.
const (
	maxFoldTokens    = 1 << 20
	maxFoldConstants = 4096
	maxFoldValue     = 4 << 10
	maxFoldDepth     = 8
	// maxFoldSteps bounds the terms read in a piece, whatever its shape: past it the piece is
	// left unfolded rather than read slowly.
	maxFoldSteps = 4 << 20
)

// jsToken is a token of a script as the folding reads it: a string (its value decoded), a name,
// a number, or one character of punctuation.
type jsToken struct {
	kind byte // 's' string, 'n' name, '0' number, 'p' punctuation, 'r' regular expression
	text string
	at   int // where it starts in the piece
	// closed is, for ")" and "}", what the bracket closed; newline says a line break came before.
	closed  byte
	newline bool
}

// What an open bracket started, as JavaScript tokenizers keep it (acorn's token contexts): it
// decides whether a "/" after the closing bracket divides or starts a pattern.
const (
	ctxCondition = 'c' // ( of if, while, for, with: a statement follows, so a pattern
	ctxParen     = 'e' // ( of an expression or a call: a division
	ctxBlock     = 'b' // { of a block or a declared function: a pattern
	ctxObject    = 'o' // { of an object: a division
	ctxFuncExpr  = 'f' // { of a function expression's body: statements inside, a division after
	ctxClass     = 'K' // { of a declared class's body: a pattern after
	ctxClassExpr = 'k' // { of a class expression's body: a division after
	ctxArrow     = 'a' // { of an arrow function's body: either, past what a tokenizer knows
	ctxSquare    = '['
	ctxTemplate  = '$' // ${ of a template literal: its text goes on after the "}"
	ctxUnknown   = '?' // a bracket opened before the piece, or past the bound on the stack
)

// maxContexts bounds the open brackets whose context is kept.
const maxContexts = 4096

// jsTokens splits content into tokens, comments and blanks left out. A template literal with
// substitutions of string literals only (`${”}`) is one string; one with any other substitution
// is read as JavaScript reads it: its text passed over, each substitution read as code up to the
// "}" that closes it, then the text again.
// A "/" after ")" or "}" divides or starts a pattern depending on what the bracket closed, which
// a stack of what each open bracket started decides where it is certain. Where it is not, after
// the body of an arrow function, a bracket opened before the piece or one whose start the stack
// could not tell, regexAfterClose picks one reading, the folding reads the script both ways, and
// ambiguous says such a "/" was met. The stack starts as from, and carry is what it was at the
// first token at or past carryAt, for the piece that goes on from there.
// A module reads "<!--" and "-->" as operators, a script as comments: module picks one.
func jsTokens(content []byte, regexAfterClose, module bool, from *brackets, carryAt int) (out []jsToken, scanned int, deep, ambiguous bool, carry *brackets) {
	depth := 0
	b := from.clone()
	// A file starts a line; a piece goes on from where the one before left the line.
	newline := from == nil || from.lineStart
	i := 0
	// The piece starts inside what the one before left open there.
	inside := b.inside
	b.inside = 0
	open := false
	switch inside {
	case '`':
		var sub bool
		i, sub, open = templateText(content, 0)
		out = append(out, b.templateToken(sub))
	case '\'', '"':
		i, _, open = stringEnd(content, 0, inside)
		out = append(out, jsToken{kind: 's'})
	case 'r':
		i, open = regexRest(content, 0)
		out = append(out, jsToken{kind: 'r'})
	case '*':
		if j := bytes.Index(content, []byte("*/")); j >= 0 {
			i = j + 2
		} else {
			i, open = len(content), true
		}
	case '\n':
		i, _ = lineEnd(content, 0)
		open = i == len(content)
	}
	if open && carryAt < len(content) {
		// Still open at the end of this piece too.
		carry = b.clone()
		carry.inside = inside
	}
	scanned += i
	regexFailedUntil := 0
	for i < len(content) && len(out) < maxFoldTokens {
		c := content[i]
		if c == '/' && len(out) > 0 && uncertainBefore(out) {
			ambiguous = true
		}
		if carry == nil && i >= carryAt {
			carry = b.clone()
			carry.lineStart = newline || len(out) == 0 && from == nil
		}
		at, start := len(out), i
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '\n' || c == '\r' || c == lineSeparator:
			newline = true
			i++
		case c == '/' && i+1 < len(content) && content[i+1] == '/',
			!module && c == '<' && bytes.HasPrefix(content[i:], []byte("<!--")),
			!module && c == '-' && bytes.HasPrefix(content[i:], []byte("-->")) && newline,
			c == '#' && i == 0 && from == nil && bytes.HasPrefix(content, []byte("#!")):
			// A line comment, also in the forms a browser's script reads as one: "<!--"
			// anywhere, "-->" first on its line, and the "#!" line that starts a file.
			i, _ = lineEnd(content, i)
		case c == '/' && i+1 < len(content) && content[i+1] == '*':
			j := bytes.Index(content[i+2:], []byte("*/"))
			if j < 0 {
				j = len(content) - i - 2
			}
			if _, ok := lineEnd(content[i+2:i+2+j], 0); ok {
				newline = true
			}
			i = min(i+j+4, len(content))
		// A comment open where the piece starts is in the state the piece before carried: a "/"
		// after "*" here is a division or a pattern like any other.
		case c == '/' && i >= regexFailedUntil && regexAllowed(out, regexAfterClose):
			end, closed := regexEnd(content, i)
			scanned += max(end-i, 1)
			switch {
			case closed || end == len(content):
				// Past the end of the piece the pattern goes on in the next.
				out = append(out, jsToken{kind: 'r', text: ""})
				i = end
			default:
				// Not closed on its line: no "/" before the line's end starts a pattern any more,
				// so the line is scanned once, and read on as code from the next byte.
				regexFailedUntil = end
				out = append(out, jsToken{kind: 'p', text: "/"})
				i++
			}
		case c == '`':
			if lit, next, ok := jsFoldLiteral(content, i); ok {
				scanned += max(next-i, 1)
				out = append(out, jsToken{kind: 's', text: string(lit)})
				i = next
				break
			}
			next, sub, _ := templateText(content, i+1)
			scanned += max(next-i, 1)
			if carry == nil && i+1 <= carryAt && carryAt < next {
				carry = b.clone()
				carry.inside = '`'
			}
			i = next
			if sub {
				if depth++; depth > maxBracketDepth {
					deep = true
				}
			}
			out = append(out, b.templateToken(sub))
		case c == '\'' || c == '"':
			if lit, next, ok := jsFoldLiteral(content, i); ok {
				scanned += max(next-i, 1)
				out = append(out, jsToken{kind: 's', text: string(lit)})
				i = next
				break
			}
			// Longer than what is kept, or open at the end of its line: never read as code. The
			// rest of a long one is passed over to its end, its text not kept.
			next, closed, open := stringEnd(content, i+1, c)
			scanned += max(next-i, 1)
			if closed || open {
				out = append(out, jsToken{kind: 's'})
			} else {
				out = append(out, jsToken{kind: 'p', text: string(c)})
			}
			i = max(i+1, next)
		case identByte(c) || c == '$' || c == '\\' && i+1 < len(content) && content[i+1] == 'u':
			// A name's \u escapes are its letters: Imag\u0065 is Image.
			var name []byte
			j := i
			for j < len(content) {
				if identByte(content[j]) || content[j] == '$' {
					name = append(name, content[j])
					j++
					continue
				}
				if content[j] != '\\' || j+1 >= len(content) || content[j+1] != 'u' {
					break
				}
				r, n := jsEscape(content[j+1:])
				name = append(name, r...)
				j += 1 + n
			}
			kind := byte('n')
			if c >= '0' && c <= '9' {
				kind = '0'
			}
			if w := string(name); kind == 'n' && (w == "function" || w == "class") && !afterDot(out) {
				b.declare(b.statementStart(out, w == "class", newline))
			}
			out = append(out, jsToken{kind: kind, text: string(name)})
			i = j
		default:
			// Brackets nested past 64 levels are past what the folding follows, and said so.
			t := jsToken{kind: 'p', text: string(c)}
			switch c {
			case '(', '{', '[':
				if depth++; depth > maxBracketDepth {
					deep = true
				}
				b.open(c, out, newline)
			case ')', '}', ']':
				depth = max(depth-1, 0)
				t.closed = b.close()
			case ';':
				b.endStatement()
			}
			i++
			if t.closed == ctxTemplate {
				// The substitution is over: the template's text goes on.
				next, sub, _ := templateText(content, i)
				scanned += max(next-i, 1)
				if carry == nil && i <= carryAt && carryAt < next {
					carry = b.clone()
					carry.inside = '`'
				}
				i = next
				if sub {
					depth++
				}
				t = b.templateToken(sub)
			}
			out = append(out, t)
		}
		if carry == nil && start < carryAt && carryAt < i {
			// A literal or a comment the next piece starts inside of.
			carry = b.clone()
			switch {
			case c == '`' || c == '\'' || c == '"':
				carry.inside = c
			case c == '/' && content[start+1] == '*':
				carry.inside = '*'
			case c == '/' && len(out) > at && out[at].kind == 'r':
				carry.inside = 'r'
			default:
				carry.inside = '\n'
			}
		}
		if len(out) > at {
			out[at].at, out[at].newline = start, newline
			newline = false
		}
	}
	if carry == nil {
		carry = b.clone()
	}
	return out, scanned, deep, ambiguous, carry
}

// templateText passes over the text of a template literal from i: it returns where the template
// ends, past its closing backtick, or where a substitution starts, past its "${", and true; open
// when the piece ends first. Its text is never read as code, however long.
func templateText(b []byte, i int) (next int, sub, open bool) {
	for ; i < len(b); i++ {
		switch {
		case b[i] == '\\':
			i++
		case b[i] == '`':
			return i + 1, false, false
		case b[i] == '$' && i+1 < len(b) && b[i+1] == '{':
			return i + 2, true, false
		}
	}
	return len(b), false, true
}

// stringEnd passes over a string from i, its quote open before: it returns where the string ends,
// past its quote, and closed, or where its line ends, which leaves it unclosed; open when the
// piece ends first.
func stringEnd(b []byte, i int, quote byte) (next int, closed, open bool) {
	for ; i < len(b); i++ {
		switch b[i] {
		case '\\':
			i++
		case quote:
			return i + 1, true, false
		case '\n', '\r':
			return i, false, false
		}
	}
	return len(b), false, true
}

// regexRest passes over the rest of a pattern open at i, to its "/" and flags, or to its line's
// end; open when the piece ends first.
func regexRest(b []byte, i int) (int, bool) {
	end, closed := regexEnd(b, i-1)
	return end, !closed && end == len(b)
}

// lineEnd returns where the line that i is on ends, at its terminator, and true; the end of b and
// false when it has none.
func lineEnd(b []byte, i int) (int, bool) {
	for ; i < len(b); i++ {
		if terminatorAt(b, i) > 0 {
			return i, true
		}
	}
	return len(b), false
}

// terminatorAt returns the length of the line terminator at i, 0 when there is none.
func terminatorAt(b []byte, i int) int {
	if b[i] == '\n' || b[i] == '\r' || b[i] == lineSeparator {
		return 1
	}
	return 0
}

// lineSeparator stands for U+2028 and U+2029 once a piece is normalized: they end a line in code
// but are text inside a string, unlike "\n".
const lineSeparator = 0x1e

// jsNormalize maps JavaScript's white space (tab, vertical tab, form feed, no-break space, the byte
// order mark and every space separator of Unicode) to a space, its line terminators to "\n" (a
// carriage return and line feed to one), and U+2028 and U+2029 to lineSeparator, in one pass, so
// that the tokenizer needs to know only those; at is an offset of b, returned as its place in the
// result. Text of strings changes with it, which no search here depends on.
func jsNormalize(b []byte, at int) ([]byte, int) {
	out := make([]byte, 0, len(b))
	mapped := -1
	for i := 0; i < len(b); {
		if mapped < 0 && i >= at {
			mapped = len(out)
		}
		c := b[i]
		if c < utf8.RuneSelf {
			switch c {
			case '\t', '\v', '\f', lineSeparator:
				c = ' '
			case '\r':
				c = '\n'
				if i+1 < len(b) && b[i+1] == '\n' {
					i++
				}
			}
			out = append(out, c)
			i++
			continue
		}
		r, n := utf8.DecodeRune(b[i:])
		switch {
		case r == '\ufeff' && i == 0:
			// A byte order mark before a file's first line is no part of it.
		case r == '\u2028' || r == '\u2029':
			out = append(out, lineSeparator)
		case r == '\u00a0' || r == '\ufeff' || unicode.Is(unicode.Zs, r):
			out = append(out, ' ')
		default:
			out = append(out, b[i:i+n]...)
		}
		i += n
	}
	if mapped < 0 {
		mapped = len(out)
	}
	return out, mapped
}

// templateToken returns the token that stands for a template's text up to a substitution, which
// it opens, or to its end.
func (b *brackets) templateToken(sub bool) jsToken {
	if sub {
		b.push(ctxTemplate)
		return jsToken{kind: 'p', text: "${"}
	}
	return jsToken{kind: 'p', text: "`"}
}

// brackets is the stack of what the open brackets started, and of the functions and classes
// named whose body is the next "{" at the depth they were named.
type brackets struct {
	stack    []byte
	overflow int
	pending  []pendingBody
	// inside says the next piece starts inside a literal or a comment: '`' a template's text,
	// a quote a string, '*' a block comment, '\n' a line comment or a pattern, 0 none.
	inside byte
	// lineStart says the next piece starts a line: no token before it on its line.
	lineStart bool
}

type pendingBody struct {
	ctx byte
	at  int
}

func (b *brackets) clone() *brackets {
	if b == nil {
		return &brackets{}
	}
	return &brackets{stack: slices.Clone(b.stack), overflow: b.overflow, pending: slices.Clone(b.pending), inside: b.inside, lineStart: b.lineStart}
}

func (b *brackets) depth() int { return len(b.stack) + b.overflow }

func (b *brackets) push(ctx byte) {
	if len(b.stack) == maxContexts || b.overflow > 0 {
		b.overflow++
		return
	}
	b.stack = append(b.stack, ctx)
}

func (b *brackets) open(c byte, before []jsToken, newline bool) {
	ctx := byte(ctxSquare)
	switch c {
	case '(':
		ctx = ctxParen
		if n := len(before); n > 0 && before[n-1].kind == 'n' && !afterDot(before[:n-1]) {
			switch before[n-1].text {
			case "if", "while", "for", "with":
				ctx = ctxCondition
			case "await":
				if n >= 2 && before[n-2].text == "for" {
					ctx = ctxCondition
				}
			}
		}
	case '{':
		ctx = b.brace(before, newline)
	}
	b.push(ctx)
}

// brace decides what a "{" starts, from the token before it (acorn's braceIsBlock), in the cases
// a tokenizer is sure of; ctxUnknown in every other.
func (b *brackets) brace(before []jsToken, newline bool) byte {
	if n := len(b.pending); n > 0 && b.pending[n-1].at == b.depth() {
		ctx := b.pending[n-1].ctx
		b.pending = b.pending[:n-1]
		return ctx
	}
	n := len(before)
	if n == 0 {
		return ctxBlock
	}
	p := before[n-1]
	switch p.kind {
	case 'p':
		switch p.text {
		case ">":
			if n >= 2 && before[n-2].text == "=" {
				return ctxArrow
			}
			return ctxObject
		case ")":
			// The body of an if, a loop, a catch or a method.
			if p.closed != ctxUnknown {
				return ctxBlock
			}
		case "}":
			if p.closed == ctxBlock || p.closed == ctxCondition {
				return ctxBlock
			}
		case ";", "{":
			// Within a for's brackets ";" separates clauses whose "{" is an object.
			if statements(b.top()) {
				return ctxBlock
			}
		case ":":
			// A property's value inside an object; a label's block when the name before ":"
			// starts a statement; a case's block or a conditional's object elsewhere, which a
			// tokenizer cannot tell apart.
			if b.top() == ctxObject {
				return ctxObject
			}
			if n >= 2 && before[n-2].kind == 'n' && !reserved(before[n-2].text) && b.statementStart(before[:n-2], false, before[n-2].newline) == ctxBlock {
				return ctxBlock
			}
		case "=", "(", "[", ",", "?", "+", "-", "*", "%", "!", "~", "&", "|", "^", "<", "/", "${":
			return ctxObject
		}
	case 'n':
		if afterDot(before[:n-1]) {
			return ctxUnknown
		}
		switch p.text {
		case "else", "do", "try", "finally", "catch":
			return ctxBlock
		case "static":
			if top := b.top(); top == ctxClass || top == ctxClassExpr {
				return ctxBlock
			}
		case "return":
			// A line break after it ends the statement.
			if !newline {
				return ctxObject
			}
		case "typeof", "case", "in", "new", "delete", "void", "throw", "instanceof":
			return ctxObject
		}
	}
	// A line break after a finished expression ends the statement, as no "{" may follow one
	// on its line: a block starts.
	if newline && expressionEnd(p) {
		return ctxBlock
	}
	return ctxUnknown
}

// expressionEnd reports a token an expression can end with and no "{", "function" or "class"
// may follow on its line: a name that is no keyword waiting for an operand, a literal, or a
// closing bracket.
func expressionEnd(t jsToken) bool {
	switch t.kind {
	case '0', 's', 'r':
		return true
	case 'n':
		switch t.text {
		case "typeof", "case", "in", "of", "new", "delete", "void", "throw", "instanceof", "yield", "await", "extends", "else", "do", "async", "export", "default":
			return false
		}
		return true
	case 'p':
		return t.text == "]" || t.text == "`" || t.text == "++" || t.text == "--"
	}
	return false
}

// reserved reports a word that cannot be a label.
func reserved(w string) bool {
	switch w {
	case "case", "default", "return", "typeof", "in", "of", "new", "delete", "void", "throw", "instanceof", "yield", "await", "this", "true", "false", "null":
		return true
	}
	return false
}

// statements reports a context whose content is statements.
func statements(ctx byte) bool {
	return ctx == ctxBlock || ctx == ctxFuncExpr || ctx == ctxArrow
}

func (b *brackets) top() byte {
	switch {
	case b.overflow > 0:
		return ctxUnknown
	case len(b.stack) == 0:
		return ctxBlock
	}
	return b.stack[len(b.stack)-1]
}

// close returns what the closing bracket closed; ctxUnknown when it opened before the piece.
func (b *brackets) close() byte {
	if b.overflow > 0 {
		b.overflow--
		return ctxUnknown
	}
	if len(b.stack) == 0 {
		return ctxUnknown
	}
	ctx := b.stack[len(b.stack)-1]
	b.stack = b.stack[:len(b.stack)-1]
	for n := len(b.pending); n > 0 && b.pending[n-1].at > b.depth(); n-- {
		b.pending = b.pending[:n-1]
	}
	return ctx
}

// declare notes a function or class named here, the context its body opens as ctx says: its body
// is the next "{" at this depth.
func (b *brackets) declare(ctx byte) {
	if len(b.pending) < maxContexts {
		b.pending = append(b.pending, pendingBody{ctx: ctx, at: b.depth()})
	}
}

// endStatement forgets the functions and classes named in a statement that ended without their
// body.
func (b *brackets) endStatement() {
	for n := len(b.pending); n > 0 && b.pending[n-1].at == b.depth(); n-- {
		b.pending = b.pending[:n-1]
	}
}

func afterDot(before []jsToken) bool {
	n := len(before)
	return n > 0 && before[n-1].text == "." || n > 1 && before[n-1].text == "?" && before[n-2].text == "."
}

// statementStart says whether a function or class named after these tokens is a declaration,
// an expression, or, where a tokenizer cannot be sure, neither: the context its body opens.
func (b *brackets) statementStart(before []jsToken, class, newline bool) byte {
	declaration, expression := byte(ctxBlock), byte(ctxFuncExpr)
	if class {
		declaration, expression = ctxClass, ctxClassExpr
	}
	n := len(before)
	for n > 0 && before[n-1].kind == 'n' && (before[n-1].text == "async" || before[n-1].text == "export" || before[n-1].text == "default") {
		n--
	}
	if n == 0 {
		return declaration
	}
	p := before[n-1]
	if newline && n == len(before) && expressionEnd(p) {
		// A line break after a finished expression ends the statement (no "function" or
		// "class" may follow one on its line): this one starts the next.
		return declaration
	}
	switch p.kind {
	case 'p':
		switch p.text {
		case ";", "{":
			if statements(b.top()) {
				return declaration
			}
		case "}", ")":
			switch p.closed {
			case ctxBlock, ctxCondition:
				return declaration
			}
		case ":":
			if b.top() == ctxObject {
				return expression
			}
		case "=", "(", "[", ",", "?", "+", "-", "*", "%", "!", "~", "&", "|", "^", "<", ">", "/", "${":
			return expression
		}
	case 'n':
		switch p.text {
		case "else", "do":
			return declaration
		case "return", "typeof", "case", "in", "new", "delete", "void", "throw", "instanceof", "extends":
			return expression
		}
	}
	return ctxUnknown
}

// uncertainBefore reports tokens after which a "/" is a division or a pattern by what a
// tokenizer cannot tell: a bracket whose start it could not, and of, await and yield, keywords
// in some places and names in others.
func uncertainBefore(toks []jsToken) bool {
	t := toks[len(toks)-1]
	switch {
	case t.closed == ctxArrow || t.closed == ctxUnknown:
		return true
	case t.kind == 'n' && !afterDot(toks[:len(toks)-1]):
		return t.text == "of" || t.text == "await" || t.text == "yield"
	}
	return false
}

// regexAllowed reports whether a "/" after these tokens starts a regular expression rather than
// a division: after punctuation other than a closing bracket or "++"/"--", after the ")" of an
// if, while or for, after a block's "}", or after a keyword that takes an expression.
func regexAllowed(toks []jsToken, regexAfterClose bool) bool {
	if len(toks) == 0 {
		return true
	}
	t := toks[len(toks)-1]
	switch t.kind {
	case 'p':
		if n := len(toks); n >= 2 && (t.text == "+" || t.text == "-") && toks[n-2].text == t.text {
			return false
		}
		switch t.closed {
		case ctxCondition, ctxBlock, ctxClass:
			return true
		case ctxParen, ctxObject, ctxFuncExpr, ctxClassExpr:
			return false
		case ctxArrow, ctxUnknown:
			return regexAfterClose
		}
		return t.text != "]" && t.text != "`"
	case 'n':
		// After a dot a keyword is a property's name, and a "/" after it divides.
		if n := len(toks); n >= 2 && toks[n-2].text == "." {
			return false
		}
		switch t.text {
		case "return", "typeof", "case", "do", "else", "in", "new", "delete", "void", "throw":
			return true
		case "of", "await", "yield":
			return regexAfterClose
		}
	}
	return false
}

// maxBracketDepth bounds the brackets matched in a piece.
const maxBracketDepth = 64

// regexEnd returns where the regular expression literal starting at i ends, with its flags, and
// true; or false with where its line ends, or the end of b, when either comes first: a quote
// inside a pattern is no string.
func regexEnd(b []byte, i int) (int, bool) {
	inClass := false
	for j := i + 1; j < len(b); j++ {
		if terminatorAt(b, j) > 0 {
			return j, false
		}
		switch b[j] {
		case '\\':
			j++
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if !inClass {
				j++
				for j < len(b) && (b[j] >= 'a' && b[j] <= 'z') {
					j++
				}
				return j, true
			}
		}
	}
	return len(b), false
}

// jsFoldLiteral is jsLiteral that also takes a template literal whose substitutions are string
// literals: `a${”}b` builds "ab".
func jsFoldLiteral(b []byte, i int) ([]byte, int, bool) {
	if b[i] != '`' {
		return jsLiteral(b, i)
	}
	var out []byte
	for j := i + 1; j < len(b) && j-i < maxLiteral; j++ {
		switch c := b[j]; {
		case c == '`':
			return out, j + 1, true
		case c == '\\' && j+1 < len(b):
			r, n := jsEscape(b[j+1:])
			out = append(out, r...)
			j += n
		case c == '$' && j+1 < len(b) && b[j+1] == '{':
			k := skipBlanks(b, j+2)
			lit, next, ok := jsLiteral(b, k)
			if !ok {
				return nil, i, false
			}
			if next = skipBlanks(b, next); next >= len(b) || b[next] != '}' {
				return nil, i, false
			}
			out = append(out, lit...)
			j = next
		default:
			out = append(out, c)
		}
	}
	return nil, min(i+maxLiteral, len(b)), false
}

// folder evaluates the expressions of a script that are built of string literals only:
// literals, parentheses, "+", .concat(), .split("").reverse().join(""), [..].join(..), and the
// names a var, let, const or plain assignment gave such a value earlier in the file.
type folder struct {
	toks      []jsToken
	constants *foldConstants
	steps     int
	// lastName is the last place of each name in the piece, in bytes; base is where these
	// tokens start in it.
	lastName map[string]int
	base     int
}

// foldConstants are the string constants of a script, kept from one piece to the next. Past the
// bound a new name is kept only when the piece uses it further on, and takes the place of one the
// piece does not use again: decoys set in bulk, never used, neither get in nor push out the name
// a skimmer builds and uses.
type foldConstants struct {
	values map[string]string
	set    map[string]int64
	clock  int64
	// used counts the distinct constants the script used; deep says its brackets went deeper
	// than the tokenizer follows. Both are the file's, gathered across its pieces.
	used map[string]bool
	deep bool
	// brackets are those open where the next piece starts.
	brackets *brackets
	// code and bare are the last piece as the tokenizer read it, with and without the text of
	// its strings.
	code, bare []byte
	// full counts the puts left to refuse after a look found no name to give up: one look,
	// not one per name, when every name kept is used further on.
	full int
}

func newFoldConstants() *foldConstants {
	return &foldConstants{values: map[string]string{}, set: map[string]int64{}, used: map[string]bool{}}
}

func (c *foldConstants) get(name string) string {
	v, ok := c.values[name]
	if ok && len(c.used) <= maxFoldConstants {
		c.used[name] = true
	}
	return v
}

// put keeps a constant; usedLater says whether the piece uses a name after this point.
func (c *foldConstants) put(name, v string, usedLater func(string) bool) {
	if _, ok := c.values[name]; !ok && len(c.values) >= maxFoldConstants {
		if !usedLater(name) || c.full > 0 {
			c.full = max(c.full-1, 0)
			return
		}
		// Half the table goes at once, the names the piece does not use again, the newest
		// first: one pass for many names to come, not one per name.
		var unused []string
		for k := range c.set {
			if !usedLater(k) {
				unused = append(unused, k)
			}
		}
		if len(unused) == 0 {
			c.full = maxFoldConstants / 8
			return
		}
		slices.SortFunc(unused, func(a, b string) int { return cmp.Compare(c.set[b], c.set[a]) })
		for _, k := range unused[:min(len(unused), maxFoldConstants/2)] {
			delete(c.values, k)
			delete(c.set, k)
		}
	}
	c.clock++
	c.values[name], c.set[name] = v, c.clock
}

// foldStrings returns every value of length 4 or more that an expression of the script's
// string literals builds, each preceded by a space, with the constants of the pieces read
// before, which it adds to; and the script as the tokenizer read it, rendered (see render).
func foldStrings(content []byte, constants *foldConstants) (folded []byte, code, bare []byte) {
	folded, _, _ = foldWork(content, constants)
	return folded, constants.code, constants.bare
}

// foldWork folds and says how much work it took: the tokens read and the terms evaluated.
//
// A "/" after ")" or "}" is decided by what the bracket closed. One the tokenizer cannot decide,
// after an arrow function's body or a bracket opened before the piece, is read both ways: the
// whole piece once each way, and each statement again both ways from its ";", so that a script
// asking for one reading in one statement and the other in the next is followed in both. The
// work stays linear: each byte is read at most four times. The names' last uses come from the
// whole readings, so that a constant one statement sets for a later one is kept.
func foldWork(content []byte, constants *foldConstants) ([]byte, int, int) {
	// The next piece starts skimmerOverlap bytes before this one ends, with the brackets open
	// there.
	carryAt := pieceCut(content)
	content, carryAt = jsNormalize(content, carryAt)
	from := constants.brackets
	pattern, scanned, deep, ambiguous, carry := jsTokens(content, true, false, from, carryAt)
	constants.brackets = carry
	constants.code, constants.bare = render(pattern)
	lastName := map[string]int{}
	readings := []tokenReading{{toks: pattern, scanned: scanned, deep: deep}}
	readings = append(readings, otherReadings(content, false, ambiguous, from)...)
	// Whether the file is a script or a module is not in its text: where it decides what
	// "<!--" and "-->" are, the piece is read as a module too, every way a script is.
	if bytes.Contains(content, []byte("<!--")) || bytes.Contains(content, []byte("-->")) {
		toks, scanned, deep, ambiguous, _ := jsTokens(content, true, true, from, len(content))
		readings = append(readings, tokenReading{toks: toks, scanned: scanned, deep: deep})
		readings = append(readings, otherReadings(content, true, ambiguous, from)...)
	}
	for _, rd := range readings {
		for _, t := range rd.toks {
			if t.kind == 'n' {
				lastName[t.text] = max(lastName[t.text], rd.base+t.at)
			}
		}
	}
	// What is folded never outgrows the piece more than four times over, all readings together.
	var out []byte
	tokens, steps := 0, 0
	for _, rd := range readings {
		if steps >= maxFoldSteps {
			break
		}
		more, n := foldReading(rd, min(maxNormalised, 4*len(content))-len(out), constants, lastName)
		out = append(out, more...)
		tokens, steps = tokens+len(rd.toks), steps+n
	}
	return out, tokens, steps
}

// render writes tokens back as text in one form, whatever the spacing, comments and escapes of
// the source: names apart by one space, punctuation glued, strings decoded between double
// quotes, literals joined by "+" as one string (fetch("https://"+"x.example/p") names its host),
// patterns as "/r/". The signal searches run on it, so that "new/**/Image(", a
// no-break space or "navigator. sendBeacon(" read as their plain forms. bare is the same without
// the text of the strings, for the searches that a word inside a string must not satisfy.
func render(toks []jsToken) (code, bare []byte) {
	for k, t := range toks {
		if k > 0 && (t.kind == 'n' || t.kind == '0') && (toks[k-1].kind == 'n' || toks[k-1].kind == '0') {
			code, bare = append(code, ' '), append(bare, ' ')
		}
		switch {
		case t.kind == 'p' && t.text == "+" && k > 0 && k+1 < len(toks) && toks[k-1].kind == 's' && toks[k+1].kind == 's':
			// Joined below.
		case t.kind == 's' && k >= 2 && toks[k-1].text == "+" && toks[k-2].kind == 's':
			code = append(append(code[:len(code)-1], t.text...), '"')
		case t.kind == 's':
			code = append(append(append(code, '"'), t.text...), '"')
			bare = append(bare, `""`...)
		case t.kind == 'r':
			code, bare = append(code, "/r/"...), append(bare, "/r/"...)
		default:
			code, bare = append(code, t.text...), append(bare, t.text...)
		}
	}
	// A member named by a string is the member: navigator["sendBeacon"] is navigator.sendBeacon.
	code = memberString.ReplaceAll(code, []byte(".$1"))
	return code, bare
}

// memberString is a member read through a string that is a plain name.
var memberString = regexp.MustCompile(`\["([A-Za-z_$][A-Za-z0-9_$]*)"\]`)

// pieceCut is where the next piece of a script starts: skimmerOverlap bytes before this one ends,
// moved back to the start of a UTF-8 character, so that no character is split between two pieces.
func pieceCut(piece []byte) int {
	p := len(piece) - skimmerOverlap
	if p <= 0 {
		return len(piece)
	}
	for k := 0; k < utf8.UTFMax && p > 0 && !utf8.RuneStart(piece[p]); k++ {
		p--
	}
	return p
}

// otherReadings are the readings of a piece besides its whole one with a pattern after an
// uncertain bracket: when that one met such a "/", the whole piece with a division there, and
// each statement again both ways from its ";".
func otherReadings(content []byte, module, ambiguous bool, from *brackets) []tokenReading {
	if !ambiguous {
		return nil
	}
	division, scanned, deep, _, _ := jsTokens(content, false, module, from, len(content))
	readings := []tokenReading{{toks: division, scanned: scanned, deep: deep}}
	for start := 0; start < len(content); {
		end := bytes.IndexByte(content[start:], ';')
		if end < 0 {
			end = len(content)
		} else {
			end += start
		}
		for _, regexAfterClose := range []bool{true, false} {
			toks, scanned, deep, _, _ := jsTokens(content[start:end], regexAfterClose, module, &brackets{}, end-start)
			readings = append(readings, tokenReading{toks: toks, scanned: scanned, deep: deep, base: start})
		}
		start = end + 1
	}
	return readings
}

// tokenReading is one reading of a piece, or of one of its statements starting at base.
type tokenReading struct {
	toks    []jsToken
	scanned int
	deep    bool
	base    int
}

// foldReading folds one reading into at most room bytes.
func foldReading(rd tokenReading, room int, constants *foldConstants, lastName map[string]int) ([]byte, int) {
	constants.deep = constants.deep || rd.deep
	f := folder{toks: rd.toks, constants: constants, lastName: lastName, base: rd.base, steps: rd.scanned / 16}
	var out []byte
	for i := 0; i < len(f.toks) && len(out) < room && f.steps < maxFoldSteps; {
		// var x = ..., x = ...: the value is kept for the uses of x after it.
		name := -1
		switch {
		case i+2 < len(f.toks) && f.toks[i].kind == 'n' && (f.toks[i].text == "var" || f.toks[i].text == "let" || f.toks[i].text == "const") &&
			f.toks[i+1].kind == 'n' && f.toks[i+2].text == "=":
			name = i + 1
		case i+1 < len(f.toks) && f.toks[i].kind == 'n' && f.toks[i+1].text == "=" && (i+2 >= len(f.toks) || f.toks[i+2].text != "="):
			name = i
		}
		start := i
		if name >= 0 {
			start = name + 2
		}
		// An expression is tried only where a string can start: a literal, a name, an array of
		// literals. Starting at every bracket of "((((" would descend as deep as allowed from
		// each one.
		// A run of opening brackets before a literal starts one too, tried once from its first
		// bracket: a failure skips the run, so "((((" costs one try, not one per bracket.
		t := f.toks[start:]
		parens := 0
		for parens < len(t) && t[parens].text == "(" {
			parens++
		}
		if len(t) == 0 || parens < len(t) && parens > 0 && t[parens].kind != 's' && t[parens].kind != 'n' ||
			parens == 0 && t[0].kind != 's' && t[0].kind != 'n' && (t[0].text != "[" || len(t) < 2 || t[1].kind != 's') {
			i = max(start+parens, i+1)
			continue
		}
		v, next, ok := f.expr(start, 0)
		if !ok {
			i = max(start+parens, i+1)
			continue
		}
		if name >= 0 {
			after := f.base + f.toks[len(f.toks)-1].at + 1
			if next < len(f.toks) {
				after = f.base + f.toks[next].at
			}
			f.constants.put(f.toks[name].text, v, func(n string) bool { return f.lastName[n] >= after })
		}
		if len(v) >= 4 {
			out = append(append(out, ' '), v...)
		}
		i = max(next, i+1)
	}
	return out, f.steps
}

// expr folds a sum of terms at i.
func (f *folder) expr(i, depth int) (string, int, bool) {
	v, i, ok := f.term(i, depth)
	if !ok {
		return "", i, false
	}
	for i < len(f.toks) && f.toks[i].text == "+" {
		w, next, ok := f.term(i+1, depth)
		if !ok {
			break
		}
		v = f.join(v, w)
		i = next
	}
	return v, i, true
}

// charge takes the cost of an operation that produces n bytes from the piece's budget, before
// the operation runs, and says whether it may.
func (f *folder) charge(n int) bool {
	f.steps += 1 + n/16
	return f.steps <= maxFoldSteps
}

// join appends w to v up to the value's bound, the bytes charged first.
func (f *folder) join(v, w string) string {
	n := min(len(w), maxFoldValue-len(v))
	if n <= 0 || !f.charge(len(v)+n) {
		return v
	}
	return v + w[:n]
}

// term folds a literal, a parenthesised expression, a known name or an array joined, followed
// by the calls that keep it a string.
func (f *folder) term(i, depth int) (string, int, bool) {
	f.steps++
	if i >= len(f.toks) || depth > maxFoldDepth || f.steps > maxFoldSteps {
		return "", i, false
	}
	var v string
	t := f.toks[i]
	switch {
	case t.kind == 's':
		v, i = t.text, i+1
	case t.kind == 'n' && t.text == "atob" && i+1 < len(f.toks) && f.toks[i+1].text == "(":
		w, next, ok := f.expr(i+2, depth+1)
		if !ok || next >= len(f.toks) || f.toks[next].text != ")" {
			return "", i, false
		}
		if !f.charge(len(w)) {
			return "", i, false
		}
		b, err := base64.StdEncoding.DecodeString(w)
		if err != nil {
			return "", i, false
		}
		v, i = clipFold(string(b)), next+1
	case t.kind == 'n' && f.constants.get(t.text) != "":
		v, i = f.constants.get(t.text), i+1
	case t.text == "(":
		w, next, ok := f.expr(i+1, depth+1)
		if !ok || next >= len(f.toks) || f.toks[next].text != ")" {
			return "", i, false
		}
		v, i = w, next+1
	case t.text == "[":
		parts, next, ok := f.list(i+1, "]", depth)
		if !ok {
			return "", i, false
		}
		// Only an array joined is a string.
		if next+4 < len(f.toks) && f.toks[next].text == "." && f.toks[next+1].text == "join" && f.toks[next+2].text == "(" {
			sep, after, ok := f.expr(next+3, depth+1)
			if ok && after < len(f.toks) && f.toks[after].text == ")" {
				joined := ""
				for k, p := range parts {
					if k > 0 {
						joined = f.join(joined, sep)
					}
					joined = f.join(joined, p)
				}
				return f.calls(joined, after+1, depth)
			}
		}
		return "", i, false
	default:
		return "", i, false
	}
	return f.calls(v, i, depth)
}

// calls folds the string methods that build a string from v: .concat(...) and the reversal
// .split("").reverse().join("").
func (f *folder) calls(v string, i, depth int) (string, int, bool) {
	for i+2 < len(f.toks) && f.toks[i].text == "." && f.toks[i+2].text == "(" {
		switch f.toks[i+1].text {
		case "concat":
			parts, next, ok := f.list(i+3, ")", depth)
			if !ok {
				return v, i, true
			}
			for _, p := range parts {
				v = f.join(v, p)
			}
			i = next
		case "slice", "substring", "substr":
			// .slice(a) and .slice(a, b) with literal numbers.
			a, b, next, ok := f.numbers(i + 3)
			if !ok {
				return v, i, true
			}
			if !f.charge(len(v)) {
				return v, i, true
			}
			r := []rune(v)
			from, to := clampIndex(a, len(r)), len(r)
			if b != nil {
				to = clampIndex(*b, len(r))
			}
			if f.toks[i+1].text == "substr" && b != nil {
				to = min(len(r), from+max(*b, 0))
			}
			if from > to {
				from, to = to, from
			}
			v, i = string(r[from:to]), next
		case "replace", "replaceAll":
			// .replace("a", "b") with literal strings.
			parts, next, ok := f.list(i+3, ")", depth)
			if !ok || len(parts) != 2 {
				return v, i, true
			}
			// The result's size is known before it is built: past the bound the call is not
			// folded, so an empty pattern on a long value cannot make megabytes.
			count := strings.Count(v, parts[0])
			if f.toks[i+1].text == "replace" {
				count = min(count, 1)
			}
			size := len(v) + count*(len(parts[1])-len(parts[0]))
			if size > maxFoldValue || !f.charge(len(v)+size) {
				return v, i, true
			}
			v, i = strings.Replace(v, parts[0], parts[1], count), next
		case "split":
			// split("").reverse().join("")
			if i+12 < len(f.toks) && f.toks[i+3].kind == 's' && f.toks[i+3].text == "" && f.toks[i+4].text == ")" &&
				f.toks[i+5].text == "." && f.toks[i+6].text == "reverse" && f.toks[i+7].text == "(" && f.toks[i+8].text == ")" &&
				f.toks[i+9].text == "." && f.toks[i+10].text == "join" && f.toks[i+11].text == "(" && f.toks[i+12].kind == 's' &&
				i+13 < len(f.toks) && f.toks[i+13].text == ")" {
				if !f.charge(len(v)) {
					return v, i, true
				}
				r := []rune(v)
				for a, b := 0, len(r)-1; a < b; a, b = a+1, b-1 {
					r[a], r[b] = r[b], r[a]
				}
				v, i = string(r), i+14
				continue
			}
			return v, i, true
		default:
			return v, i, true
		}
	}
	return v, i, true
}

// list folds expressions separated by commas up to end.
func (f *folder) list(i int, end string, depth int) ([]string, int, bool) {
	var parts []string
	for i < len(f.toks) && len(parts) < maxConcatParts {
		if f.toks[i].text == end {
			return parts, i + 1, true
		}
		v, next, ok := f.expr(i, depth+1)
		if !ok {
			return nil, i, false
		}
		parts, i = append(parts, v), next
		if i < len(f.toks) && f.toks[i].text == "," {
			i++
		}
	}
	return nil, i, false
}

// numbers reads one or two literal integers, separated by a comma and closed by ")".
func (f *folder) numbers(i int) (int, *int, int, bool) {
	num := func(j int) (int, int, bool) {
		neg := false
		if j < len(f.toks) && f.toks[j].text == "-" {
			neg, j = true, j+1
		}
		if j >= len(f.toks) || f.toks[j].kind != '0' {
			return 0, j, false
		}
		n, err := strconv.Atoi(f.toks[j].text)
		if err != nil || n > maxFoldValue {
			return 0, j, false
		}
		if neg {
			n = -n
		}
		return n, j + 1, true
	}
	a, j, ok := num(i)
	if !ok || j >= len(f.toks) {
		return 0, nil, i, false
	}
	if f.toks[j].text == ")" {
		return a, nil, j + 1, true
	}
	if f.toks[j].text != "," {
		return 0, nil, i, false
	}
	b, j, ok := num(j + 1)
	if !ok || j >= len(f.toks) || f.toks[j].text != ")" {
		return 0, nil, i, false
	}
	return a, &b, j + 1, true
}

// clampIndex turns a slice index, negative from the end, into one within n.
func clampIndex(i, n int) int {
	if i < 0 {
		i += n
	}
	return min(max(i, 0), n)
}

func clipFold(s string) string {
	if len(s) > maxFoldValue {
		return s[:maxFoldValue]
	}
	return s
}
