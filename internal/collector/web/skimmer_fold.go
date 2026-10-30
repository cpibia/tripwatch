package web

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"strings"
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
}

// jsTokens splits content into tokens, comments and blanks left out. A template literal with
// substitutions of string literals only (`${”}`) is one string; one with any other
// substitution is punctuation, so that nothing is folded across it.
func jsTokens(content []byte) []jsToken {
	var out []jsToken
	for i := 0; i < len(content) && len(out) < maxFoldTokens; {
		c := content[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '/' && i+1 < len(content) && content[i+1] == '/':
			if j := bytes.IndexByte(content[i:], '\n'); j >= 0 {
				i += j + 1
			} else {
				i = len(content)
			}
		case c == '/' && i+1 < len(content) && content[i+1] == '*':
			if j := bytes.Index(content[i+2:], []byte("*/")); j >= 0 {
				i += j + 4
			} else {
				i = len(content)
			}
		// "*/" ends a comment whose start lay in an earlier piece, never starts a pattern.
		case c == '/' && (i == 0 || content[i-1] != '*') && regexAllowed(out):
			if end := regexEnd(content, i); end > i {
				out = append(out, jsToken{'r', ""})
				i = end
			} else {
				out = append(out, jsToken{'p', "/"})
				i++
			}
		case c == '\'' || c == '"' || c == '`':
			if lit, next, ok := jsFoldLiteral(content, i); ok {
				out = append(out, jsToken{'s', string(lit)})
				i = next
			} else {
				out = append(out, jsToken{'p', string(c)})
				i++
			}
		case identByte(c) || c == '$':
			j := i
			for j < len(content) && (identByte(content[j]) || content[j] == '$') {
				j++
			}
			kind := byte('n')
			if c >= '0' && c <= '9' {
				kind = '0'
			}
			out = append(out, jsToken{kind, string(content[i:j])})
			i = j
		default:
			out = append(out, jsToken{'p', string(c)})
			i++
		}
	}
	return out
}

// regexAllowed reports whether a "/" after these tokens starts a regular expression rather than
// a division: after punctuation other than a closing bracket, or after a keyword that takes an
// expression.
func regexAllowed(toks []jsToken) bool {
	if len(toks) == 0 {
		return true
	}
	t := toks[len(toks)-1]
	switch t.kind {
	case 'p':
		return t.text != ")" && t.text != "]" && t.text != "}"
	case 'n':
		switch t.text {
		case "return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "yield", "await":
			return true
		}
	}
	return false
}

// regexEnd returns where the regular expression literal starting at i ends, with its flags, or
// i when there is none on the line: a quote inside one is no string.
func regexEnd(b []byte, i int) int {
	inClass := false
	for j := i + 1; j < len(b) && j-i < maxLiteral; j++ {
		switch b[j] {
		case '\\':
			j++
		case '\n', '\r':
			return i
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
				return j
			}
		}
	}
	return i
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
	return nil, i, false
}

// folder evaluates the expressions of a script that are built of string literals only:
// literals, parentheses, "+", .concat(), .split("").reverse().join(""), [..].join(..), and the
// names a var, let, const or plain assignment gave such a value earlier in the file.
type folder struct {
	toks      []jsToken
	constants map[string]string
	steps     int
}

// foldStrings returns every value of length 4 or more that an expression of the script's
// string literals builds, each preceded by a space, with the constants of the pieces read
// before, which it adds to.
func foldStrings(content []byte, constants map[string]string) []byte {
	out, _, _ := foldWork(content, constants)
	return out
}

// foldWork folds and says how much work it took: the tokens read and the terms evaluated.
func foldWork(content []byte, constants map[string]string) ([]byte, int, int) {
	f := folder{toks: jsTokens(content), constants: constants}
	var out []byte
	for i := 0; i < len(f.toks) && len(out) < maxNormalised && f.steps < maxFoldSteps; {
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
		if t := f.toks[start:]; len(t) == 0 || t[0].kind != 's' && t[0].kind != 'n' && (t[0].text != "[" || len(t) < 2 || t[1].kind != 's') {
			i++
			continue
		}
		v, next, ok := f.expr(start, 0)
		if !ok {
			i++
			continue
		}
		if name >= 0 {
			f.set(f.toks[name].text, v)
		}
		if len(v) >= 4 {
			out = append(append(out, ' '), v...)
		}
		i = max(next, i+1)
	}
	return out, len(f.toks), f.steps
}

// set keeps a constant. Past the bound one already kept goes: a script cannot fill the table
// with early names to make a later one forgotten.
func (f *folder) set(name, v string) {
	if _, ok := f.constants[name]; !ok && len(f.constants) >= maxFoldConstants {
		for k := range f.constants {
			delete(f.constants, k)
			break
		}
	}
	f.constants[name] = v
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
		if len(v) < maxFoldValue {
			v = clipFold(v + w)
		}
		i = next
	}
	return v, i, true
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
		b, err := base64.StdEncoding.DecodeString(w)
		if err != nil {
			return "", i, false
		}
		v, i = clipFold(string(b)), next+1
	case t.kind == 'n' && f.constants[t.text] != "":
		v, i = f.constants[t.text], i+1
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
				return f.calls(clipFold(strings.Join(parts, sep)), after+1, depth)
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
			if len(v) < maxFoldValue {
				v = clipFold(v + strings.Join(parts, ""))
			}
			i = next
		case "slice", "substring", "substr":
			// .slice(a) and .slice(a, b) with literal numbers.
			a, b, next, ok := f.numbers(i + 3)
			if !ok {
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
			if f.toks[i+1].text == "replace" {
				v = strings.Replace(v, parts[0], parts[1], 1)
			} else {
				v = strings.ReplaceAll(v, parts[0], parts[1])
			}
			v, i = clipFold(v), next
		case "split":
			// split("").reverse().join("")
			if i+12 < len(f.toks) && f.toks[i+3].kind == 's' && f.toks[i+3].text == "" && f.toks[i+4].text == ")" &&
				f.toks[i+5].text == "." && f.toks[i+6].text == "reverse" && f.toks[i+7].text == "(" && f.toks[i+8].text == ")" &&
				f.toks[i+9].text == "." && f.toks[i+10].text == "join" && f.toks[i+11].text == "(" && f.toks[i+12].kind == 's' &&
				i+13 < len(f.toks) && f.toks[i+13].text == ")" {
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
