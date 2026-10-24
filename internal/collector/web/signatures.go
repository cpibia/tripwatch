package web

import (
	"bytes"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// signature is a pattern of code that legitimate applications do not contain. literals are
// cheap lowercase substrings that must all appear before the regex is run.
type signature struct {
	name     string
	literals []string
	re       *regexp.Regexp
	// check, when set, confirms each match the expression cannot judge alone.
	check func(match [][]byte) bool
}

var signatures = []signature{
	{
		name:     "eval_decoded_payload",
		literals: []string{"eval"},
		re:       regexp.MustCompile(`(?i)\beval\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|strrev|rawurldecode)\s*\(`),
	},
	{
		name:     "exec_request_input",
		literals: []string{"$_"},
		re:       regexp.MustCompile(`(?i)\b(?:system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)\s*\(\s*(?:@\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b`),
	},
	{
		name:     "eval_request_input",
		literals: []string{"$_"},
		re:       regexp.MustCompile(`(?i)\b(?:eval|assert|create_function)\s*\(\s*(?:@\s*)?(?:base64_decode\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\b`),
	},
	{
		name:     "request_input_as_function",
		literals: []string{"$_"},
		re:       regexp.MustCompile(`\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(`),
	},
	{
		name:     "backtick_request_input",
		literals: []string{"`$_"},
		re:       regexp.MustCompile("`\\$_(?:GET|POST|REQUEST|COOKIE)"),
	},
	{
		name:     "include_request_input",
		literals: []string{"$_"},
		re:       regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\b\s*\(?\s*(?:@\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\b`),
	},
	// Included from a URL or a stream: code fetched at each request, or read from the body.
	{
		name:     "remote_include",
		literals: []string{"://"},
		re:       regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\b\s*\(?\s*(?:@\s*)?['"](?:https?|ftp|php|data|expect)://`),
	},
	{
		name:     "eval_remote_content",
		literals: []string{"eval"},
		re:       regexp.MustCompile(`(?i)\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:file_get_contents|curl_exec|stream_get_contents|fgets|fread)\s*\(`),
	},
	{
		name:     "globals_call",
		literals: []string{"$globals"},
		re:       regexp.MustCompile(`\$GLOBALS\s*\[\s*['"][^'"]{1,64}['"]\s*\]\s*\(`),
	},
	{
		name:     "preg_replace_eval",
		literals: []string{"preg_replace"},
		re:       regexp.MustCompile(`(?i)preg_replace\s*\(\s*['"]([^\w\s])[^'"]*([^\w\s])[a-df-z]*e[a-z]*['"]`),
		check:    sameDelimiters,
	},
	// Guzzle's FileCookieJar writes cookies as JSON: an unserialize gadget chain abuses it to
	// drop a file whose cookie value is PHP code.
	{
		name:     "cookie_jar_dropper",
		literals: []string{"expires", "<?"},
		re:       regexp.MustCompile(`\[\{"Expires":[^\n]*"Value":"<\?(?:php|=)`),
	},
}

const (
	obfuscatedLineLength = 4000
	obfuscatedRatio      = 0.97
)

// matchSignatures returns the names of the signatures found in content. For PHP source the
// comments are removed first: docblocks routinely quote $_POST or eval() in prose.
func matchSignatures(content []byte, php bool) []string {
	if php {
		content = stripPHPComments(content)
	}
	lower := bytes.ToLower(content)
	var out []string
	for _, s := range signatures {
		if !containsAll(lower, s.literals) {
			continue
		}
		if s.check == nil {
			if s.re.Match(content) {
				out = append(out, s.name)
			}
			continue
		}
		for _, m := range s.re.FindAllSubmatch(content, 16) {
			if s.check(m) {
				out = append(out, s.name)
				break
			}
		}
	}
	if php && hasObfuscatedName(content) {
		out = append(out, "obfuscated_function_name")
	}
	if hasEncodedBlob(content) {
		out = append(out, "encoded_blob")
	}
	return out
}

// sameDelimiters confirms a regular expression with modifiers: its closing delimiter matches the
// opening one, or closes the bracket it opened. Otherwise the "e" is only a letter of the pattern.
func sameDelimiters(m [][]byte) bool {
	if len(m) < 3 || len(m[1]) != 1 || len(m[2]) != 1 {
		return false
	}
	opening, closing := m[1][0], m[2][0]
	pairs := map[byte]byte{'(': ')', '[': ']', '{': '}', '<': '>'}
	if want, ok := pairs[opening]; ok {
		return closing == want
	}
	return opening == closing
}

func containsAll(content []byte, literals []string) bool {
	for _, l := range literals {
		if !bytes.Contains(content, []byte(l)) {
			return false
		}
	}
	return true
}

// hasEncodedBlob reports a very long line made almost only of base64 characters, the usual
// shape of a packed payload. Some libraries embed fonts or images this way, so it is a hint,
// not a verdict.
func hasEncodedBlob(content []byte) bool {
	for line := range bytes.SplitSeq(content, []byte("\n")) {
		if len(line) < obfuscatedLineLength {
			continue
		}
		encoded := 0
		for _, c := range line {
			if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' {
				encoded++
			}
		}
		if float64(encoded)/float64(len(line)) >= obfuscatedRatio {
			return true
		}
	}
	return false
}

// containsCode reports server-side code markers. "<?=" alone is too short to search in binary
// data, so it only counts when followed by a variable or a space.
func containsCode(content []byte) bool {
	return bytes.Contains(content, []byte("<?php")) ||
		bytes.Contains(content, []byte("<?PHP")) ||
		bytes.Contains(content, []byte("<?= ")) ||
		bytes.Contains(content, []byte("<?=$")) ||
		bytes.Contains(content, []byte("__HALT_COMPILER")) ||
		bytes.Contains(content, []byte("<%@ page"))
}

// stripPHPComments removes //, # and /* */ comments outside string literals.
func stripPHPComments(src []byte) []byte {
	out := make([]byte, 0, len(src))
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			j := i + 1
			for j < len(src) && src[j] != c {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			end := min(j+1, len(src))
			out = append(out, src[i:end]...)
			i = end - 1
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := bytes.Index(src[i+2:], []byte("*/"))
			if end < 0 {
				return out
			}
			i += end + 3
		case c == '#' && (i+1 >= len(src) || src[i+1] != '['), c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' && !bytes.HasPrefix(src[i:], []byte("?>")) {
				i++
			}
			i--
		default:
			out = append(out, c)
		}
	}
	return out
}

// isPlaceholder recognises the empty index.php files plugins drop in their directories to
// prevent listings ("Silence is golden"): a PHP open tag with nothing but comments after it.
func isPlaceholder(content []byte) bool {
	rest := bytes.TrimSpace(stripPHPComments(content))
	rest = bytes.TrimSpace(bytes.TrimPrefix(rest, []byte("<?php")))
	rest = bytes.TrimSpace(bytes.TrimSuffix(rest, []byte("?>")))
	return len(rest) == 0
}

// dangerousCall is what PHP code planted in a data file does: run commands, evaluate or include
// something, write files, read the request or its headers. A data file holds no code at all, so
// any of these in a block after a real open tag is enough.
var dangerousCall = regexp.MustCompile("(?i)\\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|" +
	"file_put_contents|fwrite|move_uploaded_file|fsockopen|base64_decode|gzinflate|gzuncompress|str_rot13|" +
	"create_function|call_user_func|call_user_func_array|include|include_once|require|require_once|" +
	"getallheaders|apache_request_headers)\\s*\\(" +
	"|\\b(?:include|require)(?:_once)?\\s*['\"$]|\\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\\b")

// codeInData returns what makes a data file's content PHP that would run if the file were
// included: a real open tag followed by a signature, a dangerous call or a shell command in
// backticks. A real tag is "<?php", or the short "<?", followed by a space or a line break, or
// "<?=": a request logged with its spaces encoded ("<?php+system", "<?php%20") is text. Each
// block runs to the "?>" that closes it as PHP reads it (one inside a string or a block comment
// does not), or to the end. Blocks are examined one after the other, never overlapping, so the
// cost stays linear in the size of the file. codeLeft, when set, is the budget of code examined:
// a file of hostile code is slow to match, so the run spends at most that much, and exhausted
// says the search stopped for it.
func codeInData(content []byte, codeLeft *int64) (sigs []string, exhausted bool) {
	var out []string
	add := func(sig string) {
		if !slices.Contains(out, sig) {
			out = append(out, sig)
		}
	}
	for pos := 0; pos < len(content); {
		i := bytes.Index(content[pos:], []byte("<?"))
		if i < 0 {
			break
		}
		pos += i + 2
		from, ok := openTag(content, pos)
		if !ok {
			continue
		}
		end, backtick := phpBlockEnd(content, from)
		code := content[from:end]
		pos = end
		if codeLeft != nil {
			if *codeLeft < int64(len(code)) {
				return out, true
			}
			*codeLeft -= int64(len(code))
		}
		for _, sig := range matchSignatures(code, true) {
			if sig != "encoded_blob" {
				add(sig)
			}
		}
		if backtick {
			add("backtick_exec")
		}
		if len(out) == 0 && dangerousCall.Match(stripPHPComments(code)) {
			add("dangerous_call")
		}
	}
	return out, false
}

// openTag returns where the code starts after "<?" at pos, if that is an open tag PHP runs.
func openTag(src []byte, pos int) (int, bool) {
	tag := src[pos:]
	space := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	switch {
	case len(tag) > 3 && bytes.EqualFold(tag[:3], []byte("php")) && space(tag[3]):
		return pos + 4, true
	case len(tag) > 1 && tag[0] == '=':
		return pos + 1, true
	case len(tag) > 1 && space(tag[0]):
		return pos + 1, true
	}
	return 0, false
}

// phpBlockEnd returns the end of the PHP block starting at from, past its "?>", as PHP's lexer
// finds it: not inside a string, a shell command or a block comment, while a line comment ends
// there. It also says whether the block runs a command in backticks.
func phpBlockEnd(src []byte, from int) (end int, backtick bool) {
	for i := from; i < len(src); i++ {
		switch c := src[i]; {
		case c == '?' && i+1 < len(src) && src[i+1] == '>':
			return i + 2, backtick
		case c == '\'' || c == '"' || c == '`':
			if c == '`' {
				backtick = true
			}
			for i++; i < len(src) && src[i] != c; i++ {
				if src[i] == '\\' {
					i++
				}
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			j := bytes.Index(src[i+2:], []byte("*/"))
			if j < 0 {
				return len(src), backtick
			}
			i += j + 3
		case c == '#' && (i+1 >= len(src) || src[i+1] != '['), c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				if src[i] == '?' && i+1 < len(src) && src[i+1] == '>' {
					return i + 2, backtick
				}
				i++
			}
		}
	}
	return len(src), backtick
}

// Function names a webshell builds so that no search finds them written out. Decoders count
// only next to an eval: some SDKs split "base64_decode" to get past naive scanners themselves.
var (
	dangerousNames = []string{
		"system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec", "assert",
		"create_function", "file_put_contents", "call_user_func", "call_user_func_array",
		"move_uploaded_file", "curl_exec", "fsockopen", "preg_replace", "eval",
	}
	decoderNames = []string{"base64_decode", "gzinflate", "gzuncompress", "gzdecode", "str_rot13", "hex2bin"}
	evalCall     = regexp.MustCompile(`(?i)\b(?:eval|assert)\s*\(`)
)

// maxNameExpr bounds an expression of string pieces worth decoding: a name is short.
const maxNameExpr = 2048

// hasObfuscatedName reports a function name such as "system" or "assert" written so that it
// does not appear in the source: split into pieces ("sy"."stem"), as escapes ("\x73\x79..."), as
// chr() calls, or as the XOR of two strings. Legitimate code has no reason to write a name that
// way; the pieces are decoded as PHP would and compared with the names a webshell calls. One
// pass over the source, without regular expressions: it runs on every script.
func hasObfuscatedName(content []byte) bool {
	decoders := -1
	for i := 0; i < len(content); {
		start := i
		v, pieces, escapes, next := stringChain(content, i)
		if next == i {
			i++
			continue
		}
		i = next
		if next-start > maxNameExpr || (pieces < 2 && escapes == 0) || len(v) < 4 || len(v) > 24 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(string(v)))
		if bytes.Contains(bytes.ToLower(content[start:next]), []byte(name)) {
			continue
		}
		if slices.Contains(dangerousNames, name) {
			return true
		}
		if slices.Contains(decoderNames, name) {
			if decoders < 0 {
				decoders = 0
				if evalCall.Match(content) {
					decoders = 1
				}
			}
			if decoders == 1 {
				return true
			}
		}
	}
	return false
}

// stringChain reads, at i, string pieces (quoted literals, chr() calls) joined by "." or "^" and
// returns their value as PHP computes it ("^" binds less tightly than ".", and the XOR of two
// strings is as long as the shorter), how many pieces and escapes it read, and where it stopped.
// It returns i itself when no piece starts there.
func stringChain(src []byte, i int) (value []byte, pieces, escapes, next int) {
	var groups [][]byte
	var cur []byte
	next = i
	for {
		piece, esc, end := stringPiece(src, next)
		if end == next {
			break
		}
		cur = append(cur, piece...)
		pieces++
		escapes += esc
		next = end
		j := next
		for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n' || src[j] == '\r') {
			j++
		}
		if j >= len(src) || (src[j] != '.' && src[j] != '^') || (j+1 < len(src) && src[j+1] == '=') {
			break
		}
		op := src[j]
		j++
		for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n' || src[j] == '\r') {
			j++
		}
		if _, _, end := stringPiece(src, j); end == j {
			break
		}
		if op == '^' {
			groups = append(groups, cur)
			cur = nil
		}
		next = j
		if next-i > maxNameExpr {
			break
		}
	}
	if pieces == 0 {
		return nil, 0, 0, i
	}
	value = cur
	for k := len(groups) - 1; k >= 0; k-- {
		g := groups[k]
		x := make([]byte, min(len(value), len(g)))
		for n := range x {
			x[n] = g[n] ^ value[n]
		}
		value = x
	}
	return value, pieces, escapes, next
}

// stringPiece reads one quoted literal or chr() call at i, decoded.
func stringPiece(src []byte, i int) (value []byte, escapes, end int) {
	if i >= len(src) {
		return nil, 0, i
	}
	switch c := src[i]; c {
	case '\'', '"':
		j := i + 1
		for j < len(src) && src[j] != c {
			if src[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(src) {
			return nil, 0, i
		}
		raw := src[i+1 : j]
		if j-i > maxNameExpr {
			return nil, 0, j + 1
		}
		if c == '"' {
			v, n := unescapeDouble(raw)
			return v, n, j + 1
		}
		return bytes.ReplaceAll(bytes.ReplaceAll(raw, []byte(`\'`), []byte(`'`)), []byte(`\\`), []byte(`\`)), 0, j + 1
	case 'c', 'C':
		if i > 0 && (isWordByte(src[i-1]) || src[i-1] == '$' || src[i-1] == '>') || len(src)-i < 6 || !bytes.EqualFold(src[i:i+3], []byte("chr")) {
			return nil, 0, i
		}
		j := i + 3
		for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
			j++
		}
		if j >= len(src) || src[j] != '(' {
			return nil, 0, i
		}
		rparen := bytes.IndexByte(src[j:min(len(src), j+16)], ')')
		if rparen < 0 {
			return nil, 0, i
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(src[j+1 : j+rparen])))
		if err != nil || n < 0 || n > 255 {
			return nil, 0, i
		}
		return []byte{byte(n)}, 1, j + rparen + 1
	}
	return nil, 0, i
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

var octalEscape = regexp.MustCompile(`^[0-7]{1,3}`)

// unescapeDouble decodes the escapes of a double-quoted PHP string and counts them.
func unescapeDouble(raw []byte) ([]byte, int) {
	out := make([]byte, 0, len(raw))
	n := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' || i+1 >= len(raw) {
			out = append(out, raw[i])
			continue
		}
		i++
		switch c := raw[i]; {
		case c == 'x' || c == 'X':
			j := i + 1
			for j < len(raw) && j < i+3 && strings.IndexByte("0123456789abcdefABCDEF", raw[j]) >= 0 {
				j++
			}
			if j == i+1 {
				out = append(out, '\\', c)
				continue
			}
			v, _ := strconv.ParseUint(string(raw[i+1:j]), 16, 8)
			out = append(out, byte(v))
			i = j - 1
			n++
		case c >= '0' && c <= '7':
			m := octalEscape.Find(raw[i:])
			v, _ := strconv.ParseUint(string(m), 8, 16)
			out = append(out, byte(v&0xff)) //nolint:gosec // PHP keeps the low byte of "\777", as this does
			i += len(m) - 1
			n++
		case c == 'n':
			out = append(out, '\n')
		case c == 't':
			out = append(out, '\t')
		case c == '\\' || c == '"' || c == '$':
			out = append(out, c)
		default:
			out = append(out, '\\', c)
		}
	}
	return out, n
}
