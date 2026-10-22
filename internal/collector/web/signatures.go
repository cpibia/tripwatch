package web

import (
	"bytes"
	"regexp"
)

// signature is a pattern of code that legitimate applications do not contain. literals are
// cheap lowercase substrings that must all appear before the regex is run.
type signature struct {
	name     string
	literals []string
	re       *regexp.Regexp
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
		name:     "preg_replace_eval",
		literals: []string{"preg_replace"},
		re:       regexp.MustCompile(`(?i)preg_replace\s*\(\s*['"]([^\w\s])[^'"]*([^\w\s])[a-df-z]*e[a-z]*['"]`),
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
		if s.re.Match(content) {
			out = append(out, s.name)
		}
	}
	if hasEncodedBlob(content) {
		out = append(out, "encoded_blob")
	}
	return out
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
