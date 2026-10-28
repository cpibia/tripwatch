package weblog

import (
	"math"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

const maxEvidenceLen = 200

// Parameter names whose values are secrets of the site's users, redacted even when they also
// carry an attack pattern.
var sensitiveParam = regexp.MustCompile(`(?i)(token|passw|pwd|secret|key|auth|session|sid|code|sig|signature|otp|nonce|credential|bearer|jwt)`)

// nestedSecret matches name=value pairs with sensitive names inside a parameter value.
var nestedSecret = regexp.MustCompile(`(?i)([a-z0-9_]*(?:token|passw|pwd|secret|key|auth|session|sid|code|sig|otp|nonce|credential|bearer|jwt)[a-z0-9_]*)=([^&\s]+)`)

// tokenLike matches runs that may be reset tokens, API keys, session identifiers or JWTs,
// wherever they appear: in a path segment or inside a kept value.
var tokenLike = regexp.MustCompile(`[A-Za-z0-9_\-.=]{12,}`)

// slugLike is lowercase words joined by hyphens or underscores, such as a REST route: varied
// enough to pass for random, but no token generator produces it.
var slugLike = regexp.MustCompile(`^[a-z]+([-_][a-z]+)+$`)

// queryInLine finds query strings inside free text such as an error log line.
var queryInLine = regexp.MustCompile(`\?[^\s"'<>]+`)

// RedactURI keeps the path and parameter names of a request, and a parameter value only when
// it is the evidence of an attack (traversal, injection, command): ordinary values may be
// reset tokens, API keys or personal data.
func RedactURI(uri string) string {
	p, q, found := strings.Cut(uri, "?")
	// The last segment is kept when it names a script: it is the evidence (the web shell's
	// name), and masking it would let an attacker hide it by choosing a random-looking name.
	dir, last := path.Split(p)
	if strings.Contains(path.Ext(last), "ph") || strings.Contains(path.Ext(last), "sp") || strings.Contains(path.Ext(last), "cgi") {
		p = maskTokens(dir) + last
	} else {
		p = maskTokens(p)
	}
	if !found {
		return truncateEvidence(p)
	}
	return truncateEvidence(p + "?" + redactQuery(q))
}

// maskTokens hides token-like runs: long runs whose characters are varied enough to be random
// (entropy), and shorter ones mixing letters and digits. Words, slugs and dates stay readable.
func maskTokens(s string) string {
	return tokenLike.ReplaceAllStringFunc(s, func(t string) string {
		mixed := strings.ContainsFunc(t, unicode.IsDigit) && strings.ContainsFunc(t, unicode.IsLetter)
		switch {
		case slugLike.MatchString(t):
			return t
		case len(t) >= 20 && entropy(t) >= 3.5:
			return "[redacted]"
		case len(t) >= 12 && mixed && entropy(t) >= 3.0:
			return "[redacted]"
		}
		return t
	})
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	var h float64
	for _, n := range counts {
		p := float64(n) / float64(len(s))
		h -= p * math.Log2(p)
	}
	return h
}

// RedactLine redacts the query strings inside a free-text line.
func RedactLine(line string) string {
	return truncateEvidence(maskTokens(queryInLine.ReplaceAllStringFunc(line, func(q string) string {
		return "?" + redactQuery(q[1:])
	})))
}

func redactQuery(raw string) string {
	parts := strings.Split(raw, "&")
	for i, part := range parts {
		name, value, hasValue := strings.Cut(part, "=")
		if !hasValue || value == "" {
			continue
		}
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			decoded = value
		}
		switch {
		case sensitiveParam.MatchString(name) || !isEvidence(decoded):
			parts[i] = name + "=[redacted]"
		case nestedSecret.MatchString(decoded):
			// A kept value can embed a query of its own (a redirect target, a URL).
			parts[i] = name + "=" + maskTokens(nestedSecret.ReplaceAllString(decoded, "$1=[redacted]"))
		default:
			parts[i] = name + "=" + maskTokens(value)
		}
	}
	return strings.Join(parts, "&")
}

func isEvidence(value string) bool {
	return slices.ContainsFunc([]*regexp.Regexp{traversalRe, sqlInjectionRe, injectionProbes, phpCodeRe}, func(re *regexp.Regexp) bool {
		return re.MatchString(value)
	}) || commandParamRe.MatchString("cmd="+value)
}

func truncateEvidence(s string) string {
	if len(s) <= maxEvidenceLen {
		return s
	}
	return s[:maxEvidenceLen] + "..."
}
