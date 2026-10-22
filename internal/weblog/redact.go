package weblog

import (
	"net/url"
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

// tokenLike matches long runs of letters and digits, the shape of reset tokens, API keys and
// session identifiers wherever they appear: in a path segment or inside a kept value.
var tokenLike = regexp.MustCompile(`[A-Za-z0-9_\-]{16,}`)

// queryInLine finds query strings inside free text such as an error log line.
var queryInLine = regexp.MustCompile(`\?[^\s"'<>]+`)

// RedactURI keeps the path and parameter names of a request, and a parameter value only when
// it is the evidence of an attack (traversal, injection, command): ordinary values may be
// reset tokens, API keys or personal data.
func RedactURI(uri string) string {
	p, q, found := strings.Cut(uri, "?")
	p = maskTokens(p)
	if !found {
		return truncateEvidence(p)
	}
	return truncateEvidence(p + "?" + redactQuery(q))
}

// maskTokens hides token-like runs that mix letters and digits; plain words and numbers stay.
func maskTokens(s string) string {
	return tokenLike.ReplaceAllStringFunc(s, func(t string) string {
		if strings.ContainsFunc(t, unicode.IsDigit) && strings.ContainsFunc(t, unicode.IsLetter) {
			return "[redacted]"
		}
		return t
	})
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
	return slices.ContainsFunc([]*regexp.Regexp{traversalRe, sqlInjectionRe, injectionProbes}, func(re *regexp.Regexp) bool {
		return re.MatchString(value)
	}) || commandParamRe.MatchString("cmd="+value)
}

func truncateEvidence(s string) string {
	if len(s) <= maxEvidenceLen {
		return s
	}
	return s[:maxEvidenceLen] + "..."
}
