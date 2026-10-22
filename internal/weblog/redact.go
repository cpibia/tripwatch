package weblog

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
)

const maxEvidenceLen = 200

// Parameter names whose values are secrets of the site's users, redacted even when they also
// carry an attack pattern.
var sensitiveParam = regexp.MustCompile(`(?i)(token|passw|pwd|secret|key|auth|session|sid|code|sig|signature|otp|nonce|credential|bearer|jwt)`)

// queryInLine finds query strings inside free text such as an error log line.
var queryInLine = regexp.MustCompile(`\?[^\s"'<>]+`)

// RedactURI keeps the path and parameter names of a request, and a parameter value only when
// it is the evidence of an attack (traversal, injection, command): ordinary values may be
// reset tokens, API keys or personal data.
func RedactURI(uri string) string {
	p, q, found := strings.Cut(uri, "?")
	if !found {
		return truncateEvidence(p)
	}
	return truncateEvidence(p + "?" + redactQuery(q))
}

// RedactLine redacts the query strings inside a free-text line.
func RedactLine(line string) string {
	return truncateEvidence(queryInLine.ReplaceAllStringFunc(line, func(q string) string {
		return "?" + redactQuery(q[1:])
	}))
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
		if sensitiveParam.MatchString(name) || !isEvidence(decoded) {
			parts[i] = name + "=[redacted]"
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
