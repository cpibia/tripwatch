package system

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"path"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

// sshdSettings are the sshd options that change who can log in and how.
var sshdSettings = []string{
	"port", "listenaddress", "permitrootlogin", "passwordauthentication", "permitemptypasswords",
	"pubkeyauthentication", "kbdinteractiveauthentication", "challengeresponseauthentication",
	"authorizedkeysfile", "authorizedkeyscommand", "authorizedkeyscommanduser",
	"authorizedprincipalsfile", "trustedusercakeys", "allowusers", "allowgroups", "permituserenvironment",
}

const defaultAuthorizedKeysFile = ".ssh/authorized_keys .ssh/authorized_keys2"

type AuthorizedKey struct {
	User        string `json:"user"`
	File        string `json:"file"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment,omitempty"`
	Options     string `json:"options,omitempty"`
}

// SSHMatch is a Match block: its settings apply only to the connections it matches, so they
// are reported as written rather than merged into the global settings.
type SSHMatch struct {
	File     string   `json:"file"`
	Criteria string   `json:"criteria"`
	Lines    []string `json:"lines"`
}

type SSHResult struct {
	Settings map[string]string `json:"settings"`
	Matches  []SSHMatch        `json:"matches,omitempty"`
	Keys     []AuthorizedKey   `json:"keys"`
	Files    []collector.File  `json:"files"`
	Issues   collector.Issues  `json:"issues,omitempty"`
}

// SSH collects the sshd configuration and every authorized key of every account.
type SSH struct{}

func (SSH) Name() string { return "ssh" }

func (SSH) Collect(_ context.Context, src collector.Source) (any, error) {
	res := SSHResult{Settings: map[string]string{}}
	p := sshdParser{src: src, res: &res}
	p.parseFile("etc/ssh/sshd_config", 0)

	accounts, err := readAccounts(src, &res.Issues)
	if err != nil {
		return nil, err
	}

	patterns := res.Settings["authorizedkeysfile"]
	if patterns == "" {
		patterns = defaultAuthorizedKeysFile
	}
	for _, a := range accounts {
		if a.Home == "" {
			continue
		}
		for _, pattern := range strings.Fields(patterns) {
			name := expandKeysPath(pattern, a)
			lines, err := collector.ReadLines(src.FS, name)
			res.Issues.Add(err)
			if lines == nil {
				continue
			}
			for _, line := range lines {
				if key, ok := parseAuthorizedKey(line); ok {
					key.User, key.File = a.Name, "/"+name
					res.Keys = append(res.Keys, key)
				}
			}
			res.Files = appendDescribed(res.Files, &res.Issues, src, name)
		}
	}
	return res, nil
}

const maxSSHDIncludeDepth = 8

// sshdParser follows the configuration as sshd reads it: Include is expanded where it appears
// (Debian puts it first, so drop-ins win), the first value of a setting wins, and a Match
// block lasts until the next Match or the end of the file that opened it.
type sshdParser struct {
	src   collector.Source
	res   *SSHResult
	match *SSHMatch
}

func (p *sshdParser) parseFile(name string, depth int) {
	if depth > maxSSHDIncludeDepth {
		p.res.Issues = append(p.res.Issues, "sshd: include depth exceeded at /"+name)
		return
	}
	lines, err := collector.ReadLines(p.src.FS, name)
	p.res.Issues.Add(err)
	if lines == nil {
		return
	}
	p.res.Files = appendDescribed(p.res.Files, &p.res.Issues, p.src, name)

	outer := p.match
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, _ := strings.Cut(strings.Join(strings.Fields(line), " "), " ")
		key = strings.ToLower(strings.TrimSuffix(key, "="))
		value = strings.TrimSpace(strings.TrimPrefix(value, "="))

		switch {
		case key == "include":
			for _, pattern := range strings.Fields(value) {
				if !path.IsAbs(pattern) {
					pattern = path.Join("/etc/ssh", pattern)
				}
				for _, inc := range collector.Glob(p.src.FS, collector.Rel(pattern)) {
					p.parseFile(inc, depth+1)
				}
			}
		case key == "match":
			p.closeMatch()
			p.match = &SSHMatch{File: "/" + name, Criteria: value}
		case p.match != nil:
			p.match.Lines = append(p.match.Lines, line)
		case slices.Contains(sshdSettings, key):
			if _, seen := p.res.Settings[key]; !seen {
				p.res.Settings[key] = value
			}
		}
	}
	if p.match != outer {
		p.closeMatch()
		p.match = outer
	}
}

func (p *sshdParser) closeMatch() {
	if p.match != nil {
		p.res.Matches = append(p.res.Matches, *p.match)
		p.match = nil
	}
}

// expandKeysPath resolves the %h, %u and %% tokens of AuthorizedKeysFile; relative paths
// are relative to the home directory.
func expandKeysPath(pattern string, a Account) string {
	p := strings.NewReplacer("%%", "%", "%h", a.Home, "%u", a.Name).Replace(pattern)
	if !path.IsAbs(p) {
		p = path.Join(a.Home, p)
	}
	return collector.Rel(p)
}

// parseAuthorizedKey parses one authorized_keys line: [options] type base64-key [comment].
func parseAuthorizedKey(line string) (AuthorizedKey, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return AuthorizedKey{}, false
	}

	var options string
	if first, _, _ := strings.Cut(line, " "); !isKeyType(first) {
		options, line = splitOptions(line)
	}

	fields := strings.Fields(line)
	if len(fields) < 2 || !isKeyType(fields[0]) {
		return AuthorizedKey{}, false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return AuthorizedKey{}, false
	}
	sum := sha256.Sum256(blob)
	return AuthorizedKey{
		Type:        fields[0],
		Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
		Comment:     strings.Join(fields[2:], " "),
		Options:     options,
	}, true
}

// splitOptions separates the leading options field, which may contain quoted spaces as in
// command="/bin/echo hi".
func splitOptions(line string) (options, rest string) {
	quoted := false
	for i, r := range line {
		switch {
		case r == '"':
			quoted = !quoted
		case (r == ' ' || r == '\t') && !quoted:
			return line[:i], strings.TrimSpace(line[i:])
		}
	}
	return line, ""
}

func isKeyType(s string) bool {
	return strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-") || strings.HasPrefix(s, "sk-")
}

func appendDescribed(files []collector.File, issues *collector.Issues, src collector.Source, name string) []collector.File {
	f, err := collector.Describe(src, name)
	issues.Add(err)
	if err != nil && f.Path == "" {
		return files
	}
	return append(files, f)
}
