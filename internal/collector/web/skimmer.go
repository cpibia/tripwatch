package web

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// KindSkimmer is a script or a template, changed since the previous run, that reads payment
// fields and sends them out or hides how: what a card skimmer injected into a shop looks like.
// KindActiveSVG is an SVG image among the uploads that runs script when shown.
const (
	KindSkimmer   = "payment_skimmer"
	KindActiveSVG = "active_svg_in_upload_dir"
)

// skimmerExtensions are the files a skimmer is injected into: scripts, templates, images that
// run script.
var skimmerExtensions = []string{".js", ".mjs", ".html", ".htm", ".phtml", ".svg"}

// Families of what a skimmer does. Payment libraries read payment fields and send them, to
// their own relative endpoints or through their own SDK; a skimmer reads them and sends them
// to a host of its own, or hides the code that does.
var (
	paymentFields = regexp.MustCompile(`(?i)cc[_-]?(?:number|num|cid|exp|owner)|card[_-]?(?:number|holder|cvc|cvv|expir)|cardnumber|\bcvv2?\b|\bcvc\b|security[_-]?code|payment\[cc_|expir(?:y|ation)[_-]?(?:month|year|date)`)
	exfiltration  = regexp.MustCompile(`(?i)new\s+Image\s*\(|\.sendBeacon\s*\(|new\s+WebSocket\s*\(|['"]no-cors['"]|(?:fetch|\.open|\$\.(?:ajax|post|get)|url\s*:)\s*\(?\s*(?:['"]POST['"]\s*,\s*)?['"](?:https?:)?//[a-z0-9-]+\.[a-z0-9.-]+`)
	obfuscation   = regexp.MustCompile(`(?i)\batob\s*\(|String\.fromCharCode|new\s+Function\s*\(|\beval\s*\(|\bunescape\s*\(|(?:\\x[0-9a-f]{2}){8}|['"][A-Za-z0-9+/]{400,}={0,2}['"]`)
	formHarvest   = regexp.MustCompile(`(?i)querySelectorAll\s*\(\s*['"](?:input|form|select)|\.elements\b|new\s+FormData\s*\(`)
	secretKey     = regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{16,}`)
	// sends is any way out, to a host named in the code or one put together at run time.
	sends = regexp.MustCompile(`(?i)new\s+Image\s*\(|\.sendBeacon\s*\(|new\s+WebSocket\s*\(|\bfetch\s*\(|new\s+XMLHttpRequest\b`)
	// The browser runs an SVG script element whatever namespace prefix names it.
	activeSVG = regexp.MustCompile(`(?i)<(?:[a-z0-9_.-]+:)?script\b|\bon[a-z]{3,20}\s*=|javascript:`)

	atobLiteral = regexp.MustCompile("\\batob\\s*\\(\\s*['\"`]([A-Za-z0-9+/=]{4,1000})['\"`]\\s*\\)")
	// reversedLiteral is a string written backwards and turned around at run time.
	reversedLiteral = regexp.MustCompile(`['"]([^'"\\]{4,200})['"]\s*\.\s*split\s*\(\s*['"]{2}\s*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(`)
	reversed        = regexp.MustCompile(`\.split\s*\(\s*['"]{2}\s*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(`)
	charCodes       = regexp.MustCompile(`(?i)String\.fromCharCode\s*\(\s*((?:0x[0-9a-f]{1,2}|\d{1,3})(?:\s*,\s*(?:0x[0-9a-f]{1,2}|\d{1,3})){2,200})\s*\)`)
	escapeRun       = regexp.MustCompile(`(?i)(?:\\x[0-9a-f]{2}|\\u00[0-9a-f]{2}){4,}`)
)

// maxDecoded bounds the literals decoded from one file.
const maxDecoded = 256

// decoded is the text hidden in a file's base64 literals passed to atob and its runs of escapes:
// skimmers keep the names of the payment fields there, out of sight of a plain search.
func decoded(content []byte) []byte {
	var out []byte
	// Literals joined with "+" are decoded joined: a field's name split across two of them is
	// whole again.
	last := -1
	for _, m := range atobLiteral.FindAllSubmatchIndex(content, maxDecoded) {
		b, err := base64.StdEncoding.DecodeString(string(content[m[2]:m[3]]))
		if err != nil {
			last = -1
			continue
		}
		if last < 0 || len(bytes.Trim(content[last:m[0]], " \t\r\n+")) > 0 {
			out = append(out, ' ')
		}
		out = append(out, b...)
		last = m[1]
	}
	for _, m := range reversedLiteral.FindAllSubmatch(content, maxDecoded) {
		out = append(out, ' ')
		for i := len(m[1]) - 1; i >= 0; i-- {
			out = append(out, m[1][i])
		}
	}
	for _, m := range charCodes.FindAllSubmatch(content, maxDecoded) {
		out = append(out, ' ')
		for _, code := range strings.Split(string(m[1]), ",") {
			if v, err := strconv.ParseUint(strings.TrimSpace(code), 0, 8); err == nil {
				out = append(out, byte(v))
			}
		}
	}
	for _, run := range escapeRun.FindAll(content, maxDecoded) {
		out = append(out, ' ')
		for i := 0; i+3 < len(run); {
			n := 4
			if run[i+1] == 'u' || run[i+1] == 'U' {
				n = 6
			}
			if v, err := strconv.ParseUint(string(run[i+n-2:i+n]), 16, 8); err == nil {
				out = append(out, byte(v))
			}
			i += n
		}
	}
	return out
}

// Bounds of the string literals normalised in a piece.
const (
	maxLiteral     = 4 << 10
	maxNormalised  = 1 << 20
	maxConcatParts = 64
)

func skipBlanks(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// jsLiteral decodes the string literal starting at i, if one does, and returns where it ends;
// for one not closed within the window, where reading may go on.
func jsLiteral(b []byte, i int) ([]byte, int, bool) {
	if i >= len(b) || b[i] != '\'' && b[i] != '"' && b[i] != '`' {
		return nil, i, false
	}
	quote := b[i]
	var out []byte
	for j := i + 1; j < len(b) && j-i < maxLiteral; j++ {
		c := b[j]
		switch {
		case c == quote:
			return out, j + 1, true
		case c == '\n' && quote != '`':
			// A quote left open at the end of its line is a syntax error: the line is passed
			// over, not read again from each quote in it.
			return nil, j, false
		case c == '$' && quote == '`' && j+1 < len(b) && b[j+1] == '{':
			return nil, i, false
		case c == '\\' && j+1 < len(b):
			r, n := jsEscape(b[j+1:])
			out = append(out, r...)
			j += n
		default:
			out = append(out, c)
		}
	}
	// Not closed within the window: the next quote inside it would be read the same way, so
	// the whole window is passed over.
	return nil, min(i+maxLiteral, len(b)), false
}

// jsEscape decodes the escape after a backslash and returns its bytes and length.
func jsEscape(b []byte) ([]byte, int) {
	hex := func(s []byte) (rune, bool) {
		v, err := strconv.ParseUint(string(s), 16, 32)
		if err != nil || v > unicode.MaxRune {
			return 0, false
		}
		return rune(v), true
	}
	switch {
	case b[0] == 'x' && len(b) >= 3:
		if v, ok := hex(b[1:3]); ok {
			return []byte(string(v)), 3
		}
	case b[0] == 'u' && len(b) >= 3 && b[1] == '{':
		if end := bytes.IndexByte(b[:min(len(b), 10)], '}'); end > 2 {
			if v, ok := hex(b[2:end]); ok {
				return []byte(string(v)), end + 1
			}
		}
	case b[0] == 'u' && len(b) >= 5:
		if v, ok := hex(b[1:5]); ok {
			return []byte(string(v)), 5
		}
	case b[0] == '\r' && len(b) >= 2 && b[1] == '\n':
		// A backslash at the end of a line continues the literal on the next.
		return nil, 2
	case b[0] == '\n' || b[0] == '\r' || b[0] == lineSeparator:
		return nil, 1
	case b[0] >= '0' && b[0] <= '7':
		n := 1
		for n < 3 && n < len(b) && b[n] >= '0' && b[n] <= '7' {
			n++
		}
		if v, err := strconv.ParseUint(string(b[:n]), 8, 8); err == nil {
			return []byte{byte(v)}, n
		}
	}
	return b[:1], 1
}

// skimmerFamilies are the families of a skimmer seen in a file, gathered across its pieces.
type skimmerFamilies struct {
	fields, harvest, exits, sends, hidden, key bool
	// constants are the string constants folded so far, kept from one piece to the next.
	constants *foldConstants
}

func (f *skimmerFamilies) scan(content []byte) {
	text := content
	if f.constants == nil {
		f.constants = newFoldConstants()
	}
	if extra := append(decoded(content), foldStrings(content, f.constants)...); len(extra) > 0 {
		text = append(slices.Clip(content), extra...)
	}
	f.fields = f.fields || paymentFields.Match(text)
	f.harvest = f.harvest || formHarvest.Match(text)
	f.exits = f.exits || exfiltration.Match(text)
	f.sends = f.sends || sends.Match(text)
	f.hidden = f.hidden || obfuscation.Match(content) || reversed.Match(content)
	f.key = f.key || secretKey.Match(text)
}

// verdict names the families of a skimmer: payment fields with an exit to another host or with
// obfuscation, or a secret payment key. One family alone is what payment libraries and analytics
// do, and a harvest of every form field with exits and eval is what editor, file manager and
// admin bundles hold: on a corpus of clean plugins it matches dozens of them.
func (f skimmerFamilies) verdict() []string {
	if skimmer := f.key || f.fields && (f.exits || f.hidden); !skimmer {
		return nil
	}
	var got []string
	for _, fam := range []struct {
		on   bool
		name string
	}{{f.fields, "payment_fields"}, {f.harvest, "form_harvest"}, {f.exits, "exfiltration"}, {f.hidden, "obfuscation"}, {f.key, "secret_payment_key"}} {
		if fam.on {
			got = append(got, fam.name)
		}
	}
	return got
}

// skimmerSignals returns the families of a skimmer found in content, or nil.
func skimmerSignals(content []byte) []string {
	var f skimmerFamilies
	f.scan(content)
	return f.verdict()
}

// svgSignals reports an SVG that runs script when shown, and whether that script is hidden.
func svgSignals(content []byte) []string {
	if !activeSVG.Match(content) {
		return nil
	}
	out := []string{"svg_script"}
	if obfuscation.Match(content) {
		out = append(out, "obfuscation")
	}
	return out
}

// inspectCandidates looks for skimmers in the scripts and templates the manifest found changed.
// Only changed files: payment libraries and bundles hold every one of these families somewhere,
// and what matters is what someone added. When many change at once, a deploy or an update
// rebuilds bundles and replaces whole packages whose admin scripts hold payment field names
// with exits and eval: generated bundles and packages with many changed files are left out
// then, and the files changed elsewhere, a few at a time, are still read.
func (s *scanner) inspectCandidates(ctx context.Context, k skimmerCandidates) skimmerRun {
	run := skimmerRun{read: map[string]bool{}, updating: map[string]bool{}}
	files := k.others
	if k.count <= maxSkimmerChanges {
		files = append(files, k.generated...)
	} else {
		run.skipGenerated = true
		if skipped := k.count - len(k.others) - k.dropped; skipped > 0 {
			s.issues = append(s.issues, fmt.Sprintf("%s: %d scripts changed in generated bundles not read for skimmers: %d scripts and templates changed at once, a deploy",
				s.report.Path, skipped, k.count))
		}
		// A package is being updated when its version file changed with its scripts: one whose
		// scripts change by the dozen at the same version is read, as decoys put next to a
		// skimmer by whoever can write there make it.
		perPackage := map[string]int{}
		for _, c := range k.others {
			perPackage[packageOf(c.Path)]++
		}
		for pkg, n := range perPackage {
			if n > maxPackageChanges && k.versioned[pkg] {
				run.updating[pkg] = true
			}
		}
		files = slices.DeleteFunc(slices.Clone(files), func(c FileChange) bool { return run.updating[packageOf(c.Path)] })
		if len(run.updating) > 0 {
			updated := slices.Sorted(maps.Keys(run.updating))
			s.issues = append(s.issues, fmt.Sprintf("%s: packages updated as a whole not read for skimmers: %s", s.report.Path, strings.Join(updated[:min(len(updated), 20)], ", ")))
		}
	}
	// The order is not the attacker's to choose: scripts left unread by earlier runs come first,
	// then the smallest, so decoys written to fill the run's time or budget go last.
	sizes := make(map[string]int64, len(files))
	for _, c := range files {
		if info, err := fs.Stat(s.src.FS, strings.TrimPrefix(c.Path, "/")); err == nil {
			sizes[c.Path] = info.Size()
		}
	}
	slices.SortStableFunc(files, func(a, b FileChange) int {
		return cmp.Or(cmp.Compare(b.pending, a.pending), cmp.Compare(sizes[a.Path], sizes[b.Path]))
	})
	left := 0
	for _, c := range files {
		if s.expired(ctx) {
			left++
			continue
		}
		if s.inspectChanged(ctx, c) {
			run.read[c.Path] = true
		} else {
			left++
		}
	}
	run.left = left + k.dropped
	if left += k.dropped; left > 0 {
		s.issues = append(s.issues, fmt.Sprintf("%s: %d changed scripts not read for skimmers in this run, kept pending for the next", s.report.Path, left))
	}
	return run
}

// skimmerRun is what a run did with the changed scripts: those it read, and what it left out by
// design, the bundles a deploy generates and the packages being updated.
type skimmerRun struct {
	read map[string]bool
	// left counts the changed scripts left unread, past the bound included.
	left          int
	skipGenerated bool
	updating      map[string]bool
}

// pending reports whether a changed script was left unread by the run, not by design: it stays
// to be read at a later run.
func (r skimmerRun) pending(p string) bool {
	if r.read[p] || r.updating[packageOf(p)] {
		return false
	}
	return !r.skipGenerated || !slices.ContainsFunc(generatedBundles, func(d string) bool { return strings.Contains(p, d) })
}

// versionFile reports a file that changes when the package holding it is updated: the
// manifest of its package manager, WordPress' style.css, readme.txt or main plugin file named
// after the package, Magento's etc/module.xml, Drupal's .info.yml.
func versionFile(p string) bool {
	pkg := packageOf(p)
	dir, base := path.Dir(p), strings.ToLower(path.Base(p))
	switch {
	case dir == pkg+"/etc":
		return base == "module.xml"
	case dir != pkg:
		return false
	}
	return slices.Contains([]string{"composer.json", "package.json", "style.css", "readme.txt", "readme.md", "changelog.txt", "changelog.md"}, base) ||
		base == strings.ToLower(path.Base(pkg))+".php" || strings.HasSuffix(base, ".info.yml")
}

// maxPackageChanges is how many scripts of one package may change at once, in a change too large
// to read whole, for them to be read: more is the package being updated.
const maxPackageChanges = 10

// packageDirs are the directories whose children are packages installed and updated as a whole;
// vendor and app/code hold them two levels down (vendor/acme/module).
var packageDirs = map[string]int{"plugins": 1, "themes": 1, "mu-plugins": 1, "modules": 1, "extensions": 1, "node_modules": 1, "design": 2, "vendor": 2, "code": 2}

// packageOf is the package a changed file belongs to, or its directory when it is in none.
func packageOf(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		if depth, ok := packageDirs[part]; ok && i+depth < len(parts)-1 {
			return strings.Join(parts[:i+depth+1], "/")
		}
	}
	return path.Dir(p)
}

// inspectChanged reads one changed script or template for a skimmer, piece after piece when it
// is large, gathering the families across the pieces: padding cannot push them apart.
// It reports whether the file was read, or is gone: one left unread for the run's budget or time
// stays to be read at the next run.
func (s *scanner) inspectChanged(ctx context.Context, c FileChange) bool {
	name := strings.TrimPrefix(c.Path, "/")
	info, err := fs.Stat(s.src.FS, name)
	if err != nil || !info.Mode().IsRegular() {
		return true
	}
	if s.budget.dataLeft < info.Size() {
		s.issues = append(s.issues, fmt.Sprintf("%s: not read for skimmers, budget of %d bytes a run spent; read at the next run", c.Path, MaxDataScanBytesPerRun))
		return false
	}
	s.budget.dataLeft -= info.Size()
	// One file cannot take the rest of the run: past its own time it is left, and stays pending.
	fileCtx, cancel := context.WithTimeout(ctx, maxSkimmerFileTime)
	defer cancel()
	f, err := s.src.FS.Open(name)
	if err != nil {
		return true
	}
	defer func() { _ = f.Close() }()
	var fam skimmerFamilies
	var svg []string
	r := io.LimitReader(f, info.Size())
	buf := make([]byte, skimmerChunk+skimmerOverlap)
	kept := 0
	for {
		n, err := io.ReadFull(r, buf[kept:])
		piece := buf[:kept+n]
		fam.scan(piece)
		if strings.EqualFold(path.Ext(name), ".svg") && svg == nil {
			svg = svgSignals(piece)
		}
		if err != nil || s.expired(ctx) || fileCtx.Err() != nil {
			break
		}
		// The end of a piece is read again with the next, so a pattern cut in two is whole once.
		kept = copy(buf, piece[len(piece)-skimmerOverlap:])
	}
	// Strings built past what the search follows are named, not judged: more constants used
	// than any clean script of thousands holds (689 at most), or brackets deeper than matched.
	if k := fam.constants; k != nil && (len(k.used) > maxUsedConstants || k.deep) {
		s.issues = append(s.issues, fmt.Sprintf("%s: strings built past what the skimmer search follows: %d constants used, brackets deeper than %d: %v", c.Path, len(k.used), maxBracketDepth, k.deep))
	}
	sigs := append(fam.verdict(), svg...)
	// A skimmer the bound on findings left out leaves its script pending, read again next run.
	if len(sigs) > 0 && s.add(KindSkimmer, name, fs.FileInfoToDirEntry(info), sigs) == nil {
		return false
	}
	return !s.expired(ctx) && fileCtx.Err() == nil
}

// maxUsedConstants is how many string constants a script may use before it is named.
const maxUsedConstants = 2048

// maxSkimmerFileTime bounds the time one changed script takes to read for skimmers. A variable for
// the tests, whose race detector makes reading ten times slower.
var maxSkimmerFileTime = 20 * time.Second

// Pieces in which a large script is read for skimmers.
const (
	skimmerChunk   = 1 << 20
	skimmerOverlap = 8 << 10
)

// isSVG reports an SVG by name or by content: uploads keep whatever name the visitor gave.
func isSVG(base string, content []byte) bool {
	if path.Ext(base) == ".svg" || path.Ext(base) == ".svgz" {
		return true
	}
	head := content[:min(len(content), 1024)]
	return bytes.Contains(bytes.ToLower(head), []byte("<svg"))
}
