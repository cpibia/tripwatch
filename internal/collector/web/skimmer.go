package web

import (
	"bytes"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
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
	activeSVG     = regexp.MustCompile(`(?i)<script\b|\bon[a-z]{3,20}\s*=|javascript:`)
)

// skimmerSignals returns the families of a skimmer found in content: payment fields with an exit
// to another host or with obfuscation, or a secret payment key. One family alone is what payment
// libraries and analytics do. A harvest of every form field is reported with them but is not
// enough: large editor, file manager and admin bundles hold a harvest, exits and eval together.
func skimmerSignals(content []byte) []string {
	var got []string
	has := func(re *regexp.Regexp, name string) bool {
		if re.Match(content) {
			got = append(got, name)
			return true
		}
		return false
	}
	fields := has(paymentFields, "payment_fields")
	has(formHarvest, "form_harvest")
	exits := has(exfiltration, "exfiltration")
	hidden := has(obfuscation, "obfuscation")
	key := has(secretKey, "secret_payment_key")
	if key || (fields && (exits || hidden)) {
		return got
	}
	return nil
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

// inspectChanged looks for skimmers in the scripts and templates the manifest found changed.
// Only changed files: payment libraries and bundles hold every one of these families somewhere,
// and what matters is what someone added.
func (s *scanner) inspectChanged(changes []FileChange) {
	for _, c := range changes {
		if c.Change == ChangeRemoved || !slices.Contains(skimmerExtensions, strings.ToLower(path.Ext(c.Path))) {
			continue
		}
		name := strings.TrimPrefix(c.Path, "/")
		info, err := fs.Stat(s.src.FS, name)
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxInMemory || s.budget.dataLeft < info.Size() {
			continue
		}
		s.budget.dataLeft -= info.Size()
		content, err := fs.ReadFile(s.src.FS, name)
		if err != nil {
			continue
		}
		sigs := skimmerSignals(content)
		if strings.EqualFold(path.Ext(name), ".svg") {
			if svg := svgSignals(content); svg != nil {
				sigs = append(sigs, svg...)
			}
		}
		if len(sigs) > 0 {
			s.add(KindSkimmer, name, fs.FileInfoToDirEntry(info), sigs)
		}
	}
}

// isSVG reports an SVG by name or by content: uploads keep whatever name the visitor gave.
func isSVG(base string, content []byte) bool {
	if path.Ext(base) == ".svg" || path.Ext(base) == ".svgz" {
		return true
	}
	head := content[:min(len(content), 1024)]
	return bytes.Contains(bytes.ToLower(head), []byte("<svg"))
}
