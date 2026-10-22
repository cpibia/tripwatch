// Package web inspects the applications served on the machine: code integrity, executable
// files where only data belongs, web shell signatures, and which scripts the web server
// actually executes.
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/discovery"
)

// Finding kinds.
const (
	KindScriptInUploads = "script_in_upload_dir"
	KindCodeInUploads   = "code_in_upload_dir"
	KindPolyglotImage   = "polyglot_image"
	KindSignature       = "webshell_signature"
	KindHiddenScript    = "hidden_script"
	KindHiddenInData    = "hidden_in_data_dir"
	KindEncodedBlob     = "encoded_blob"
)

const (
	maxInMemory       = 4 << 20
	edgeScanSize      = 256 << 10
	maxFindingsPerApp = 1000
	maxReachableList  = 500
	dirHashDepth      = 2
)

var scriptExtensions = []string{
	".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".phar", ".pht", ".phps", ".pgif", ".inc",
	".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cgi", ".pl",
}

var imageExtensions = []string{".gif", ".jpg", ".jpeg", ".png", ".ico", ".webp", ".bmp", ".svg", ".tif", ".tiff"}

// Server configuration files that change how the web server treats a directory.
var overrideNames = []string{".htaccess", ".user.ini", "web.config"}

var allowedHidden = []string{
	".htaccess", ".user.ini", ".gitignore", ".gitkeep", ".keep", ".gitattributes", ".well-known",
	".php-cs-fixer.php", ".php-cs-fixer.dist.php", ".php_cs", ".php_cs.dist", ".phpstorm.meta.php",
	".DS_Store", ".regenerate.lock", ".maintenance.flag", ".maintenance.ip",
}

// Prefixes of hidden names applications create in their media directories (Magento's image
// browser and template manager).
var allowedHiddenPrefixes = []string{".thumbs", ".template-manager"}

// Final extensions that make a double extension (shell.php.png) suspicious: formats an upload
// form accepts.
var uploadExtensions = []string{".gif", ".jpg", ".jpeg", ".png", ".ico", ".webp", ".bmp", ".svg", ".txt", ".pdf", ".doc", ".docx", ".zip", ""}

// Libraries and VCS metadata: never treated as upload directories, and .git is not walked.
var thirdPartyDirs = []string{"vendor", "node_modules", "bower_components"}

type Finding struct {
	Kind       string   `json:"kind"`
	Signatures []string `json:"signatures,omitempty"`
	Reachable  bool     `json:"reachable,omitempty"`
	collector.File
}

type AppReport struct {
	discovery.Application
	Files          int               `json:"files"`
	TreeHash       string            `json:"tree_hash"`
	DirHashes      map[string]string `json:"dir_hashes"`
	Overrides      []collector.File  `json:"overrides"`
	Findings       []Finding         `json:"findings"`
	Reachable      []string          `json:"reachable_scripts"`
	ReachableCount int               `json:"reachable_count"`
	Truncated      bool              `json:"truncated,omitempty"`
}

type Result struct {
	Inventory discovery.Inventory `json:"inventory"`
	Apps      []AppReport         `json:"apps"`
	Issues    collector.Issues    `json:"issues,omitempty"`
}

// Collector inventories the web stack and scans every application found.
type Collector struct{}

func (Collector) Name() string { return "web" }

func (Collector) Collect(ctx context.Context, src collector.Source) (any, error) {
	res := Result{Inventory: discovery.Inspect(src.FS)}
	for _, app := range res.Inventory.Applications {
		s := newScanner(src, app, res.Inventory.Sites)
		if err := s.scan(ctx); err != nil {
			return nil, err
		}
		res.Apps = append(res.Apps, s.report)
		res.Issues = append(res.Issues, s.issues...)
	}
	return res, nil
}

type scanner struct {
	src     collector.Source
	root    string
	profile *discovery.Profile
	sites   []discovery.Site
	report  AppReport
	issues  collector.Issues
	uploads []string
	data    []string
}

func newScanner(src collector.Source, app discovery.Application, sites []discovery.Site) *scanner {
	s := &scanner{
		src:     src,
		root:    strings.TrimPrefix(app.Path, "/"),
		profile: app.Profile,
		report:  AppReport{Application: app, DirHashes: map[string]string{}},
	}
	for _, site := range sites {
		if site.Root != "" && (site.Root == app.Path || strings.HasPrefix(site.Root, app.Path+"/")) {
			s.sites = append(s.sites, site)
		}
	}
	if s.profile != nil {
		s.uploads = s.expand(s.profile.UploadDirs)
		s.data = s.expand(s.profile.DataDirs)
	}
	return s
}

// expand resolves profile globs (sites/*/files) to concrete paths inside the application.
func (s *scanner) expand(patterns []string) []string {
	var out []string
	for _, p := range patterns {
		matches, _ := fs.Glob(s.src.FS, path.Join(s.root, p))
		out = append(out, matches...)
	}
	return out
}

func (s *scanner) scan(ctx context.Context) error {
	hash, err := s.walk(ctx, s.root, 0, false, false)
	if err != nil {
		return err
	}
	s.report.TreeHash = hash
	return nil
}

// walk hashes dir as a Merkle tree (name, type and content hash of each child) and inspects
// every file. Data directories are scanned but left out of the hash, since their content
// changes at runtime; the hash covers code only.
func (s *scanner) walk(ctx context.Context, dir string, depth int, inUploads, inThirdParty bool) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	entries, err := fs.ReadDir(s.src.FS, dir)
	if err != nil {
		s.issues.Add(err)
		return "", nil
	}

	h := sha256.New()
	for _, e := range entries {
		name := path.Join(dir, e.Name())
		childUploads := inUploads || slices.Contains(s.uploads, name) || (e.IsDir() && s.genericUploadDir(dir, e.Name()))
		childThirdParty := inThirdParty || slices.Contains(thirdPartyDirs, e.Name())
		isData := slices.Contains(s.data, name) || (childUploads && !inUploads)

		var childHash string
		switch {
		case e.Type()&fs.ModeSymlink != 0:
			target, _ := fs.ReadLink(s.src.FS, name)
			childHash = "link:" + target
		case e.IsDir():
			if e.Name() == ".git" {
				continue
			}
			if isSuspiciousHidden(e.Name()) && (inUploads || s.inData(dir)) {
				s.add(KindHiddenInData, name, e, nil)
			}
			childHash, err = s.walk(ctx, name, depth+1, childUploads, childThirdParty)
			if err != nil {
				return "", err
			}
		case e.Type().IsRegular():
			childHash = s.inspectFile(name, e, inUploads, inUploads || s.inData(dir))
		default:
			continue
		}

		if isData {
			continue
		}
		h.Write([]byte(e.Name() + "\x00" + e.Type().String() + "\x00" + childHash + "\n"))
	}

	sum := hex.EncodeToString(h.Sum(nil))
	if depth <= dirHashDepth && depth > 0 {
		s.report.DirHashes["/"+dir] = sum
	}
	return sum, nil
}

// genericUploadDir applies the generic upload names (uploads, media, files...) when the
// profile does not say where uploads go, and only right under the application or web root:
// deeper down the same names are ordinary code directories (templates/media, assets/img).
func (s *scanner) genericUploadDir(parent, name string) bool {
	if len(s.uploads) > 0 || !slices.Contains(discovery.GenericUploadDirs, name) {
		return false
	}
	if parent == s.root {
		return true
	}
	return s.profile != nil && s.profile.WebRoot != "" && parent == path.Join(s.root, s.profile.WebRoot)
}

func (s *scanner) inData(dir string) bool {
	return slices.ContainsFunc(s.data, func(d string) bool { return dir == d || strings.HasPrefix(dir, d+"/") })
}

// inspectFile hashes one file and runs the content checks that apply to it. Executable code
// is only out of place in upload directories; caches and other data directories legitimately
// hold generated PHP, but hidden files there are still reported.
func (s *scanner) inspectFile(name string, e fs.DirEntry, inUploads, inData bool) string {
	s.report.Files++
	base := strings.ToLower(e.Name())
	ext := path.Ext(base)
	script := isScript(base)
	image := slices.Contains(imageExtensions, ext)

	if slices.Contains(overrideNames, base) {
		if f, err := collector.DescribeEntry(s.src, name, e); err == nil {
			s.report.Overrides = append(s.report.Overrides, f)
		}
	}

	info, err := e.Info()
	if err != nil {
		s.issues.Add(err)
		return ""
	}
	needContent := script || image || inUploads || inData
	if !needContent || info.Size() > maxInMemory {
		sum, edges := s.hashStream(name, needContent)
		if image && containsCode(edges) {
			s.add(KindPolyglotImage, name, e, nil)
		}
		return sum
	}

	content, err := fs.ReadFile(s.src.FS, name)
	if err != nil {
		s.issues.Add(err)
		return ""
	}
	sum := sha256.Sum256(content)

	php := s.isPHP(base)
	switch {
	case image && containsCode(content):
		s.add(KindPolyglotImage, name, e, nil)
	case script && inUploads && !isPlaceholder(content):
		s.add(KindScriptInUploads, name, e, matchSignatures(content, php))
	case inUploads && !script && containsCode(content):
		s.add(KindCodeInUploads, name, e, matchSignatures(content, false))
	case script:
		switch sigs := matchSignatures(content, php); {
		case slices.Equal(sigs, []string{"encoded_blob"}):
			s.add(KindEncodedBlob, name, e, nil)
		case len(sigs) > 0:
			s.add(KindSignature, name, e, sigs)
		}
	}
	hidden := isSuspiciousHidden(e.Name())
	if script && hidden {
		s.add(KindHiddenScript, name, e, nil)
	} else if inData && hidden {
		s.add(KindHiddenInData, name, e, nil)
	}

	if php {
		s.markReachable(name)
	}
	return hex.EncodeToString(sum[:])
}

// hashStream hashes a large file without loading it, keeping its first and last bytes for
// the polyglot check: code hidden in an image sits after the header or at the end.
func (s *scanner) hashStream(name string, keepEdges bool) (string, []byte) {
	f, err := s.src.FS.Open(name)
	if err != nil {
		s.issues.Add(err)
		return "", nil
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	var head bytes.Buffer
	tail := make([]byte, 0, edgeScanSize)
	buf := make([]byte, 64<<10)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			if keepEdges {
				if head.Len() < edgeScanSize {
					head.Write(buf[:min(n, edgeScanSize-head.Len())])
				}
				tail = append(tail, buf[:n]...)
				if len(tail) > edgeScanSize {
					tail = tail[len(tail)-edgeScanSize:]
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			s.issues.Add(err)
			return "", nil
		}
	}
	return hex.EncodeToString(h.Sum(nil)), append(head.Bytes(), tail...)
}

func (s *scanner) add(kind, name string, e fs.DirEntry, sigs []string) {
	if len(s.report.Findings) >= maxFindingsPerApp {
		s.report.Truncated = true
		return
	}
	f, err := collector.DescribeEntry(s.src, name, e)
	if err != nil && f.Path == "" {
		f = collector.File{Path: "/" + name}
	}
	s.report.Findings = append(s.report.Findings, Finding{Kind: kind, Signatures: sigs, Reachable: s.reachable(name), File: f})
}

// reachable reports whether some site serving this application would execute name.
func (s *scanner) reachable(name string) bool {
	abs := "/" + name
	for i := range s.sites {
		site := &s.sites[i]
		if uri, ok := strings.CutPrefix(abs, strings.TrimSuffix(site.Root, "/")); ok && strings.HasPrefix(uri, "/") && site.Executes(uri) {
			return true
		}
	}
	return false
}

func (s *scanner) markReachable(name string) {
	if !s.reachable(name) {
		return
	}
	s.report.ReachableCount++
	if len(s.report.Reachable) < maxReachableList {
		s.report.Reachable = append(s.report.Reachable, "/"+name)
	}
}

func isSuspiciousHidden(name string) bool {
	if !strings.HasPrefix(name, ".") || slices.Contains(allowedHidden, name) {
		return false
	}
	return !slices.ContainsFunc(allowedHiddenPrefixes, func(p string) bool { return strings.HasPrefix(name, p) })
}

func (s *scanner) isPHP(base string) bool {
	ext := path.Ext(base)
	return strings.HasPrefix(ext, ".php") || ext == ".phtml" || ext == ".phar"
}

// isScript matches server-side script extensions, including double extensions such as
// shell.php.png or shell.php..png that some server configurations still execute.
func isScript(base string) bool {
	if slices.Contains(scriptExtensions, path.Ext(base)) {
		return true
	}
	if !slices.Contains(uploadExtensions, path.Ext(base)) {
		return false
	}
	return strings.Contains(base, ".php.") || strings.Contains(base, ".phtml.") || strings.Contains(base, ".phar.")
}
