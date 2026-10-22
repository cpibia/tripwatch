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
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/discovery"
)

// MaxHashBytesPerRun bounds the bytes hashed by one run across all applications; beyond it
// files are fingerprinted by size, ctime and inode. Sparse files cost nothing to create.
var MaxHashBytesPerRun int64 = 8 << 30

// Finding kinds.
const (
	KindScriptInUploads = "script_in_upload_dir"
	KindCodeInUploads   = "code_in_upload_dir"
	KindPolyglotImage   = "polyglot_image"
	KindSignature       = "webshell_signature"
	KindHiddenScript    = "hidden_script"
	KindHiddenInData    = "hidden_in_data_dir"
	KindEncodedBlob     = "encoded_blob"
	// A symlink where code or data lives: web servers follow links by default, so a link named
	// x.php in an upload directory runs whatever it points to.
	KindSuspiciousSymlink = "suspicious_symlink"
	// A symlink leaving the application. Deploy tools link shared directories this way, so it
	// is a weak signal on its own.
	KindExternalSymlink = "external_symlink"
	// An application found inside another one's upload or data directory: uploads are not
	// where software gets installed.
	KindAppInData = "application_in_data_dir"
)

const (
	maxInMemory       = 4 << 20
	edgeScanSize      = 256 << 10
	maxFindingsPerApp = 1000
	maxReachableList  = 500
	dirHashDepth      = 2
	// maxFindingHashSize bounds hashing for the file attached to a finding.
	maxFindingHashSize = 64 << 20
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
	Target     string   `json:"target,omitempty"`
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

// Collect scans every application. When the context expires the scan stops where it is and the
// partial result is returned, marked as truncated, rather than lost.
func (Collector) Collect(ctx context.Context, src collector.Source) (any, error) {
	res := Result{Inventory: discovery.Inspect(src.FS)}
	budget := &hashBudget{left: MaxHashBytesPerRun}
	for _, app := range res.Inventory.Applications {
		if ctx.Err() != nil {
			res.Issues = append(res.Issues, fmt.Sprintf("%s not scanned: %v", app.Path, ctx.Err()))
			continue
		}
		s := newScanner(src, app, res.Inventory.Sites, res.Inventory.Applications)
		s.budget = budget
		s.scan(ctx)
		res.Apps = append(res.Apps, s.report)
		res.Issues = append(res.Issues, s.issues...)
	}
	return res, nil
}

// hashBudget is shared by the scanners of one run.
type hashBudget struct {
	left      int64
	exhausted bool
}

func (b *hashBudget) take(n int64) bool {
	if b.left < n {
		b.exhausted = true
		return false
	}
	b.left -= n
	return true
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
	// nested are the roots of applications inside this one, scanned on their own with their
	// own profile.
	nested []string
	budget *hashBudget
	// followed holds the directories reached through symlinks, so a link loop is walked once.
	followed map[string]bool
	stopped  bool
}

func newScanner(src collector.Source, app discovery.Application, sites []discovery.Site, apps []discovery.Application) *scanner {
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
	for _, other := range apps {
		if strings.HasPrefix(other.Path, app.Path+"/") {
			s.nested = append(s.nested, strings.TrimPrefix(other.Path, "/"))
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

func (s *scanner) scan(ctx context.Context) {
	if s.budget == nil {
		s.budget = &hashBudget{left: MaxHashBytesPerRun}
	}
	s.followed = map[string]bool{}
	s.report.TreeHash = s.walk(ctx, s.root, 0, false, false)
	if s.stopped {
		s.report.Truncated = true
		s.issues = append(s.issues, fmt.Sprintf("%s: scan stopped before the end (%v), results are partial", s.report.Path, ctx.Err()))
	}
	if s.budget.exhausted {
		s.issues = append(s.issues, fmt.Sprintf("hash budget of %d bytes per run exhausted: later files fingerprinted by size, ctime and inode", MaxHashBytesPerRun))
	}
}

func (s *scanner) expired(ctx context.Context) bool {
	if ctx.Err() != nil {
		s.stopped = true
	}
	return s.stopped
}

// walk hashes dir as a Merkle tree (name, type and content hash of each child) and inspects
// every file. Data directories are handed to walkData: they are inspected but left out of the
// hash, since their content changes at runtime; the hash covers code only.
func (s *scanner) walk(ctx context.Context, dir string, depth int, inUploads, inThirdParty bool) string {
	if s.expired(ctx) {
		return ""
	}
	entries, err := fs.ReadDir(s.src.FS, dir)
	if err != nil {
		// A partial listing (a directory over the entry limit) is still scanned.
		s.issues = append(s.issues, err.Error())
	}

	h := sha256.New()
	for _, e := range entries {
		name := path.Join(dir, e.Name())
		maybeDir := e.IsDir() || e.Type()&fs.ModeSymlink != 0
		childUploads := inUploads || slices.Contains(s.uploads, name) || (maybeDir && s.genericUploadDir(dir, e.Name()))
		childThirdParty := inThirdParty || slices.Contains(thirdPartyDirs, e.Name())
		isData := slices.Contains(s.data, name) || childUploads
		if slices.Contains(s.nested, name) && !isData {
			continue
		}
		if isData {
			if slices.Contains(s.nested, name) {
				s.add(KindAppInData, name, e, nil)
			}
			s.enterData(ctx, name, e, childUploads)
			continue
		}

		var childHash string
		switch {
		case e.Type()&fs.ModeSymlink != 0:
			target, _ := fs.ReadLink(s.src.FS, name)
			childHash = "link:" + target
			s.inspectSymlink(name, e, target, false)
		case e.IsDir():
			if e.Name() == ".git" {
				continue
			}
			childHash = s.walk(ctx, name, depth+1, false, childThirdParty)
		case e.Type().IsRegular():
			childHash = s.inspectFile(name, e, false, false, true)
		default:
			continue
		}
		h.Write([]byte(e.Name() + "\x00" + e.Type().String() + "\x00" + childHash + "\n"))
	}

	sum := hex.EncodeToString(h.Sum(nil))
	if depth <= dirHashDepth && depth > 0 {
		s.report.DirHashes["/"+dir] = sum
	}
	return sum
}

// enterData handles the root of an upload or data directory, which may itself be a symlink
// (deploy tools link uploads to a shared directory): it is followed once, confined to the
// observed root, and its content scanned as data.
func (s *scanner) enterData(ctx context.Context, name string, e fs.DirEntry, inUploads bool) {
	if e.Type()&fs.ModeSymlink != 0 {
		target, _ := fs.ReadLink(s.src.FS, name)
		s.inspectSymlink(name, e, target, true)
		info, err := fs.Stat(s.src.FS, name)
		if err != nil || !info.IsDir() {
			return
		}
		id, ok := collector.FileID(info)
		if ok && s.followed[id] {
			return
		}
		s.followed[id] = true
	} else if !e.IsDir() {
		s.inspectFile(name, e, inUploads, true, false)
		return
	}
	s.walkData(ctx, name, inUploads)
}

// walkData inspects a data directory without hashing it. Entries are streamed in batches, so a
// directory with millions of uploads is scanned in full without holding its listing.
func (s *scanner) walkData(ctx context.Context, dir string, inUploads bool) {
	if s.expired(ctx) {
		return
	}
	f, err := s.src.FS.Open(dir)
	if err != nil {
		s.issues.Add(err)
		return
	}
	defer func() { _ = f.Close() }()
	rd, ok := f.(fs.ReadDirFile)
	if !ok {
		return
	}
	for {
		batch, err := rd.ReadDir(4096)
		for _, raw := range batch {
			if s.expired(ctx) {
				return
			}
			name := path.Join(dir, raw.Name())
			e := lazyEntry{DirEntry: raw, fsys: s.src.FS, name: name}
			s.inspectDataEntry(ctx, name, e, inUploads)
		}
		if err != nil || len(batch) == 0 {
			if err != nil && !errors.Is(err, io.EOF) {
				s.issues.Add(err)
			}
			return
		}
	}
}

func (s *scanner) inspectDataEntry(ctx context.Context, name string, e fs.DirEntry, inUploads bool) {
	if slices.Contains(s.nested, name) {
		// Not skipped: the parent's rules for uploads still apply to what is inside.
		s.add(KindAppInData, name, e, nil)
	}
	switch {
	case e.Type()&fs.ModeSymlink != 0:
		s.enterData(ctx, name, e, inUploads)
	case e.IsDir():
		if e.Name() == ".git" {
			return
		}
		if isSuspiciousHidden(e.Name()) {
			s.add(KindHiddenInData, name, e, nil)
		}
		s.walkData(ctx, name, inUploads)
	case e.Type().IsRegular():
		s.inspectFile(name, e, inUploads, true, false)
	}
}

// lazyEntry answers Info through the observed filesystem's Lstat, so entries streamed from an
// open directory keep the same path rules as everything else.
type lazyEntry struct {
	fs.DirEntry
	fsys fs.FS
	name string
}

func (e lazyEntry) Info() (fs.FileInfo, error) {
	return fs.Lstat(e.fsys, e.name)
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

// inspectFile hashes one file and runs the content checks that apply to it. Executable code
// is only out of place in upload directories; caches and other data directories legitimately
// hold generated PHP, but hidden files there are still reported.
func (s *scanner) inspectFile(name string, e fs.DirEntry, inUploads, inData, hash bool) string {
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
		// Explicit even for "does not exist": a file listed a moment ago must not vanish silently.
		s.issues = append(s.issues, fmt.Sprintf("/%s: %v", name, err))
		return ""
	}
	needContent := script || image || inUploads || inData
	if !needContent || info.Size() > maxInMemory {
		if !hash {
			s.classify(name, e, s.edges(name, info), false, inUploads, inData)
			return ""
		}
		sum, edges := s.hashLarge(name, info, needContent)
		if needContent {
			s.classify(name, e, edges, false, inUploads, inData)
		}
		return sum
	}

	content, err := fs.ReadFile(s.src.FS, name)
	if err != nil {
		s.issues.Add(err)
		return ""
	}
	s.classify(name, e, content, true, inUploads, inData)
	if !hash {
		return ""
	}
	s.budget.take(int64(len(content)))
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// classify runs the content checks. For large files content holds only the head and tail
// (complete is false): a script in an upload directory is reported whatever its size, and
// signatures are searched in what was read.
func (s *scanner) classify(name string, e fs.DirEntry, content []byte, complete, inUploads, inData bool) {
	base := strings.ToLower(e.Name())
	script := isScript(base)
	image := slices.Contains(imageExtensions, path.Ext(base))
	php := s.isPHP(base)

	switch {
	case image && containsCode(content):
		s.add(KindPolyglotImage, name, e, nil)
	case script && inUploads && (!complete || !isPlaceholder(content)):
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
}

func (s *scanner) inspectSymlink(name string, e fs.DirEntry, target string, inData bool) {
	resolved := target
	if !path.IsAbs(resolved) {
		resolved = path.Join("/"+path.Dir(name), target)
	}
	root := "/" + s.root
	outside := resolved != root && !strings.HasPrefix(resolved, root+"/")
	script := isScript(strings.ToLower(e.Name()))

	kind := ""
	switch {
	case script || inData:
		kind = KindSuspiciousSymlink
	case outside:
		kind = KindExternalSymlink
	default:
		return
	}

	var sigs []string
	if info, err := fs.Stat(s.src.FS, name); err == nil && info.Mode().IsRegular() && info.Size() <= maxInMemory {
		if content, err := fs.ReadFile(s.src.FS, name); err == nil {
			sigs = matchSignatures(content, s.isPHP(strings.ToLower(e.Name())))
			if containsCode(content) && !script && inData {
				sigs = append(sigs, "code_in_target")
			}
		}
	}
	if s.add(kind, name, e, sigs) {
		s.report.Findings[len(s.report.Findings)-1].Target = target
	}
	if s.isPHP(strings.ToLower(e.Name())) {
		s.markReachable(name)
	}
}

// hashLarge hashes a file too big to load, keeping its first and last bytes for the content
// checks: code hidden in an image sits after the header or at the end. Beyond MaxHashSize the
// content is not hashed at all (a sparse file of terabytes would take hours to read): size,
// change time and inode stand in for the hash, an issue records it, and only the edges are
// read.
func (s *scanner) hashLarge(name string, info fs.FileInfo, keepEdges bool) (string, []byte) {
	if info.Size() <= collector.MaxHashSize && s.budget.take(info.Size()) {
		return s.hashStream(name, keepEdges)
	}
	// The modification time can be set back by the file's owner; the change time and the
	// inode cannot, so a rewrite at the same size still changes the surrogate.
	ctime, _ := collector.ChangeTime(info)
	id, _ := collector.FileID(info)
	surrogate := fmt.Sprintf("unhashed:size:%d:ctime:%d:id:%s", info.Size(), ctime, id)
	if info.Size() > collector.MaxHashSize {
		s.issues = append(s.issues, fmt.Sprintf("/%s not hashed: %d bytes, over %d", name, info.Size(), collector.MaxHashSize))
	}
	if !keepEdges {
		return surrogate, nil
	}
	return surrogate, s.edges(name, info)
}

// edges reads the head and tail of a file without reading what lies between.
func (s *scanner) edges(name string, info fs.FileInfo) []byte {
	f, err := s.src.FS.Open(name)
	if err != nil {
		s.issues.Add(err)
		return nil
	}
	defer func() { _ = f.Close() }()
	ra, ok := f.(io.ReaderAt)
	if !ok {
		return nil
	}
	head := make([]byte, min(edgeScanSize, info.Size()))
	n, _ := ra.ReadAt(head, 0)
	if info.Size() <= edgeScanSize {
		return head[:n]
	}
	tail := make([]byte, edgeScanSize)
	m, _ := ra.ReadAt(tail, info.Size()-edgeScanSize)
	return append(head[:n], tail[:m]...)
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
	r := io.LimitReader(f, collector.MaxHashSize)
	for {
		n, err := r.Read(buf)
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

// describe returns the metadata of a finding's file, hashed only when small and within the
// run's budget.
func (s *scanner) describe(name string, e fs.DirEntry) collector.File {
	info, err := e.Info()
	if err == nil && info.Mode().IsRegular() && info.Size() <= maxFindingHashSize && s.budget.take(info.Size()) {
		if f, err := collector.DescribeEntry(s.src, name, e); f.Path != "" {
			s.issues.Add(err)
			return f
		}
	}
	f := collector.File{Path: "/" + name}
	if err == nil {
		f.Mode, f.Size, f.ModTime = info.Mode().String(), info.Size(), info.ModTime().UTC()
	}
	return f
}

// add records a finding and reports whether it was kept (the list is capped).
func (s *scanner) add(kind, name string, e fs.DirEntry, sigs []string) bool {
	if len(s.report.Findings) >= maxFindingsPerApp {
		s.report.Truncated = true
		return false
	}
	f := s.describe(name, e)
	s.report.Findings = append(s.report.Findings, Finding{Kind: kind, Signatures: sigs, Reachable: s.reachable(name), File: f})
	return true
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
