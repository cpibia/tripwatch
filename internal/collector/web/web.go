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
	"regexp"
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
	// A per-directory server configuration (.htaccess, .user.ini) where uploads live: it can
	// turn an uploaded image into an executable script.
	KindOverrideInData = "override_in_data_dir"
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

// handlerDirective matches per-directory settings that make the server execute files as PHP:
// mapping a type or handler to PHP (the same directives that disable execution, such as
// AddHandler cgi-script with Options -ExecCGI, do not match), or prepending a file to every
// script.
var handlerDirective = regexp.MustCompile(`(?im)^\s*(Add(Type|Handler)\s+\S*(php|x-httpd)\S*|SetHandler\s+("?proxy:|\S*php)|ForceType\s+\S*php|php_value\s+auto_(prepend|append)_file|php_flag\s+engine\s+(on|1)|auto_(prepend|append)_file\s*=)`)

// Server configuration files that change how the web server treats a directory.
var overrideNames = []string{".htaccess", ".user.ini", "web.config"}

var allowedHidden = []string{
	".htaccess", ".user.ini", ".gitignore", ".gitkeep", ".keep", ".gitattributes", ".well-known",
	".php-cs-fixer.php", ".php-cs-fixer.dist.php", ".php_cs", ".php_cs.dist", ".php_cs.php", ".php_cs.dist.php", ".phpstorm.meta.php",
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

// Test directories of a library, which ship hidden files on purpose: code analysers test how they
// treat them.
var dependencyTestDirs = []string{"tests", "test", "fixtures", "__fixtures__"}

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
	// UploadDirs are the upload directories found in the application, for the sensor to watch
	// between snapshots.
	UploadDirs []string `json:"upload_dirs,omitempty"`
}

// maxUploadDirs bounds the upload directories listed for one application.
const maxUploadDirs = 64

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
	scanners := make([]*scanner, 0, len(res.Inventory.Applications))
	for _, app := range res.Inventory.Applications {
		s := newScanner(src, app, res.Inventory.Sites, res.Inventory.Applications)
		s.budget = budget
		scanners = append(scanners, s)
	}
	// Every application's uploads are listed before any file of any application is read.
	for _, s := range scanners {
		s.namesPass(ctx)
	}
	for _, s := range scanners {
		if ctx.Err() != nil {
			s.issues = append(s.issues, fmt.Sprintf("%s: content not scanned: %v", s.report.Path, ctx.Err()))
			s.report.Truncated = true
		} else {
			s.scan(ctx)
		}
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
	findings map[string]int
}

func newScanner(src collector.Source, app discovery.Application, sites []discovery.Site, apps []discovery.Application) *scanner {
	s := &scanner{
		src:      src,
		root:     strings.TrimPrefix(app.Path, "/"),
		profile:  app.Profile,
		report:   AppReport{Application: app, DirHashes: map[string]string{}},
		budget:   &hashBudget{left: MaxHashBytesPerRun},
		followed: map[string]bool{},
		findings: map[string]int{},
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
	s.report.TreeHash = s.walk(ctx, s.root, 0, false, false)
	s.report.Findings = slices.DeleteFunc(s.report.Findings, func(f Finding) bool { return f.Kind == "" })
	if s.stopped {
		s.report.Truncated = true
		s.issues = append(s.issues, fmt.Sprintf("%s: scan stopped before the end (%v), results are partial", s.report.Path, ctx.Err()))
	}
	if s.budget.exhausted {
		s.issues = append(s.issues, fmt.Sprintf("hash budget of %d bytes per run exhausted: later files fingerprinted by size, ctime and inode", MaxHashBytesPerRun))
	}
}

// namesPass lists the upload directories before any file is read and reports the scripts in
// them by name alone. It costs directory listings only, so the files that would take long to
// read (sparse files, millions of images) cannot push a web shell past the deadline.
func (s *scanner) namesPass(ctx context.Context) {
	roots := slices.Clone(s.uploads)
	if len(roots) == 0 {
		for _, base := range []string{s.root, path.Join(s.root, s.webRoot())} {
			for _, g := range discovery.GenericUploadDirs {
				if p := path.Join(base, g); !slices.Contains(roots, p) {
					roots = append(roots, p)
				}
			}
		}
	}
	for _, root := range roots {
		info, err := fs.Lstat(s.src.FS, root)
		if err != nil {
			continue
		}
		verify := false
		if info.Mode()&fs.ModeSymlink != 0 {
			// The usual release layout: pub/media -> ../../shared/pub/media.
			resolved, ok := s.followable(root)
			if !ok {
				continue
			}
			if info, err = fs.Lstat(s.src.FS, resolved); err != nil {
				continue
			}
			root, verify = resolved, true
		}
		if info.IsDir() {
			s.listNames(ctx, root, 0, verify)
		}
	}
}

const maxNamesDepth = 64

func (s *scanner) listNames(ctx context.Context, dir string, depth int, verify bool) {
	if depth > maxNamesDepth || s.expired(ctx) || (verify && !s.unchanged(dir)) {
		return
	}
	f, err := s.src.FS.Open(dir)
	if err != nil {
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
			name := path.Join(dir, raw.Name())
			switch {
			case raw.IsDir():
				s.listNames(ctx, name, depth+1, verify)
			case raw.Type().IsRegular() && isScript(strings.ToLower(raw.Name())):
				s.add(KindScriptInUploads, name, lazyEntry{DirEntry: raw, fsys: s.src.FS, name: name}, nil)
			}
		}
		if err != nil || len(batch) == 0 {
			return
		}
	}
}

// withdraw removes a finding recorded by an earlier pass. Withdrawn findings are dropped when
// the scan ends.
func (s *scanner) withdraw(kind, name string) {
	key := kind + "\x00" + name
	if i, seen := s.findings[key]; seen {
		s.report.Findings[i].Kind = ""
		delete(s.findings, key)
	}
}

func (s *scanner) webRoot() string {
	if s.profile == nil || s.profile.WebRoot == "" {
		return "."
	}
	return s.profile.WebRoot
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
	if errors.Is(err, collector.ErrTooManyEntries) {
		// Too many entries to hold and sort: every one is still inspected, streaming, and the
		// directory is fingerprinted as oversized instead of hashed.
		s.issues = append(s.issues, fmt.Sprintf("/%s: over %d entries, inspected without hashing", dir, collector.MaxDirEntries))
		s.walkData(ctx, dir, false, false)
		return "oversized-directory"
	}
	if err != nil {
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
			if childUploads && !inUploads && maybeDir && len(s.report.UploadDirs) < maxUploadDirs {
				s.report.UploadDirs = append(s.report.UploadDirs, "/"+name)
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
// observed root, and its content scanned as data. That link is the deploy pattern, not a
// finding, as long as it leads to a directory followable() allows: what it leads to is scanned
// like any upload directory. Any other link in its place is reported.
func (s *scanner) enterData(ctx context.Context, name string, e fs.DirEntry, inUploads bool) {
	if e.Type()&fs.ModeSymlink != 0 {
		target, _ := fs.ReadLink(s.src.FS, name)
		resolved, ok := s.followable(name)
		var info fs.FileInfo
		var err error
		if ok {
			info, err = fs.Lstat(s.src.FS, resolved)
		}
		if !ok || err != nil || !info.IsDir() || isScript(strings.ToLower(e.Name())) {
			s.inspectSymlink(name, e, target, true)
		}
		if !ok {
			s.issues = append(s.issues, fmt.Sprintf("/%s -> %s not followed: target outside the application and its deploy directory", name, target))
			return
		}
		if err != nil || !info.IsDir() {
			return
		}
		if id, ok := collector.FileID(info); ok {
			if s.followed[id] {
				return
			}
			s.followed[id] = true
		}
		s.walkData(ctx, resolved, inUploads, true)
		return
	} else if !e.IsDir() {
		s.inspectFile(name, e, inUploads, true, false)
		return
	}
	s.walkData(ctx, name, inUploads, false)
}

// followable allows a linked upload or data directory to lead inside the application, or into
// the directory that holds it and its siblings (releases/5/storage -> ../../shared/storage with
// release-based deploys), never above that and never into system trees. The decision is taken
// on the fully resolved location, since the target can itself go through further links.
func (s *scanner) followable(name string) (string, bool) {
	resolved, err := collector.ResolvePath(s.src.FS, name)
	if err != nil {
		return "", false
	}
	abs := "/" + resolved
	root := "/" + s.root
	if strings.HasPrefix(abs, root+"/") {
		return resolved, true
	}
	deploy := path.Dir(path.Dir(root))
	return resolved, strings.Count(deploy, "/") >= 2 && strings.HasPrefix(abs, deploy+"/")
}

// unchanged reports whether dir still resolves to itself, that is no component of it has been
// replaced by a link since the walk entered it. Followed trees are walked by their real path
// and checked at every directory, so a link swapped in during the scan cannot lead out.
func (s *scanner) unchanged(dir string) bool {
	resolved, err := collector.ResolvePath(s.src.FS, dir)
	if err == nil && resolved == dir {
		return true
	}
	s.issues = append(s.issues, fmt.Sprintf("/%s changed during the scan (a component is now a link): not scanned", dir))
	return false
}

// walkData inspects a data directory without hashing it. Entries are streamed in batches, so a
// directory with millions of uploads is scanned in full without holding its listing.
func (s *scanner) walkData(ctx context.Context, dir string, inUploads, verify bool) {
	if s.expired(ctx) || (verify && !s.unchanged(dir)) {
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
			s.inspectDataEntry(ctx, name, e, inUploads, verify)
		}
		if err != nil || len(batch) == 0 {
			if err != nil && !errors.Is(err, io.EOF) {
				s.issues.Add(err)
			}
			return
		}
	}
}

func (s *scanner) inspectDataEntry(ctx context.Context, name string, e fs.DirEntry, inUploads, verify bool) {
	if slices.Contains(s.nested, name) {
		// Not skipped: the parent's rules for uploads still apply to what is inside.
		s.add(KindAppInData, name, e, nil)
	}
	// An upload directory can sit inside a data directory (storage/app/public in storage).
	inUploads = inUploads || slices.Contains(s.uploads, name)
	switch {
	case e.Type()&fs.ModeSymlink != 0:
		// Reported, never followed: a link to / in an upload directory would walk the whole
		// host. Only a linked upload directory itself is followed, from enterData.
		target, _ := fs.ReadLink(s.src.FS, name)
		s.inspectSymlink(name, e, target, true)
	case e.IsDir():
		if e.Name() == ".git" {
			return
		}
		if isSuspiciousHidden(e.Name()) {
			s.add(KindHiddenInData, name, e, nil)
		}
		s.walkData(ctx, name, inUploads, verify)
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
		if inUploads || inData {
			var sigs []string
			if data, err := fs.ReadFile(s.src.FS, name); err == nil && handlerDirective.Match(data) {
				sigs = []string{"handler_directive"}
			}
			s.add(KindOverrideInData, name, e, sigs)
		}
	}

	info, err := e.Info()
	if err != nil {
		// Explicit even for "does not exist": a file listed a moment ago must not vanish silently.
		s.issues = append(s.issues, fmt.Sprintf("/%s: %v", name, err))
		return ""
	}
	needContent := script || image || inUploads || inData
	// A sparse file costs nothing to create and a full read to inspect: it is read at the
	// edges like a large one.
	sparse := false
	if allocated, ok := collector.Allocated(info); ok && info.Size() > edgeScanSize && allocated < info.Size()/2 {
		sparse = true
	}
	if !needContent || info.Size() > maxInMemory || sparse {
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
	case script && inUploads && complete && isPlaceholder(content):
		// The names pass reported it; the content shows an empty placeholder.
		s.withdraw(KindScriptInUploads, name)
	case script && inUploads:
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
	// Signatures above still apply to these: only the hidden name stops being a finding.
	if script && hidden && !inDependencyTests(name) {
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
	if f := s.add(kind, name, e, sigs); f != nil {
		f.Target = target
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

// add records a finding, or adds signatures to the same finding already recorded by an earlier
// pass, and returns it; nil when the list is full.
func (s *scanner) add(kind, name string, e fs.DirEntry, sigs []string) *Finding {
	key := kind + "\x00" + name
	if i, seen := s.findings[key]; seen {
		f := &s.report.Findings[i]
		for _, sig := range sigs {
			if !slices.Contains(f.Signatures, sig) {
				f.Signatures = append(f.Signatures, sig)
			}
		}
		return f
	}
	if len(s.report.Findings) >= maxFindingsPerApp {
		s.report.Truncated = true
		return nil
	}
	f := s.describe(name, e)
	s.findings[key] = len(s.report.Findings)
	s.report.Findings = append(s.report.Findings, Finding{Kind: kind, Signatures: sigs, Reachable: s.reachable(name), File: f})
	return &s.report.Findings[len(s.report.Findings)-1]
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

// inDependencyTests reports whether name lies in a test directory of a library installed under a
// third-party directory, such as vendor/acme/lib/tests/.
func inDependencyTests(name string) bool {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		if !slices.Contains(thirdPartyDirs, p) {
			continue
		}
		return slices.ContainsFunc(parts[i+1:len(parts)-1], func(d string) bool {
			return slices.Contains(dependencyTestDirs, strings.ToLower(d))
		})
	}
	return false
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
