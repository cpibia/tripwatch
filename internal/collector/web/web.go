// Package web inspects the applications served on the machine: code integrity, executable
// files where only data belongs, web shell signatures, and which scripts the web server
// actually executes.
package web

import (
	"bytes"
	"cmp"
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
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/discovery"
)

// MaxHashBytesPerRun bounds the bytes hashed by one run across all applications; beyond it
// files are fingerprinted by size, ctime and inode. Sparse files cost nothing to create.
var MaxHashBytesPerRun int64 = 8 << 30

// MaxDataScanBytesPerRun bounds the bytes of large data files (logs, reports) read through for
// code by one run across all applications; beyond it they are read at their edges only.
var MaxDataScanBytesPerRun int64 = 4 << 30

// MaxDataCodeBytesPerRun bounds the PHP found in data files and matched against the signatures
// by one run: clean data holds none, and hostile code is matched at a few megabytes a second.
var MaxDataCodeBytesPerRun int64 = 64 << 20

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
	// PHP code in a file the application writes and may read back (a session, a log, an error
	// report): an injection waiting for an include of that file to run.
	KindCodeInData = "code_in_data_file"
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
	".ht.router.php", ".phpstan-baseline.php",
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
	// Changes names the code files added, changed or removed since the previous run whose
	// snapshot was delivered, at most maxChanges of them; ChangeCount counts them all. Both are
	// absent on a first run and when the sensor keeps no state.
	Changes     []FileChange `json:"changes,omitempty"`
	ChangeCount int          `json:"change_count,omitempty"`
}

// maxUploadDirs bounds the upload directories listed for one application.
const maxUploadDirs = 64

type Result struct {
	Inventory discovery.Inventory `json:"inventory"`
	Apps      []AppReport         `json:"apps"`
	Issues    collector.Issues    `json:"issues,omitempty"`
	// CodeSearch is present when data files were left not fully searched for code because a
	// budget of the run was spent.
	CodeSearch *CodeSearch `json:"code_search,omitempty"`
}

// CodeSearch says which data files a run could not search through for code, and which files
// spent the most of its budget: files that fill it on purpose are named, so hiding a payload
// behind decoys points at the decoys.
type CodeSearch struct {
	Unsearched     []string       `json:"unsearched"`
	UnsearchedMore int            `json:"unsearched_more,omitempty"`
	Heaviest       []CodeConsumer `json:"heaviest,omitempty"`
}

// CodeConsumer is a data file and the bytes of code in it that were matched.
type CodeConsumer struct {
	Path      string `json:"path"`
	CodeBytes int64  `json:"code_bytes"`
	UID       int    `json:"uid"`
}

// Bounds of what CodeSearch lists.
const (
	maxUnsearched = 20
	maxHeaviest   = 5
)

// Collector inventories the web stack and scans every application found. With a StateDir it
// keeps a manifest of each application's code files there, to name the files that changed.
// Manifests advance in two steps, like log positions: Collect writes them, Commit puts them in
// use once the snapshot naming the changes has been delivered.
type Collector struct {
	StateDir string
	pending  pendingManifests
}

func (*Collector) Name() string { return "web" }

// Commit puts in use the manifests of the last Collect. Call it only after its snapshot has been
// delivered.
func (c *Collector) Commit() error { return c.pending.commit() }

// Collect scans every application. When the context expires the scan stops where it is and the
// partial result is returned, marked as truncated, rather than lost.
func (c *Collector) Collect(ctx context.Context, src collector.Source) (any, error) {
	res := Result{Inventory: discovery.InspectWithContainers(src)}
	budget := newHashBudget()
	mounts, err := collector.NetworkMounts(src)
	if err != nil {
		res.Issues.Add(err)
	}
	for _, m := range mounts {
		budget.network[m.Point] = m.Type
	}
	scanners := make([]*scanner, 0, len(res.Inventory.Applications))
	for _, app := range res.Inventory.Applications {
		s := newScanner(src, app, res.Inventory.Sites, res.Inventory.Applications)
		s.budget = budget
		scanners = append(scanners, s)
	}
	// A directory several applications reach through links (the uploads every release of a
	// deploy shares) is scanned once, by the first: served applications go first, so what is
	// found there is reported where it is served.
	slices.SortStableFunc(scanners, func(a, b *scanner) int {
		return cmp.Compare(min(len(b.report.Sites), 1), min(len(a.report.Sites), 1))
	})
	// Every application's uploads are listed before any file of any application is read.
	for _, s := range scanners {
		s.namesPass(ctx)
	}
	var manifests []string
	for _, s := range scanners {
		if ctx.Err() != nil {
			s.issues = append(s.issues, fmt.Sprintf("%s: content not scanned: %v", s.report.Path, ctx.Err()))
			s.report.Truncated = true
		} else {
			if c.StateDir != "" {
				var err error
				if s.manifest, err = newManifestWriter(c.StateDir, s.report.Path); err != nil {
					s.issues.Add(err)
				}
			}
			s.scan(ctx)
			if next := s.finishManifest(c.StateDir); next != "" {
				manifests = append(manifests, next)
			}
		}
		res.Apps = append(res.Apps, s.report)
		res.Issues = append(res.Issues, s.issues...)
	}
	c.pending.set(manifests)
	if c.StateDir != "" {
		if err := removeStaleManifests(c.StateDir, time.Now()); err != nil {
			res.Issues.Add(err)
		}
	}
	if len(budget.search.Unsearched) > 0 {
		res.CodeSearch = &budget.search
	}
	return res, nil
}

func newHashBudget() *hashBudget {
	return &hashBudget{left: MaxHashBytesPerRun, dataLeft: MaxDataScanBytesPerRun, codeLeft: MaxDataCodeBytesPerRun,
		followed: map[string]bool{}, listed: map[string]bool{}, network: map[string]string{}}
}

// hashBudget is shared by the scanners of one run.
type hashBudget struct {
	// followed holds the directories reached through symlinks: a link loop is walked once, and
	// so is a directory that several applications link to.
	followed map[string]bool
	// listed holds the upload directories whose names were listed this run.
	listed map[string]bool
	// network maps the mount points of network filesystems to their type: their content is
	// another machine's, and one slow read there would stall the whole run.
	network   map[string]string
	left      int64
	exhausted bool
	dataLeft  int64
	codeLeft  int64
	search    CodeSearch
}

// unsearched records a data file not fully searched for code.
func (b *hashBudget) unsearched(name string) {
	if len(b.search.Unsearched) == maxUnsearched {
		b.search.UnsearchedMore++
		return
	}
	b.search.Unsearched = append(b.search.Unsearched, "/"+name)
}

// spent records the code of a data file matched against the signatures, keeping the heaviest.
func (b *hashBudget) spent(name string, info fs.FileInfo, codeBytes int64) {
	h := b.search.Heaviest
	if codeBytes <= 0 || (len(h) == maxHeaviest && codeBytes <= h[len(h)-1].CodeBytes) {
		return
	}
	uid := -1
	if u, ok := collector.Owner(info); ok {
		uid = int(u)
	}
	c := CodeConsumer{Path: "/" + name, CodeBytes: codeBytes, UID: uid}
	i, _ := slices.BinarySearchFunc(h, c, func(a, b CodeConsumer) int { return cmp.Compare(b.CodeBytes, a.CodeBytes) })
	h = slices.Insert(h, i, c)
	b.search.Heaviest = h[:min(len(h), maxHeaviest)]
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
	// deployRoots are the directories that hold an application's releases (deploy/releases/N):
	// a linked upload or data directory may lead into them, where deploy tools keep what the
	// releases share.
	deployRoots []string
	stopped     bool
	findings    map[string]int
	manifest    *manifestWriter
}

func newScanner(src collector.Source, app discovery.Application, sites []discovery.Site, apps []discovery.Application) *scanner {
	s := &scanner{
		src:      src,
		root:     strings.TrimPrefix(app.Path, "/"),
		profile:  app.Profile,
		report:   AppReport{Application: app, DirHashes: map[string]string{}},
		budget:   newHashBudget(),
		findings: map[string]int{},
	}
	for _, site := range sites {
		if site.Root != "" && (site.Root == app.Path || strings.HasPrefix(site.Root, app.Path+"/")) {
			s.sites = append(s.sites, site)
		}
	}
	// An application served through a link to its current release (current -> releases/N)
	// belongs to that deploy as much as the releases listed next to it.
	paths := []string{}
	if where, err := collector.ResolvePath(src.FS, s.root); err == nil && where != s.root {
		paths = append(paths, "/"+where)
	}
	for _, other := range apps {
		if strings.HasPrefix(other.Path, app.Path+"/") {
			s.nested = append(s.nested, strings.TrimPrefix(other.Path, "/"))
		}
		paths = append(paths, other.Path)
	}
	for _, p := range paths {
		if path.Base(path.Dir(p)) == "releases" {
			if root := path.Dir(path.Dir(p)); strings.Count(root, "/") >= 2 && !slices.Contains(s.deployRoots, root) {
				s.deployRoots = append(s.deployRoots, root)
			}
		}
	}
	if s.profile != nil {
		s.uploads = s.expand(s.profile.UploadDirs)
		s.data = s.expand(s.profile.DataDirs)
		if s.profile.Generic {
			s.writableDirs()
		}
	}
	return s
}

// maxWritableDirs bounds the directories an application without a known stack gets from its
// permissions.
const maxWritableDirs = 64

// writableDirs finds, for an application no profile describes, where it keeps what it writes
// at runtime, from who may write there: a directory of its root anyone may write to is an
// upload directory, one owned by another account than the root's, the web server's as a
// rule, holds its data (caches, compiled templates, files it was sent).
func (s *scanner) writableDirs() {
	rootInfo, err := fs.Stat(s.src.FS, s.root)
	if err != nil {
		return
	}
	rootOwner, ok := collector.Owner(rootInfo)
	if !ok {
		return
	}
	entries, err := fs.ReadDir(s.src.FS, s.root)
	if err != nil {
		return
	}
	found := 0
	for _, e := range entries {
		if !e.IsDir() || found == maxWritableDirs {
			continue
		}
		name := path.Join(s.root, e.Name())
		// An application of its own inside (a CMS in web/ of a Composer project) is scanned
		// with its own profile: the web server owning its tree does not make it data.
		if slices.ContainsFunc(s.nested, func(n string) bool { return n == name || strings.HasPrefix(n, name+"/") }) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		owner, ok := collector.Owner(info)
		switch {
		case info.Mode().Perm()&0o002 != 0:
			if !slices.Contains(s.uploads, name) {
				s.uploads = append(s.uploads, name)
				found++
			}
		case ok && owner != 0 && owner != rootOwner:
			if !slices.Contains(s.data, name) {
				s.data = append(s.data, name)
				found++
			}
		}
	}
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
		if id, ok := collector.FileID(info); ok {
			if s.budget.listed[id] {
				continue
			}
			s.budget.listed[id] = true
		}
		if info.IsDir() {
			s.listNames(ctx, root, 0, verify)
		}
	}
}

const maxNamesDepth = 64

func (s *scanner) listNames(ctx context.Context, dir string, depth int, verify bool) {
	if depth > maxNamesDepth || s.expired(ctx) || s.onNetwork(dir) || (verify && !s.unchanged(dir)) {
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

// onNetwork reports whether dir is a network filesystem's mount point, which is not scanned,
// and says so the first time.
func (s *scanner) onNetwork(dir string) bool {
	t, ok := s.budget.network[dir]
	if ok && t != "" {
		s.issues = append(s.issues, fmt.Sprintf("/%s: %s network filesystem, not scanned", dir, t))
		s.budget.network[dir] = ""
	}
	return ok
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
	if s.expired(ctx) || s.onNetwork(dir) {
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
			s.enterData(ctx, name, e, childUploads, childUploads && !inUploads && maybeDir)
			continue
		}

		var childHash string
		switch {
		case e.Type()&fs.ModeSymlink != 0:
			target, _ := fs.ReadLink(s.src.FS, name)
			childHash = "link:" + target
			s.inspectSymlink(name, e, target, false)
			// A release's link to its shared copy (wp-config.php, .env) leads to code included
			// on every request: its content is hashed under the link's name, so a change to it
			// is a change of the application's code.
			if sum := s.sharedContent(name); sum != "" {
				childHash += ":" + sum
			}
			s.manifest.add(name, childHash)
		case e.IsDir():
			if e.Name() == ".git" {
				continue
			}
			childHash = s.walk(ctx, name, depth+1, false, childThirdParty)
		case e.Type().IsRegular():
			childHash = s.inspectFile(name, e, false, false, true)
			s.manifest.add(name, childHash)
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
func (s *scanner) enterData(ctx context.Context, name string, e fs.DirEntry, inUploads, uploadRoot bool) {
	// The real location is what the real-time watch is given: it does not follow links.
	record := func(dir string) {
		if uploadRoot && len(s.report.UploadDirs) < maxUploadDirs {
			s.report.UploadDirs = append(s.report.UploadDirs, "/"+dir)
		}
	}
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
			record(name)
			where := target
			if resolved != "" && "/"+resolved != target {
				where += " (resolved to /" + resolved + ")"
			}
			s.issues = append(s.issues, fmt.Sprintf("/%s -> %s not followed: target outside the application and its deploy directory", name, where))
			return
		}
		if err != nil || !info.IsDir() {
			return
		}
		record(resolved)
		if id, ok := collector.FileID(info); ok {
			if s.budget.followed[id] {
				return
			}
			s.budget.followed[id] = true
		}
		s.walkData(ctx, resolved, inUploads, true)
		return
	} else if !e.IsDir() {
		s.inspectFile(name, e, inUploads, true, false)
		return
	}
	record(name)
	s.walkData(ctx, name, inUploads, false)
}

// followable allows a linked upload or data directory to lead inside the application, or into
// the directory that holds it and its siblings (releases/5/storage -> ../../shared/storage with
// release-based deploys), never above that and never into system trees. The decision is taken
// on the fully resolved location, since the target can itself go through further links, with
// one exception: the deploy's shared directory may itself lead elsewhere, to the volume the
// uploads of every server live on, as long as that is no system tree.
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
	roots := s.deployRoots
	if strings.Count(deploy, "/") >= 2 {
		roots = append(slices.Clone(roots), deploy)
	}
	if slices.ContainsFunc(roots, func(d string) bool { return strings.HasPrefix(abs, d+"/") }) {
		return resolved, true
	}
	target, err := fs.ReadLink(s.src.FS, name)
	if err != nil {
		return resolved, false
	}
	if !path.IsAbs(target) {
		// Relative to where the link really is: the application may be reached through a
		// link itself (current -> releases/N).
		dir, err := collector.ResolvePath(s.src.FS, path.Dir(name))
		if err != nil {
			return resolved, false
		}
		target = path.Join("/"+dir, target)
	}
	shared := slices.ContainsFunc(roots, func(d string) bool { return strings.HasPrefix(path.Clean(target), d+"/shared/") })
	return resolved, shared && !slices.ContainsFunc(systemTrees, func(t string) bool { return abs == t || strings.HasPrefix(abs, t+"/") }) && abs != "/"
}

// systemTrees are never scanned as an application's data, wherever a link leads.
var systemTrees = []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/root", "/proc", "/sys", "/dev", "/run", "/var/lib", "/var/run"}

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
	if s.expired(ctx) || s.onNetwork(dir) || (verify && !s.unchanged(dir)) {
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
	if inData && !script && !image && !sparse && info.Size() > maxInMemory {
		// A log grows until the code planted in it sits far from both edges: read it through.
		if sigs := s.streamCodeInData(name, info); len(sigs) > 0 {
			s.add(KindCodeInData, name, e, sigs)
		}
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
	case image && polyglot(content, php):
		s.add(KindPolyglotImage, name, e, nil)
	case script && inUploads && complete && php && (exitGuarded(content) || dataOnly(content)):
		// A plugin's log kept under a .php name with an exit in front, so that requesting it
		// shows nothing, or a theme's layouts kept as a returned array: nothing in either runs.
		s.withdraw(KindScriptInUploads, name)
	case script && inUploads && complete && isPlaceholder(content):
		// The names pass reported it; the content shows an empty placeholder.
		s.withdraw(KindScriptInUploads, name)
	case script && inUploads && complete && compiledTwig(name, content):
		// Drupal writes the templates it compiles under its public files; a webshell given that
		// header is still matched against the signatures.
		s.withdraw(KindScriptInUploads, name)
		if sigs := matchSignatures(content, php); len(sigs) > 0 && !slices.Equal(sigs, []string{"encoded_blob"}) {
			s.add(KindSignature, name, e, sigs)
		}
	case script && inUploads:
		s.add(KindScriptInUploads, name, e, matchSignatures(content, php))
	case inUploads && !script && containsCode(content):
		// An archive or a document holding PHP (a plugin backed up as a zip) runs nothing; one
		// named by a signature is still reported.
		if sigs := matchSignatures(content, false); !mediaOrDocument(content) || len(strongInDocuments(content, sigs)) > 0 {
			s.add(KindCodeInUploads, name, e, sigs)
		}
	case inData && !script && !image:
		if sigs := s.codeInData(name, e, content); len(sigs) > 0 {
			s.add(KindCodeInData, name, e, sigs)
		}
	case script:
		switch sigs := matchSignatures(content, php); {
		case slices.Equal(sigs, []string{"encoded_blob"}):
			s.add(KindEncodedBlob, name, e, nil)
		case len(sigs) > 0:
			s.add(KindSignature, name, e, sigs)
		}
	}
	if inUploads && !script && isSVG(base, content) {
		if sigs := svgSignals(content); sigs != nil {
			s.add(KindActiveSVG, name, e, sigs)
		}
	}
	hidden := isSuspiciousHidden(e.Name())
	// Signatures above still apply to these: only the hidden name stops being a finding. A
	// hidden .php with no PHP in it, or that only sets values, runs nothing (the ._ files macOS
	// leaves in a zip it packed, a CMS's version file), and an empty file, an image, a video or a document a CMS saved without a name
	// before its extension hides nothing.
	runsNothing := php && complete && (!bytes.Contains(content, []byte("<?")) || onlyLiterals(content))
	switch {
	case script && hidden && !inDependencyTests(name) && !runsNothing:
		s.add(KindHiddenScript, name, e, nil)
	case inData && hidden && !script && (complete && len(content) == 0 || mediaOrDocument(content)):
	case inData && hidden:
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
	if kind == KindSuspiciousSymlink && !inData && len(sigs) == 0 && s.sharedFile(name) {
		if !outside {
			return
		}
		kind = KindExternalSymlink
	}
	if f := s.add(kind, name, e, sigs); f != nil {
		f.Target = target
	}
	if s.isPHP(strings.ToLower(e.Name())) {
		s.markReachable(name)
	}
}

// sharedContent hashes, and inspects, the file behind a release's link to its shared copy;
// "" for any other link.
func (s *scanner) sharedContent(name string) string {
	if !isScript(strings.ToLower(path.Base(name))) || !s.sharedFile(name) {
		return ""
	}
	resolved, ok := s.followable(name)
	if !ok {
		return ""
	}
	info, err := fs.Lstat(s.src.FS, resolved)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return s.inspectFile(resolved, fs.FileInfoToDirEntry(info), false, false, true)
}

// sharedFile reports whether a script link is a release's link to its shared copy, the way
// Capistrano's linked_files and Deployer's shared_files keep wp-config.php or .env across
// releases: the target, resolved for real inside the application or its deploy directory, is
// a regular script at the same path relative to the application, outside every upload or data
// directory. A script linked to an upload, to another name or to anything else stays
// suspicious.
func (s *scanner) sharedFile(name string) bool {
	rel := strings.TrimPrefix(name, s.root+"/")
	resolved, ok := s.followable(name)
	if !ok || rel == name || resolved == name || !strings.HasSuffix(resolved, "/"+rel) || !isScript(strings.ToLower(path.Base(resolved))) {
		return false
	}
	if info, err := fs.Lstat(s.src.FS, resolved); err != nil || !info.Mode().IsRegular() {
		return false
	}
	for _, dir := range strings.Split(path.Dir(resolved), "/") {
		if slices.Contains(discovery.GenericUploadDirs, strings.ToLower(dir)) {
			return false
		}
	}
	return !slices.ContainsFunc(append(slices.Clone(s.uploads), s.data...), func(d string) bool { return resolved == d || strings.HasPrefix(resolved, d+"/") })
}

// dataScanChunk is how much of a large data file is read at a time; the lexer keeps its state
// from one piece to the next, so code is judged with its block however far from its tag.
const dataScanChunk = 1 << 20

// streamCodeInData reads a data file too large to load, piece after piece, and searches it for
// code within the run's budget; past it, an issue says the file was read at its edges.
func (s *scanner) streamCodeInData(name string, info fs.FileInfo) []string {
	if s.budget.dataLeft < info.Size() {
		s.issues = append(s.issues, fmt.Sprintf("/%s: %d bytes, read for code at its edges only: budget of %d bytes a run spent", name, info.Size(), MaxDataScanBytesPerRun))
		s.budget.unsearched(name)
		return nil
	}
	s.budget.dataLeft -= info.Size()
	f, err := s.src.FS.Open(name)
	if err != nil {
		s.issues.Add(err)
		return nil
	}
	defer func() { _ = f.Close() }()
	// What the file had when listed: a log written meanwhile does not keep the scan going.
	r := io.LimitReader(f, info.Size())
	c := newDataSearch(&s.budget.codeLeft)
	before := s.budget.codeLeft
	defer func() { s.budget.spent(name, info, before-s.budget.codeLeft) }()
	buf := make([]byte, dataScanChunk)
	var head []byte
	for !c.exhausted() {
		n, err := io.ReadFull(r, buf)
		if head == nil {
			head = slices.Clone(buf[:min(n, 16)])
		}
		last := err != nil
		c.feed(buf[:n], last)
		if last {
			break
		}
	}
	if c.exhausted() {
		s.issues = append(s.issues, fmt.Sprintf("/%s: not fully searched for code: budget of %d bytes of code in data files a run spent", name, MaxDataCodeBytesPerRun))
		s.budget.unsearched(name)
	}
	return strongInDocuments(head, c.signatures())
}

// mediaMagic are the first bytes of the images, videos and sounds uploaded every day.
var mediaMagic = [][]byte{[]byte("\x89PNG"), []byte("\xff\xd8\xff"), []byte("GIF8"), []byte("RIFF"), []byte("ID3"), []byte("\x1a\x45\xdf\xa3"),
	[]byte("OggS"), []byte("fLaC"), []byte("II*\x00"), []byte("MM\x00*")}

// mediaOrDocument reports content that starts like a document, an archive or a media file. MP4
// and QuickTime name their type after a four-byte box size.
func mediaOrDocument(head []byte) bool {
	starts := func(m []byte) bool { return bytes.HasPrefix(head, m) }
	return slices.ContainsFunc(documentMagic, starts) || slices.ContainsFunc(mediaMagic, starts) ||
		len(head) >= 12 && bytes.Equal(head[4:8], []byte("ftyp"))
}

// polyglot reports an image carrying server-side code. The full open tag cannot come from
// compressed pixels by chance; the short echo tag can, every few megabytes, so it counts only
// with code a signature names.
func polyglot(content []byte, php bool) bool {
	if bytes.Contains(content, []byte("<?php")) || bytes.Contains(content, []byte("<?PHP")) || bytes.Contains(content, []byte("__HALT_COMPILER")) {
		return true
	}
	return containsCode(content) && slices.ContainsFunc(matchSignatures(content, php), func(sig string) bool { return !slices.Contains(weakCodeSignals, sig) })
}

// documentMagic are the first bytes of the documents and archives uploaded every day: PDF,
// ZIP (and the Office and OpenDocument formats inside), gzip, old Office, 7-Zip and RAR.
var documentMagic = [][]byte{[]byte("%PDF-"), []byte("PK\x03\x04"), []byte("\x1f\x8b"), []byte("\xd0\xcf\x11\xe0"), []byte("7z\xbc\xaf"), []byte("Rar!")}

// weakCodeSignals are the signals of a block that random bytes produce too: a backtick, a word
// like exec(.
var weakCodeSignals = []string{"backtick_exec", "dangerous_call"}

// strongInDocuments keeps only the named signatures of a file that starts like a document or an
// archive: their compressed streams hold an open tag and a backtick by chance every few
// megabytes, in text PHP would compile, while code planted to run is named by a signature.
func strongInDocuments(head []byte, sigs []string) []string {
	if !mediaOrDocument(head) {
		return sigs
	}
	return slices.DeleteFunc(sigs, func(s string) bool { return slices.Contains(weakCodeSignals, s) })
}

// codeInData searches data for code within the run's budget, and says when it ran out.
func (s *scanner) codeInData(name string, e fs.DirEntry, content []byte) []string {
	before := s.budget.codeLeft
	sigs, exhausted := codeInData(content, &s.budget.codeLeft)
	sigs = strongInDocuments(content, sigs)
	if info, err := e.Info(); err == nil {
		s.budget.spent(name, info, before-s.budget.codeLeft)
	}
	if exhausted {
		s.issues = append(s.issues, fmt.Sprintf("/%s: not fully searched for code: budget of %d bytes of code in data files a run spent", name, MaxDataCodeBytesPerRun))
		s.budget.unsearched(name)
	}
	return sigs
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
		// Drupal ships its own test fixtures under core/, like a dependency.
		if !slices.Contains(thirdPartyDirs, p) && p != "core" {
			continue
		}
		return slices.ContainsFunc(parts[i+1:len(parts)-1], func(d string) bool {
			return slices.Contains(dependencyTestDirs, strings.ToLower(d))
		})
	}
	return false
}

// drupalTwigCache is where Drupal keeps the PHP it compiles from Twig templates.
var drupalTwigCache = regexp.MustCompile(`/sites/[^/]+/files/php/twig/[^/]+/[^/]+\.php$`)

// compiledTwig reports a file of Drupal's Twig cache: at its place, and with the header Twig
// gives the classes it generates.
func compiledTwig(name string, content []byte) bool {
	head := content[:min(len(content), 512)]
	return drupalTwigCache.MatchString("/"+name) && bytes.HasPrefix(head, []byte("<?php")) && bytes.Contains(head, []byte("use Twig\\"))
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

// IsScript reports whether the web server may run a file of this name as a script, by its
// extension: what the scan counts as a script, for the real-time rules to judge alike.
func IsScript(name string) bool { return isScript(strings.ToLower(path.Base(name))) }

// IsOverride reports whether a file of this name changes how the web server treats its
// directory, such as an .htaccess.
func IsOverride(name string) bool { return slices.Contains(overrideNames, path.Base(name)) }
