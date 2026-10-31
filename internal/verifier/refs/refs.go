// Package refs fetches and keeps the published content of public components (the files of a
// WordPress plugin's release, by SHA-256), so that a changed script that matches the release it
// belongs to can be told from one that does not. It is off unless the verifier is configured to
// use it: fetching tells the sources which releases the servers run.
package refs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// Ecosystems the references are fetched for.
const (
	WordPressPlugin = "wordpress-plugin"
	// WordPressCore is WordPress itself; its key's Slug is the locale of the release.
	WordPressCore = "wordpress-core"
	// WordPressTheme is a theme of WordPress's directory.
	WordPressTheme = "wordpress-theme"
	// DrupalProject is a module or theme of drupal.org, its Slug the project's short name.
	DrupalProject = "drupal-project"
	// drupalFiles is the host Drupal's archives must come from.
	drupalFiles = "drupal-files"
	// wordPressAPI is the source of WordPress's MD5 lists, the cross-check of the core's archive.
	wordPressAPI = "wordpress-api"
)

// Key names a release.
type Key struct {
	Ecosystem, Slug, Version string
}

// A slug and a version come from a sensor, which a compromised host controls: only these shapes
// ever reach a URL, so no host, path or query can be put in one.
var (
	slugPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,99}$`)
	localePattern  = regexp.MustCompile(`^[a-z]{2,3}(_[A-Z]{2})?(_[a-z]{2,10})?$`)
	drupalPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,99}$`)
	versionPattern = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]{0,31}$`)
)

// Valid reports whether the key may be fetched.
func (k Key) Valid() bool {
	if !versionPattern.MatchString(k.Version) {
		return false
	}
	switch k.Ecosystem {
	case WordPressPlugin, WordPressTheme:
		return slugPattern.MatchString(k.Slug)
	case WordPressCore:
		return localePattern.MatchString(k.Slug)
	case DrupalProject:
		return drupalPattern.MatchString(k.Slug)
	}
	return false
}

// DefaultSources are where each ecosystem's references come from.
var DefaultSources = map[string]string{
	WordPressPlugin: "https://downloads.wordpress.org",
	WordPressCore:   "https://downloads.wordpress.org",
	WordPressTheme:  "https://downloads.wordpress.org",
	DrupalProject:   "https://updates.drupal.org",
	drupalFiles:     "https://ftp.drupal.org",
	wordPressAPI:    "https://api.wordpress.org",
}

// maxReferenceBytes bounds one downloaded list of checksums; the largest plugins list a few
// thousand files.
const maxReferenceBytes = 16 << 20

// ErrTooLarge is a reference past maxReferenceBytes.
var ErrTooLarge = errors.New("refs: reference larger than its bound")

// Fetcher downloads references from fixed sources.
type Fetcher struct {
	// Sources maps an ecosystem to the base URL of its source; DefaultSources when nil.
	Sources map[string]string
	Client  *http.Client
}

// Fetch downloads the reference of a release. A release the source does not have is a
// reference with Missing set, not an error.
func (f *Fetcher) Fetch(ctx context.Context, k Key) (store.ContentRef, error) {
	ref := store.ContentRef{Ecosystem: k.Ecosystem, Slug: k.Slug, Version: k.Version}
	if !k.Valid() {
		return ref, fmt.Errorf("refs: invalid key %q %q %q", k.Ecosystem, k.Slug, k.Version)
	}
	sources := f.Sources
	if sources == nil {
		sources = DefaultSources
	}
	base, err := url.Parse(sources[k.Ecosystem])
	if err != nil || base.Host == "" {
		return ref, fmt.Errorf("refs: no source for %s", k.Ecosystem)
	}
	switch k.Ecosystem {
	case WordPressCore:
		return f.fetchCore(ctx, k, base, sources[wordPressAPI])
	case WordPressTheme:
		return f.fetchTheme(ctx, k, base)
	case DrupalProject:
		return f.fetchDrupal(ctx, k, base, sources[drupalFiles])
	}
	u := base.JoinPath("plugin-checksums", k.Slug, k.Version+".json")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ref, err
	}
	resp, err := f.client(base.Host).Do(req)
	if err != nil {
		return ref, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		ref.Missing = true
		return ref, nil
	default:
		return ref, fmt.Errorf("refs: %s: %s", u.Redacted(), resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxReferenceBytes+1))
	if err != nil {
		return ref, err
	}
	if len(raw) > maxReferenceBytes {
		return ref, ErrTooLarge
	}
	ref.Files, err = pluginChecksums(raw)
	return ref, err
}

// get downloads u, at most limit bytes; a 404 is found false.
func (f *Fetcher) get(ctx context.Context, u *url.URL, limit int64) (body []byte, found bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := f.client(u.Host).Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("refs: %s: %s", u.Redacted(), resp.Status)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) > limit {
		return nil, false, ErrTooLarge
	}
	return body, true, nil
}

// client is the fetcher's client, kept to the source's host: a redirect elsewhere is refused.
func (f *Fetcher) client(host string) *http.Client {
	c := http.Client{Timeout: 30 * time.Second}
	if f.Client != nil {
		c = *f.Client
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != host || req.URL.Scheme != via[0].URL.Scheme || len(via) > 3 {
			return fmt.Errorf("refs: redirect to %s://%s refused", req.URL.Scheme, req.URL.Host)
		}
		return nil
	}
	return &c
}

// maxReferenceFiles bounds the files of one release.
const maxReferenceFiles = 50000

// pluginChecksums reads the list WordPress publishes for a plugin's release: each file's path
// with its SHA-256, one or several.
func pluginChecksums(raw []byte) (map[string][]string, error) {
	var doc struct {
		Files map[string]struct {
			SHA256 json.RawMessage `json:"sha256"`
		} `json:"files"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("refs: checksums: %w", err)
	}
	if len(doc.Files) > maxReferenceFiles {
		return nil, ErrTooLarge
	}
	files := make(map[string][]string, len(doc.Files))
	for p, f := range doc.Files {
		var one string
		var many []string
		switch {
		case json.Unmarshal(f.SHA256, &one) == nil:
			many = []string{one}
		case json.Unmarshal(f.SHA256, &many) == nil:
		default:
			continue
		}
		files[p] = many
	}
	return files, nil
}

// Resolver gives the reference of a release from the store, fetching it when the store has none,
// within bounds: a host that names a thousand releases starts a handful of downloads, not a
// thousand.
type Resolver struct {
	Store   *store.Store
	Fetcher *Fetcher
	// Enabled turns references on; off, Lookup always answers none.
	Enabled bool
	// PerRound bounds the fetches of one pass of the analysis queue, PerHostDay those a host's
	// snapshots start in a day.
	PerRound, PerHostDay int
	Now                  func() time.Time
	// Background hands fetches to Run instead of making them in Lookup, so that a slow source
	// never holds up the analysis: a release is then judged from the next snapshot on.
	Background bool

	mu      sync.Mutex
	round   int
	day     string
	perHost map[string]int
	queue   chan Key
	queued  map[Key]bool
}

// maxQueued bounds the releases waiting to be fetched in the background.
const maxQueued = 64

// missingFor is how long a release the source does not have, or could not give (a timeout, an
// error, a list too large or malformed), is remembered before it is asked for again: a host
// naming one cannot make the verifier try at every snapshot.
const missingFor = 24 * time.Hour

// NewRound starts an analysis round, whose fetches PerRound bounds.
func (r *Resolver) NewRound() {
	r.mu.Lock()
	r.round = 0
	r.mu.Unlock()
}

// Lookup returns the reference of a release for a host's snapshot, and false when there is none
// to use: references off, the key invalid, the source without that release, or the bounds spent.
func (r *Resolver) Lookup(ctx context.Context, host string, k Key) (store.ContentRef, bool) {
	if !r.Enabled || !k.Valid() {
		return store.ContentRef{}, false
	}
	now := r.now()
	ref, ok, err := r.Store.ContentRef(ctx, k.Ecosystem, k.Slug, k.Version, now)
	if err == nil && ok && (!ref.Missing || now.Sub(ref.FetchedAt) < missingFor) {
		return ref, !ref.Missing
	}
	if !r.take(host, now) {
		return store.ContentRef{}, false
	}
	if r.Background {
		r.enqueue(k)
		return store.ContentRef{}, false
	}
	ref = r.fetch(ctx, k, now)
	return ref, !ref.Missing
}

// fetch fetches and keeps a release's reference; a failure is kept as missing, for missingFor.
func (r *Resolver) fetch(ctx context.Context, k Key, now time.Time) store.ContentRef {
	ref, err := r.Fetcher.Fetch(ctx, k)
	if err != nil {
		ref = store.ContentRef{Ecosystem: k.Ecosystem, Slug: k.Slug, Version: k.Version, Missing: true}
	}
	_ = r.Store.PutContentRef(ctx, ref, now)
	return ref
}

func (r *Resolver) enqueue(k Key) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.queue == nil {
		r.queue, r.queued = make(chan Key, maxQueued), map[Key]bool{}
	}
	if r.queued[k] {
		return
	}
	select {
	case r.queue <- k:
		r.queued[k] = true
	default:
	}
}

// Run makes the fetches Lookup handed over, one at a time, until ctx ends.
func (r *Resolver) Run(ctx context.Context) {
	r.mu.Lock()
	if r.queue == nil {
		r.queue, r.queued = make(chan Key, maxQueued), map[Key]bool{}
	}
	queue := r.queue
	r.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			return
		case k := <-queue:
			r.fetch(ctx, k, r.now())
			r.mu.Lock()
			delete(r.queued, k)
			r.mu.Unlock()
		}
	}
}

// take spends one fetch of the round and of the host's day, or reports none is left.
func (r *Resolver) take(host string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if day := now.UTC().Format(time.DateOnly); day != r.day || r.perHost == nil {
		r.day, r.perHost = day, map[string]int{}
	}
	if r.round >= r.PerRound || r.perHost[host] >= r.PerHostDay {
		return false
	}
	r.round++
	r.perHost[host]++
	return true
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
