package refs

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // only to compare with the MD5 list WordPress publishes
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/url"
	"strings"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// Bounds of a core release's archive: downloaded, expanded, and entries. WordPress's archives are
// about 27 MB, 70 MB expanded, 3,500 files. Variables for the tests.
var (
	maxArchiveBytes  int64 = 64 << 20
	maxExpandedBytes int64 = 256 << 20
	maxArchiveFiles        = 50000
)

// ErrCrossCheck is a core archive whose files do not have the MD5 WordPress's API lists.
var ErrCrossCheck = errors.New("refs: archive differs from WordPress's MD5 list")

// fetchCore makes the reference of a WordPress release from its official archive, hashing every
// file itself, and checks it against the MD5 list api.wordpress.org publishes: a file of the
// list that the archive lacks or has with another MD5 drops the reference, so one source alone
// cannot make a file pass.
func (f *Fetcher) fetchCore(ctx context.Context, k Key, base *url.URL, api string) (store.ContentRef, error) {
	ref := store.ContentRef{Ecosystem: k.Ecosystem, Slug: k.Slug, Version: k.Version}
	apiURL, err := url.Parse(api)
	if err != nil || apiURL.Host == "" {
		return ref, errors.New("refs: no source for WordPress's checksums")
	}
	listURL := apiURL.JoinPath("core", "checksums", "1.0/")
	listURL.RawQuery = url.Values{"version": {k.Version}, "locale": {k.Slug}}.Encode()
	raw, found, err := f.get(ctx, listURL, maxReferenceBytes)
	if err != nil {
		return ref, err
	}
	var list struct {
		Checksums json.RawMessage `json:"checksums"`
	}
	if !found || json.Unmarshal(raw, &list) != nil || string(list.Checksums) == "false" {
		ref.Missing = true
		return ref, nil
	}
	var md5s map[string]string
	if err := json.Unmarshal(list.Checksums, &md5s); err != nil {
		return ref, fmt.Errorf("refs: core checksums: %w", err)
	}
	archive := base.JoinPath("release", "wordpress-"+k.Version+".zip")
	if k.Slug != "en_US" {
		archive = base.JoinPath("release", k.Slug, "wordpress-"+k.Version+".zip")
	}
	zipped, found, err := f.get(ctx, archive, maxArchiveBytes)
	if err != nil {
		return ref, err
	}
	if !found {
		ref.Missing = true
		return ref, nil
	}
	files, sums, err := hashArchive(zipped)
	if err != nil {
		return ref, err
	}
	for p, want := range md5s {
		if sums[p] != want {
			return ref, fmt.Errorf("%w: %s", ErrCrossCheck, p)
		}
	}
	ref.Files = files
	return ref, nil
}

// hashArchive returns the SHA-256 and the MD5 of every file of a release's archive, by its path
// under the archive's top directory, within the bounds on entries and expanded bytes.
func hashArchive(zipped []byte) (sha map[string][]string, md5s map[string]string, err error) {
	zr, err := zip.NewReader(bytes.NewReader(zipped), int64(len(zipped)))
	if err != nil {
		return nil, nil, fmt.Errorf("refs: archive: %w", err)
	}
	if len(zr.File) > maxArchiveFiles {
		return nil, nil, ErrTooLarge
	}
	sha, md5s = map[string][]string{}, map[string]string{}
	left := maxExpandedBytes
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		_, p, ok := strings.Cut(zf.Name, "/")
		if !ok || p == "" {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("refs: archive: %w", err)
		}
		s, m := sha256.New(), md5.New() //nolint:gosec // compared with WordPress's MD5 list only
		n, err := io.Copy(io.MultiWriter(s, m), io.LimitReader(rc, left+1))
		_ = rc.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("refs: archive: %w", err)
		}
		if left -= n; left < 0 {
			return nil, nil, ErrTooLarge
		}
		sha[p], md5s[p] = []string{sum(s)}, sum(m)
	}
	return sha, md5s, nil
}

func sum(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }
