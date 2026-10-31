package refs

import (
	"context"
	"crypto/md5" //nolint:gosec // only to compare with the MD5 drupal.org publishes for an archive
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// ErrArchiveSource is an archive a release history points outside drupal.org's file host.
var ErrArchiveSource = errors.New("refs: archive outside the file host")

// fetchDrupal makes the reference of a drupal.org project's release: its release history names
// the zip archive with its size and MD5, the archive must come from drupal.org's file host and
// have that size and MD5, and every file in it is hashed here.
func (f *Fetcher) fetchDrupal(ctx context.Context, k Key, base *url.URL, files string) (store.ContentRef, error) {
	ref := store.ContentRef{Ecosystem: k.Ecosystem, Slug: k.Slug, Version: k.Version}
	fileHost, err := url.Parse(files)
	if err != nil || fileHost.Host == "" {
		return ref, errors.New("refs: no file host for drupal.org")
	}
	raw, found, err := f.get(ctx, base.JoinPath("release-history", k.Slug, "current"), maxReferenceBytes)
	if err != nil {
		return ref, err
	}
	var history struct {
		Releases []struct {
			Version string `xml:"version"`
			Files   []struct {
				URL  string `xml:"url"`
				Type string `xml:"archive_type"`
				MD5  string `xml:"md5"`
				Size int64  `xml:"size"`
			} `xml:"files>file"`
		} `xml:"releases>release"`
	}
	if !found || xml.Unmarshal(raw, &history) != nil {
		ref.Missing = true
		return ref, nil
	}
	for _, rel := range history.Releases {
		if rel.Version != k.Version {
			continue
		}
		for _, file := range rel.Files {
			if file.Type != "zip" {
				continue
			}
			u, err := url.Parse(file.URL)
			if err != nil || u.Scheme != fileHost.Scheme || u.Host != fileHost.Host || !strings.HasPrefix(u.Path, "/files/projects/") {
				return ref, fmt.Errorf("%w: %s", ErrArchiveSource, file.URL)
			}
			zipped, found, err := f.get(ctx, u, maxArchiveBytes)
			if err != nil {
				return ref, err
			}
			sum := md5.Sum(zipped) //nolint:gosec // compared with drupal.org's MD5 of the archive
			if !found || int64(len(zipped)) != file.Size || hex.EncodeToString(sum[:]) != file.MD5 {
				return ref, ErrCrossCheck
			}
			ref.Files, _, err = hashArchive(zipped)
			return ref, err
		}
	}
	ref.Missing = true
	return ref, nil
}
