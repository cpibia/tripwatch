// Package selfupdate installs the latest release of the sensor in the same form as the one
// running: the .deb or .rpm package when the package manager owns the binary, the static binary
// otherwise.
//
// Nothing is installed unless the release's build provenance proves the file was built by
// tripwatch's release workflow from the tag of that version (package provenance, verified
// offline against the Sigstore roots embedded in the binary). The release's SHA256SUMS is not
// read: whoever can change a release can change it too. An update order from the verifier adds
// its own hash, which must be the attested one, but cannot replace the provenance.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/cpibia/tripwatch/internal/provenance"
)

// Repository is where releases are published.
const Repository = "https://github.com/cpibia/tripwatch"

const maxAssetSize = 128 << 20

// ProvenanceAsset is the release file holding the Sigstore bundle of the build provenance.
const ProvenanceAsset = "provenance.sigstore.json"

// RejectedError is an update refused on evidence: a release whose provenance is missing or does
// not verify, or a file or an order that is not the attested one. Retrying will not change it;
// errors of any other type (the network, the server, the disk) may go away on their own.
type RejectedError struct {
	Version string
	Err     error
}

func (e *RejectedError) Error() string {
	return "update to " + e.Version + " refused: " + e.Err.Error()
}

func (e *RejectedError) Unwrap() error { return e.Err }

func rejected(version string, format string, args ...any) error {
	return &RejectedError{Version: version, Err: fmt.Errorf(format, args...)}
}

// Kind is how the running sensor was installed.
type Kind string

// Installation kinds.
const (
	Deb    Kind = "deb"
	RPM    Kind = "rpm"
	Binary Kind = "binary"
)

var releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// Updater holds what an update depends on, so tests can replace the network and the commands.
type Updater struct {
	Client  *http.Client
	BaseURL string
	// Current is the running version; "dev" or any other non-release value is always replaced.
	Current string
	Arch    string
	// Executable is the path of the running binary, replaced in place for a Binary install.
	Executable string
	// Run executes a command, writing its output to out; an error means it failed or was not
	// found.
	Run func(ctx context.Context, out io.Writer, name string, args ...string) error
	Out io.Writer
	// Provenance verifies the release's bundle; nil is the public-good Sigstore embedded in the
	// binary, the only one outside tests.
	Provenance *provenance.Verifier
}

// Update installs the latest release if it is newer than the running one, and reports the
// version that is installed afterwards.
func (u Updater) Update(ctx context.Context) (string, error) {
	latest, err := u.Latest(ctx)
	if err != nil {
		return "", err
	}
	if !newer(latest, u.Current) {
		_, _ = fmt.Fprintf(u.Out, "tripwatch-sensor %s is up to date (latest release %s)\n", u.Current, latest)
		return u.Current, nil
	}
	return u.install(ctx, latest, nil)
}

// UpdateTo installs version, if newer than the running one, on an order the caller verified:
// the hash sums gives for the file must also be the one its provenance attests.
func (u Updater) UpdateTo(ctx context.Context, version string, sums map[string]string) (string, error) {
	if !releaseVersion.MatchString(version) {
		return "", fmt.Errorf("%q is not a release version", version)
	}
	if !newer(version, u.Current) {
		_, _ = fmt.Fprintf(u.Out, "tripwatch-sensor %s is not older than %s\n", u.Current, version)
		return u.Current, nil
	}
	if sums == nil {
		sums = map[string]string{}
	}
	return u.install(ctx, version, sums)
}

// install verifies the release's provenance, downloads the file for this installation, checks
// it against the attested digest, and installs it. With ordered sums, the order's hash for the
// file must be the attested one.
func (u Updater) install(ctx context.Context, latest string, ordered map[string]string) (string, error) {
	kind := u.detect(ctx)
	name, err := AssetName(kind, latest, u.Arch)
	if err != nil {
		return "", err
	}
	base := u.BaseURL + "/releases/download/v" + latest + "/"
	sum, err := u.attested(ctx, base, latest, name)
	if err != nil {
		return "", err
	}
	if ordered != nil {
		if want, ok := ordered[name]; !ok || !strings.EqualFold(want, sum) {
			return "", rejected(latest, "the order's hash for %s is not the attested one", name)
		}
	}

	dir, err := os.MkdirTemp("", "tripwatch-update-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	_, _ = fmt.Fprintf(u.Out, "Downloading %s\n", name)
	path := filepath.Join(dir, name)
	if err := u.download(ctx, base+name, path, sum, latest); err != nil {
		return "", err
	}

	switch kind {
	case Deb:
		err = u.Run(ctx, u.Out, "dpkg", "-i", path)
	case RPM:
		err = u.Run(ctx, u.Out, "rpm", "-U", path)
	default:
		err = replaceExecutable(path, u.Executable)
		if err == nil {
			// The packages' postinstall does the same; a binary install has nobody else to do it.
			_ = u.Run(ctx, u.Out, "systemctl", "try-restart", "tripwatch-sensor")
		}
	}
	if err != nil {
		return "", fmt.Errorf("installing %s: %w", name, err)
	}
	_, _ = fmt.Fprintf(u.Out, "tripwatch-sensor updated from %s to %s (%s)\n", u.Current, latest, kind)
	return latest, nil
}

// Latest returns the version of the latest release, read from the redirect of
// /releases/latest, which unlike the API has no rate limit for unauthenticated clients.
func (u Updater) Latest(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.BaseURL+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	client := *u.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	loc := resp.Header.Get("Location")
	i := strings.LastIndex(loc, "/tag/v")
	if resp.StatusCode/100 != 3 || i < 0 {
		return "", fmt.Errorf("latest release: unexpected answer %s", resp.Status)
	}
	v := loc[i+len("/tag/v"):]
	if !releaseVersion.MatchString(v) {
		return "", fmt.Errorf("latest release: %q is not a release version", v)
	}
	return v, nil
}

// Detect is how the running sensor was installed.
func (u Updater) Detect(ctx context.Context) Kind { return u.detect(ctx) }

// detect asks the package managers whether they own the running binary; a binary owned by
// neither was installed by hand and is replaced in place.
func (u Updater) detect(ctx context.Context) Kind {
	if u.Run(ctx, io.Discard, "dpkg", "-S", u.Executable) == nil {
		return Deb
	}
	if u.Run(ctx, io.Discard, "rpm", "-qf", u.Executable) == nil {
		return RPM
	}
	return Binary
}

// AssetName is the name of the release file for an installation kind, as GoReleaser names it.
func AssetName(kind Kind, version, arch string) (string, error) {
	rpmArch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[arch]
	if rpmArch == "" {
		return "", fmt.Errorf("no release is built for %s", arch)
	}
	switch kind {
	case Deb:
		return "tripwatch-sensor_" + version + "_" + arch + ".deb", nil
	case RPM:
		return "tripwatch-sensor-" + version + "-1." + rpmArch + ".rpm", nil
	default:
		return "tripwatch-sensor_" + version + "_linux_" + arch, nil
	}
}

// attested fetches and verifies the release's provenance bundle and returns the digest it
// attests for name. A bundle that is missing (404) or does not verify is a refusal; a failure to
// reach the server is not.
func (u Updater) attested(ctx context.Context, base, version, name string) (string, error) {
	v := u.Provenance
	if v == nil {
		var err error
		if v, err = provenance.Default(); err != nil {
			return "", err
		}
	}
	resp, err := u.get(ctx, base+ProvenanceAsset)
	var status *statusError
	if errors.As(err, &status) && status.code == http.StatusNotFound {
		return "", rejected(version, "the release has no %s", ProvenanceAsset)
	}
	if err != nil {
		return "", fmt.Errorf("provenance of %s: %w", version, err)
	}
	defer func() { _ = resp.Body.Close() }()
	bundle, err := io.ReadAll(io.LimitReader(resp.Body, provenance.MaxBundleSize+1))
	if err != nil {
		return "", fmt.Errorf("provenance of %s: %w", version, err)
	}
	subjects, err := v.Verify(bundle, version)
	if err != nil {
		return "", &RejectedError{Version: version, Err: err}
	}
	d, ok := subjects[name]
	if !ok {
		return "", rejected(version, "the provenance does not attest %s", name)
	}
	return hex.EncodeToString(d[:]), nil
}

type statusError struct {
	url  string
	code int
	text string
}

func (e *statusError) Error() string { return e.url + ": " + e.text }

func (u Updater) get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, &statusError{url: url, code: resp.StatusCode, text: resp.Status}
	}
	return resp, nil
}

// download writes url to path and refuses it unless its SHA-256 is the attested want.
func (u Updater) download(ctx context.Context, url, path, want, version string) error {
	resp, err := u.get(ctx, url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // inside our own temporary directory
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxAssetSize))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return rejected(version, "%s: SHA-256 %s is not the attested %s", filepath.Base(path), got, want)
	}
	return nil
}

// replaceExecutable copies src next to dst and renames it over dst, so the binary is never seen
// half written, and a running process keeps its own copy until it restarts.
func replaceExecutable(src, dst string) error {
	if dst == "" {
		return errors.New("path of the running binary unknown")
	}
	in, err := os.Open(src) //nolint:gosec // the file just downloaded and checked
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tripwatch-sensor-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err = io.Copy(tmp, in)
	if err == nil {
		err = tmp.Chmod(0o755) //nolint:gosec // an executable meant to be run by anyone, like the packaged one
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// newer reports whether latest is a later release than current. A current version that is not
// a release, such as a development build, is always replaced.
// Newer reports whether release version latest is newer than current; a current version that
// is not a release (a development build) is older than any release.
func Newer(latest, current string) bool { return newer(latest, current) }

func newer(latest, current string) bool {
	if !releaseVersion.MatchString(current) {
		return true
	}
	l, c := strings.Split(latest, "."), strings.Split(current, ".")
	for i := range l {
		a, _ := strconv.Atoi(l[i])
		b, _ := strconv.Atoi(c[i])
		if a != b {
			return a > b
		}
	}
	return false
}
