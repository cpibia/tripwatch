// Package selfupdate installs the latest release of the sensor in the same form as the one
// running: the .deb or .rpm package when the package manager owns the binary, the static binary
// otherwise.
//
// The file is checked against the release's SHA256SUMS before anything is installed. Both come
// from the same release over TLS, so the check catches a truncated or altered download, not a
// compromised release; `gh attestation verify` remains the way to prove where a file was built.
package selfupdate

import (
	"bufio"
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
)

// Repository is where releases are published.
const Repository = "https://github.com/cpibia/tripwatch"

const (
	maxSumsSize  = 64 << 10
	maxAssetSize = 128 << 20
)

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
	kind := u.detect(ctx)
	name, err := AssetName(kind, latest, u.Arch)
	if err != nil {
		return "", err
	}
	base := u.BaseURL + "/releases/download/v" + latest + "/"
	sums, err := u.fetch(ctx, base+"SHA256SUMS", maxSumsSize)
	if err != nil {
		return "", fmt.Errorf("checksums of %s: %w", latest, err)
	}
	want, err := lookupSum(sums, name)
	if err != nil {
		return "", err
	}

	dir, err := os.MkdirTemp("", "tripwatch-update-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	_, _ = fmt.Fprintf(u.Out, "Downloading %s\n", name)
	path := filepath.Join(dir, name)
	if err := u.download(ctx, base+name, path, want); err != nil {
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

func (u Updater) fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	resp, err := u.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

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
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return resp, nil
}

// download writes url to path and fails unless its SHA-256 is want.
func (u Updater) download(ctx context.Context, url, path, want string) error {
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
		return fmt.Errorf("%s: SHA-256 %s does not match SHA256SUMS (%s)", filepath.Base(path), got, want)
	}
	return nil
}

func lookupSum(sums []byte, name string) (string, error) {
	sc := bufio.NewScanner(strings.NewReader(string(sums)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			if b, err := hex.DecodeString(fields[0]); err != nil || len(b) != sha256.Size {
				return "", fmt.Errorf("SHA256SUMS: malformed entry for %s", name)
			}
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("SHA256SUMS lists no %s", name)
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
