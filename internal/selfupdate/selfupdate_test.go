package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cpibia/tripwatch/internal/provenance"
)

// The release the synthetic Sigstore in ../provenance/testdata signed: version 1.2.3, each file
// holding "contents of <name>".
const release = "1.2.3"

var releaseFiles = func() map[string][]byte {
	files := map[string][]byte{}
	for _, name := range []string{
		"tripwatch-sensor_1.2.3_amd64.deb",
		"tripwatch-sensor-1.2.3-1.x86_64.rpm",
		"tripwatch-sensor_1.2.3_linux_amd64",
		"tripwatch-sensor_1.2.3_arm64.deb",
	} {
		files[name] = []byte("contents of " + name)
	}
	return files
}()

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "provenance", "testdata", "synthetic", name)) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testVerifier(t *testing.T) *provenance.Verifier {
	t.Helper()
	v, err := provenance.NewVerifier(fixture(t, "trusted_root.json"))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type fakeRelease struct {
	latest string
	files  map[string][]byte
	// provenance is served as the bundle; with status set, the bundle answers that instead.
	provenance []byte
	status     int
}

func (f fakeRelease) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases/latest" {
			http.Redirect(w, r, "/releases/tag/v"+f.latest, http.StatusFound)
			return
		}
		prefix := "/releases/download/v" + f.latest + "/"
		name, ok := strings.CutPrefix(r.URL.Path, prefix)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if name == ProvenanceAsset {
			if f.status != 0 {
				w.WriteHeader(f.status)
				return
			}
			_, _ = w.Write(f.provenance)
			return
		}
		b, ok := f.files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f fakeRelease) signed(t *testing.T) fakeRelease {
	t.Helper()
	if f.latest == "" {
		f.latest = release
	}
	if f.files == nil {
		f.files = releaseFiles
	}
	if f.provenance == nil {
		f.provenance = fixture(t, "valid.jsonl")
	}
	return f
}

// commands records what was run and answers ownership queries for the package manager in owner.
type commands struct {
	owner     string
	ran       []string
	installed []byte
}

func (c *commands) run(_ context.Context, _ io.Writer, name string, args ...string) error {
	c.ran = append(c.ran, name+" "+strings.Join(args, " "))
	switch {
	case name == "dpkg" && args[0] == "-S", name == "rpm" && args[0] == "-qf":
		if name != c.owner {
			return errors.New("not owned")
		}
	case name == "dpkg" && args[0] == "-i", name == "rpm" && args[0] == "-U":
		b, err := os.ReadFile(args[1])
		c.installed = b
		return err
	}
	return nil
}

func newUpdater(t *testing.T, srv *httptest.Server, current, exe string, c *commands) Updater {
	return Updater{Client: srv.Client(), BaseURL: srv.URL, Current: current, Arch: "amd64", Executable: exe, Run: c.run, Out: io.Discard, Provenance: testVerifier(t)}
}

// installed reports the commands that install or restart something, as opposed to the queries
// that find how the sensor was installed.
func (c *commands) installing() []string {
	var out []string
	for _, r := range c.ran {
		if !strings.HasPrefix(r, "dpkg -S ") && !strings.HasPrefix(r, "rpm -qf ") {
			out = append(out, r)
		}
	}
	return out
}

func TestUpdateInstallsThePackageOfTheSameKind(t *testing.T) {
	srv := fakeRelease{}.signed(t).server(t)
	for _, tc := range []struct {
		owner, want, install string
	}{
		{"dpkg", "contents of tripwatch-sensor_1.2.3_amd64.deb", "dpkg -i"},
		{"rpm", "contents of tripwatch-sensor-1.2.3-1.x86_64.rpm", "rpm -U"},
	} {
		c := &commands{owner: tc.owner}
		got, err := newUpdater(t, srv, "0.1.3", "/usr/bin/tripwatch-sensor", c).Update(t.Context())
		if err != nil {
			t.Fatalf("%s: %v", tc.owner, err)
		}
		if got != release || string(c.installed) != tc.want {
			t.Fatalf("%s: got %s with %q installed, want %s with %q", tc.owner, got, c.installed, release, tc.want)
		}
		if last := c.ran[len(c.ran)-1]; !strings.HasPrefix(last, tc.install+" ") {
			t.Fatalf("%s: last command %q, want %s", tc.owner, last, tc.install)
		}
	}
}

func TestUpdateReplacesAHandInstalledBinary(t *testing.T) {
	srv := fakeRelease{}.signed(t).server(t)
	exe := filepath.Join(t.TempDir(), "tripwatch-sensor")
	if err := os.WriteFile(exe, []byte("old binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &commands{}
	if _, err := newUpdater(t, srv, "dev", exe, c).Update(t.Context()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(exe) //nolint:gosec // test file
	fi, _ := os.Stat(exe)
	if string(b) != "contents of tripwatch-sensor_1.2.3_linux_amd64" || fi.Mode().Perm() != 0o755 {
		t.Fatalf("binary %q mode %v, want the new one executable", b, fi.Mode().Perm())
	}
	if last := c.ran[len(c.ran)-1]; last != "systemctl try-restart tripwatch-sensor" {
		t.Fatalf("last command %q, want a restart of the service", last)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), ".tripwatch-sensor-*")); len(left) != 0 {
		t.Fatalf("temporary files left behind: %v", left)
	}
}

// Every way a release can fail its provenance is a refusal, and nothing gets installed.
func TestUpdateRefusesWhatProvenanceDoesNotVouchFor(t *testing.T) {
	tampered := map[string][]byte{}
	for name, data := range releaseFiles {
		tampered[name] = data
	}
	tampered["tripwatch-sensor_1.2.3_amd64.deb"] = []byte("tampered")
	for name, f := range map[string]fakeRelease{
		"file not the attested one":  {files: tampered},
		"no bundle":                  {status: http.StatusNotFound},
		"bundle that does not chain": {provenance: fixture(t, "rekor-proof.jsonl")},
		"bundle of another version":  {latest: "1.2.4", provenance: fixture(t, "valid.jsonl")},
		"two bundles":                {provenance: append(fixture(t, "valid.jsonl"), fixture(t, "valid.jsonl")...)},
		"bundle over the size limit": {provenance: bytes.Repeat([]byte("{"), provenance.MaxBundleSize+1)},
	} {
		srv := f.signed(t).server(t)
		c := &commands{owner: "dpkg"}
		_, err := newUpdater(t, srv, "0.1.3", "/usr/bin/tripwatch-sensor", c).Update(t.Context())
		assertRefused(t, name, err, c)
	}

	// The release attests no static arm64 binary.
	srv := fakeRelease{}.signed(t).server(t)
	c := &commands{}
	u := newUpdater(t, srv, "0.1.3", "/usr/bin/tripwatch-sensor", c)
	u.Arch = "arm64"
	_, err := u.Update(t.Context())
	assertRefused(t, "file the bundle omits", err, c)
}

func assertRefused(t *testing.T, name string, err error, c *commands) {
	t.Helper()
	var refused *RejectedError
	if !errors.As(err, &refused) {
		t.Errorf("%s: got %v, want a refusal", name, err)
	}
	if ran := c.installing(); len(ran) != 0 || c.installed != nil {
		t.Errorf("%s: ran %v", name, ran)
	}
}

// A server that cannot be reached, or fails, is not evidence against the release: the error is
// not a refusal, so the sensor tries again later without raising an alert.
func TestUpdateFailuresToReachTheReleaseAreNotRefusals(t *testing.T) {
	srv := fakeRelease{status: http.StatusBadGateway}.signed(t).server(t)
	c := &commands{owner: "dpkg"}
	_, err := newUpdater(t, srv, "0.1.3", "/usr/bin/tripwatch-sensor", c).Update(t.Context())
	var refused *RejectedError
	if err == nil || errors.As(err, &refused) || len(c.installing()) != 0 {
		t.Fatalf("502: got %v, ran %v", err, c.installing())
	}
	down := fakeRelease{}.signed(t).server(t)
	u := newUpdater(t, down, "0.1.3", "/usr/bin/tripwatch-sensor", c)
	down.Close()
	if _, err := u.UpdateTo(t.Context(), release, map[string]string{}); err == nil || errors.As(err, &refused) {
		t.Fatalf("unreachable: got %v", err)
	}
}

func TestUpdateKeepsACurrentOrNewerVersion(t *testing.T) {
	srv := fakeRelease{latest: "0.10.0"}.server(t)
	for _, current := range []string{"0.10.0", "0.10.1", "1.0.0"} {
		c := &commands{owner: "dpkg"}
		var out bytes.Buffer
		u := newUpdater(t, srv, current, "/usr/bin/tripwatch-sensor", c)
		u.Out = &out
		got, err := u.Update(t.Context())
		if err != nil || got != current || len(c.ran) != 0 {
			t.Fatalf("current %s: got %s, %v, ran %v; want nothing done", current, got, err, c.ran)
		}
		if !strings.Contains(out.String(), "up to date") {
			t.Fatalf("current %s: output %q", current, out.String())
		}
	}
	// 0.9.0 against 0.10.0 compares numerically, not as text.
	if !newer("0.10.0", "0.9.0") {
		t.Fatal("0.10.0 not seen as newer than 0.9.0")
	}
}

func TestLatestRejectsAnUnexpectedAnswer(t *testing.T) {
	for _, location := range []string{"", "/releases/tag/v1.2", "/releases/tag/v1.2.3;rm", "/login"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if location != "" {
				w.Header().Set("Location", location)
				w.WriteHeader(http.StatusFound)
			}
		}))
		u := Updater{Client: srv.Client(), BaseURL: srv.URL}
		if v, err := u.Latest(t.Context()); err == nil {
			t.Errorf("location %q: accepted version %q", location, v)
		}
		srv.Close()
	}
}

func TestAssetNameRejectsUnbuiltArchitectures(t *testing.T) {
	if _, err := AssetName(Deb, "0.2.0", "386"); err == nil {
		t.Fatal("asset name for 386")
	}
	if got, _ := AssetName(RPM, "0.2.0", "arm64"); got != "tripwatch-sensor-0.2.0-1.aarch64.rpm" {
		t.Fatalf("arm64 rpm named %s", got)
	}
}

// An ordered update installs only the attested file, and only when the order's hash is the
// attested one: an order signed by the verifier's CA cannot install anything else.
func TestUpdateToNeedsTheOrderedHashToBeTheAttestedOne(t *testing.T) {
	srv := fakeRelease{}.signed(t).server(t)
	name := "tripwatch-sensor_1.2.3_amd64.deb"
	h := sha256.Sum256(releaseFiles[name])
	attested := hex.EncodeToString(h[:])
	other := sha256.Sum256([]byte("another build"))

	for desc, sums := range map[string]map[string]string{
		"another hash":       {name: hex.EncodeToString(other[:])},
		"no hash for a file": {"tripwatch-sensor-1.2.3-1.x86_64.rpm": attested},
	} {
		c := &commands{owner: "dpkg"}
		_, err := newUpdater(t, srv, "0.1.3", "/usr/bin/tripwatch-sensor", c).UpdateTo(t.Context(), release, sums)
		assertRefused(t, desc, err, c)
	}

	c := &commands{owner: "dpkg"}
	got, err := newUpdater(t, srv, "0.1.3", "/usr/bin/tripwatch-sensor", c).UpdateTo(t.Context(), release, map[string]string{name: strings.ToUpper(attested)})
	if err != nil || got != release || string(c.installed) != "contents of "+name {
		t.Fatalf("ordered update: %q installed, %v", c.installed, err)
	}
	c = &commands{owner: "dpkg"}
	if got, err := newUpdater(t, srv, release, "/usr/bin/tripwatch-sensor", c).UpdateTo(t.Context(), release, map[string]string{name: attested}); err != nil || got != release || c.installed != nil {
		t.Fatalf("an order for the running version installed again: %v", err)
	}
}
