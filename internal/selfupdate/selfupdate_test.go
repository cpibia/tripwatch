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
)

type fakeRelease struct {
	latest string
	files  map[string][]byte
	sums   string
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
		if name == "SHA256SUMS" {
			_, _ = io.WriteString(w, f.sums)
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

func sumsFor(files map[string][]byte) string {
	var b strings.Builder
	for name, data := range files {
		h := sha256.Sum256(data)
		b.WriteString(hex.EncodeToString(h[:]) + "  " + name + "\n")
	}
	return b.String()
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

func newUpdater(srv *httptest.Server, current, exe string, c *commands) Updater {
	return Updater{Client: srv.Client(), BaseURL: srv.URL, Current: current, Arch: "amd64", Executable: exe, Run: c.run, Out: io.Discard}
}

func TestUpdateInstallsThePackageOfTheSameKind(t *testing.T) {
	files := map[string][]byte{
		"tripwatch-sensor_0.2.0_amd64.deb":        []byte("deb"),
		"tripwatch-sensor-0.2.0-1.x86_64.rpm":     []byte("rpm"),
		"tripwatch-sensor_0.2.0_linux_amd64":      []byte("bin"),
		"tripwatch-sensor_0.2.0_linux_arm64":      []byte("arm"),
		"tripwatch-verifier_0.2.0_linux_amd64":    []byte("verifier"),
		"tripwatch-sensor-0.2.0-1.aarch64.rpm":    []byte("arm rpm"),
		"tripwatch-sensor_0.2.0_arm64.deb":        []byte("arm deb"),
		"docker-compose.yml":                      []byte("compose"),
		"tripwatch-sensor_0.2.0_linux_amd64.sbom": []byte("x"),
	}
	srv := fakeRelease{latest: "0.2.0", files: files, sums: sumsFor(files)}.server(t)
	for _, tc := range []struct {
		owner, want, install string
	}{
		{"dpkg", "deb", "dpkg -i"},
		{"rpm", "rpm", "rpm -U"},
	} {
		c := &commands{owner: tc.owner}
		got, err := newUpdater(srv, "0.1.3", "/usr/bin/tripwatch-sensor", c).Update(t.Context())
		if err != nil {
			t.Fatalf("%s: %v", tc.owner, err)
		}
		if got != "0.2.0" || string(c.installed) != tc.want {
			t.Fatalf("%s: got %s with %q installed, want 0.2.0 with %q", tc.owner, got, c.installed, tc.want)
		}
		if last := c.ran[len(c.ran)-1]; !strings.HasPrefix(last, tc.install+" ") {
			t.Fatalf("%s: last command %q, want %s", tc.owner, last, tc.install)
		}
	}
}

func TestUpdateReplacesAHandInstalledBinary(t *testing.T) {
	files := map[string][]byte{"tripwatch-sensor_0.2.0_linux_amd64": []byte("new binary")}
	srv := fakeRelease{latest: "0.2.0", files: files, sums: sumsFor(files)}.server(t)
	exe := filepath.Join(t.TempDir(), "tripwatch-sensor")
	if err := os.WriteFile(exe, []byte("old binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &commands{}
	if _, err := newUpdater(srv, "dev", exe, c).Update(t.Context()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(exe) //nolint:gosec // test file
	fi, _ := os.Stat(exe)
	if string(b) != "new binary" || fi.Mode().Perm() != 0o755 {
		t.Fatalf("binary %q mode %v, want the new one executable", b, fi.Mode().Perm())
	}
	if last := c.ran[len(c.ran)-1]; last != "systemctl try-restart tripwatch-sensor" {
		t.Fatalf("last command %q, want a restart of the service", last)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), ".tripwatch-sensor-*")); len(left) != 0 {
		t.Fatalf("temporary files left behind: %v", left)
	}
}

func TestUpdateRefusesAFileThatDoesNotMatchItsChecksum(t *testing.T) {
	files := map[string][]byte{"tripwatch-sensor_0.2.0_amd64.deb": []byte("genuine")}
	sums := sumsFor(files)
	files["tripwatch-sensor_0.2.0_amd64.deb"] = []byte("tampered")
	srv := fakeRelease{latest: "0.2.0", files: files, sums: sums}.server(t)
	c := &commands{owner: "dpkg"}
	_, err := newUpdater(srv, "0.1.3", "/usr/bin/tripwatch-sensor", c).Update(t.Context())
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("got %v, want a checksum mismatch", err)
	}
	if c.installed != nil {
		t.Fatal("a file failing its checksum was installed")
	}
}

func TestUpdateFailsWhenTheChecksumIsMissing(t *testing.T) {
	files := map[string][]byte{"tripwatch-sensor-0.2.0-1.x86_64.rpm": []byte("rpm")}
	srv := fakeRelease{latest: "0.2.0", files: files, sums: "zz  tripwatch-sensor-0.2.0-1.x86_64.rpm\n"}.server(t)
	if _, err := newUpdater(srv, "0.1.3", "/usr/bin/tripwatch-sensor", &commands{owner: "rpm"}).Update(t.Context()); err == nil {
		t.Fatal("a malformed checksum was accepted")
	}
	srv = fakeRelease{latest: "0.2.0", files: files, sums: ""}.server(t)
	if _, err := newUpdater(srv, "0.1.3", "/usr/bin/tripwatch-sensor", &commands{owner: "rpm"}).Update(t.Context()); err == nil {
		t.Fatal("a file absent from SHA256SUMS was accepted")
	}
}

func TestUpdateKeepsACurrentOrNewerVersion(t *testing.T) {
	srv := fakeRelease{latest: "0.10.0"}.server(t)
	for _, current := range []string{"0.10.0", "0.10.1", "1.0.0"} {
		c := &commands{owner: "dpkg"}
		var out bytes.Buffer
		u := newUpdater(srv, current, "/usr/bin/tripwatch-sensor", c)
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

// An ordered update checks the file against the hash the order carries, not against the
// release's own SHA256SUMS: a release whose file and sums were both replaced installs nothing.
func TestUpdateToChecksTheOrderedHash(t *testing.T) {
	genuine := map[string][]byte{"tripwatch-sensor_0.2.0_amd64.deb": []byte("genuine")}
	ordered := map[string]string{}
	for name, data := range genuine {
		h := sha256.Sum256(data)
		ordered[name] = hex.EncodeToString(h[:])
	}
	replaced := map[string][]byte{"tripwatch-sensor_0.2.0_amd64.deb": []byte("replaced")}
	srv := fakeRelease{latest: "0.2.0", files: replaced, sums: sumsFor(replaced)}.server(t)
	c := &commands{owner: "dpkg"}
	if _, err := newUpdater(srv, "0.1.3", "/usr/bin/tripwatch-sensor", c).UpdateTo(t.Context(), "0.2.0", ordered); err == nil || c.installed != nil {
		t.Fatalf("a file replaced in the release was installed: %v", err)
	}

	srv = fakeRelease{latest: "0.2.0", files: genuine, sums: "garbage"}.server(t)
	c = &commands{owner: "dpkg"}
	if got, err := newUpdater(srv, "0.1.3", "/usr/bin/tripwatch-sensor", c).UpdateTo(t.Context(), "0.2.0", ordered); err != nil || string(c.installed) != "genuine" || got != "0.2.0" {
		t.Fatalf("ordered update: %q installed, %v", c.installed, err)
	}
	c = &commands{owner: "dpkg"}
	if got, err := newUpdater(srv, "0.2.0", "/usr/bin/tripwatch-sensor", c).UpdateTo(t.Context(), "0.2.0", ordered); err != nil || got != "0.2.0" || c.installed != nil {
		t.Fatalf("an order for the running version installed again: %v", err)
	}
}
