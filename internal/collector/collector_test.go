package collector

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type stubCollector struct {
	name   string
	result any
	err    error
}

func (s stubCollector) Name() string { return s.name }

func (s stubCollector) Collect(context.Context, Source) (any, error) { return s.result, s.err }

func TestRunIsolatesFailures(t *testing.T) {
	now := time.Date(2026, 10, 22, 2, 1, 0, 0, time.FixedZone("CEST", 2*3600))
	snap := Run(context.Background(), Source{FS: fstest.MapFS{}}, []Collector{
		stubCollector{name: "ok", result: map[string]int{"n": 1}},
		stubCollector{name: "fails", err: errors.New("boom")},
		stubCollector{name: "unencodable", result: math.Inf(1)},
		stubCollector{name: "after", result: []string{"still runs"}},
	}, now)

	if !snap.TakenAt.Equal(now) || snap.TakenAt.Location() != time.UTC {
		t.Errorf("taken at = %v, want %v in UTC", snap.TakenAt, now)
	}
	if string(snap.Results["ok"]) != `{"n":1}` || string(snap.Results["after"]) != `["still runs"]` {
		t.Errorf("results = %s", mustJSON(t, snap.Results))
	}
	if snap.Errors["fails"] != "boom" || snap.Errors["unencodable"] == "" || len(snap.Errors) != 2 {
		t.Errorf("errors = %v", snap.Errors)
	}
}

func TestDescribe(t *testing.T) {
	src := Source{
		FS: fstest.MapFS{
			"etc/hosts": {Data: []byte("127.0.0.1 localhost\n"), Mode: 0o644},
			"etc/link":  {Data: []byte("hosts"), Mode: fs.ModeSymlink},
			"etc/dir":   {Mode: fs.ModeDir | 0o755},
		},
		Attrs: func(name string) (Attrs, error) {
			if name == "etc/hosts" {
				return Attrs{Immutable: true}, nil
			}
			return Attrs{}, ErrAttrsUnsupported
		},
	}

	f, err := Describe(src, "etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	const hostsSHA256 = "081ef9d5367595d16e30b4b4549d9f43537320508b4ce0788963e10e4f808857"
	if f.Path != "/etc/hosts" || f.Size != 20 || !f.Immutable || f.SHA256 != hostsSHA256 {
		t.Errorf("file = %+v", f)
	}

	linked, err := Describe(src, "etc/link")
	if err != nil {
		t.Fatal(err)
	}
	if linked.SHA256 != f.SHA256 {
		t.Error("Describe must follow symlinks")
	}

	dir, err := Describe(src, "etc/dir")
	if err != nil || dir.SHA256 != "" || dir.Immutable {
		t.Errorf("dir = %+v, err %v", dir, err)
	}

	if _, err := Describe(src, "etc/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want not exist", err)
	}
}

func TestRel(t *testing.T) {
	tests := map[string]string{
		"/":                       ".",
		"":                        ".",
		"/root":                   "root",
		"/var/www/":               "var/www",
		"var/www":                 "var/www",
		"/home/u/../../etc/x":     "etc/x",
		"/../../../../etc/shadow": "etc/shadow",
	}
	for in, want := range tests {
		if got := Rel(in); got != want {
			t.Errorf("Rel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadLinesAndGlob(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/cron.d/a":     {Data: []byte("x\r\ny")},
		"etc/cron.d/b":     {Data: []byte("")},
		"etc/cron.d/sub/c": {Data: []byte("")},
	}

	lines, err := ReadLines(fsys, "etc/cron.d/a")
	if err != nil || len(lines) != 2 || lines[0] != "x" || lines[1] != "y" {
		t.Errorf("lines = %q, err %v", lines, err)
	}
	if lines, err := ReadLines(fsys, "etc/missing"); lines != nil || err != nil {
		t.Errorf("missing file: lines %q, err %v", lines, err)
	}
	if _, err := ReadLines(fsys, "etc/cron.d"); err == nil {
		t.Error("reading a directory must fail")
	}

	got := Glob(fsys, "etc/cron.d/*")
	if len(got) != 2 || got[0] != "etc/cron.d/a" || got[1] != "etc/cron.d/b" {
		t.Errorf("glob = %v, want files only", got)
	}
}

func TestIssuesIgnoreMissingFiles(t *testing.T) {
	var is Issues
	is.Add(nil)
	is.Add(fs.ErrNotExist)
	is.Add(&fs.PathError{Op: "open", Path: "etc/shadow", Err: fs.ErrPermission})
	if len(is) != 1 {
		t.Errorf("issues = %v, want only the permission error", is)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Results past the bound are left out largest first, each named in the errors.
func TestSnapshotBound(t *testing.T) {
	s := Snapshot{Results: map[string]json.RawMessage{
		"accounts":  json.RawMessage(strings.Repeat("a", 100)),
		"processes": json.RawMessage(strings.Repeat("p", 900)),
		"sockets":   json.RawMessage(strings.Repeat("s", 300)),
	}}
	s.Bound(500)
	if _, ok := s.Results["processes"]; ok || len(s.Results) != 2 || !strings.Contains(s.Errors["processes"], "900 bytes") {
		t.Errorf("results %v, errors %v", len(s.Results), s.Errors)
	}
}
