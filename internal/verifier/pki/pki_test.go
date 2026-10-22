package pki

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadBundleRefusesUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	write := func(url string, mode os.FileMode) string {
		b, _, err := ca.Enroll("web-01", url, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(b)
		path := filepath.Join(t.TempDir(), "bundle.json")
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}

	if _, _, err := LoadBundle(write("https://verifier.example.net:8443/v1/envelopes", 0o600)); err != nil {
		t.Fatalf("private https bundle: %v", err)
	}
	if _, _, err := LoadBundle(write("https://verifier.example.net:8443/v1/envelopes", 0o644)); err == nil || !strings.Contains(err.Error(), "other users") {
		t.Fatalf("world-readable bundle accepted: %v", err)
	}
	if _, _, err := LoadBundle(write("http://verifier.example.net:8443/v1/envelopes", 0o600)); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("plain http bundle accepted: %v", err)
	}
}
