package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

func TestRetentionFromEnvironment(t *testing.T) {
	if r, err := retention(); err != nil || r != store.DefaultRetention {
		t.Fatalf("defaults: %+v, %v", r, err)
	}
	t.Setenv("TRIPWATCH_KEEP_EVENTS_DAYS", "30")
	t.Setenv("TRIPWATCH_KEEP_RESOLVED_DAYS", "365")
	if r, err := retention(); err != nil || r.Events != 30*24*time.Hour || r.Resolved != 365*24*time.Hour || r.Snapshots != store.DefaultRetention.Snapshots {
		t.Fatalf("configured: %+v, %v", r, err)
	}
	for _, bad := range []string{"7d", "0", "-3", "99999999999"} {
		t.Setenv("TRIPWATCH_KEEP_EVENTS_DAYS", bad)
		if _, err := retention(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	t.Setenv("TRIPWATCH_KEEP_EVENTS_DAYS", "30")
	t.Setenv("TRIPWATCH_KEEP_RESOLVED_MINOR_DAYS", "400")
	if _, err := retention(); err == nil {
		t.Error("minor alerts kept longer than the others accepted")
	}
}

// The secrets key comes from the environment when set, otherwise from a file made once in the
// data directory, readable by its owner only.
func TestSecretsKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRIPWATCH_DATA", dir)
	t.Setenv("TRIPWATCH_SECRETS_KEY", "")
	first, err := secretsKey()
	if err != nil || len(first) != store.SecretsKeySize {
		t.Fatalf("made: %d bytes, %v", len(first), err)
	}
	info, err := os.Stat(filepath.Join(dir, "pki", "secrets.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v, %v", info, err)
	}
	if again, err := secretsKey(); err != nil || !bytes.Equal(again, first) {
		t.Fatal("the key changed at the second start")
	}
	t.Setenv("TRIPWATCH_SECRETS_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	if key, err := secretsKey(); err != nil || key[0] != 1 {
		t.Fatalf("from the environment: %v", err)
	}
	t.Setenv("TRIPWATCH_SECRETS_KEY", "c2hvcnQ=")
	if _, err := secretsKey(); err == nil {
		t.Error("a short key accepted")
	}
}
