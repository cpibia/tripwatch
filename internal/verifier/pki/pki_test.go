package pki

import (
	"crypto/ed25519"
	"crypto/tls"
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

func TestCALifecycle(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	ca, err := LoadOrCreate(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreate(dir, now)
	if err != nil || again.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("the CA is not reloaded: %v", err)
	}
	if info, _ := os.Stat(filepath.Join(dir, "ca.key")); info.Mode().Perm() != 0o600 {
		t.Errorf("CA key mode %v", info.Mode().Perm())
	}

	first, err := ca.ServerCertificate(dir, []string{"verifier.example.net"}, now)
	if err != nil || len(first.Certificate) != 2 {
		t.Fatalf("server certificate: %v, chain %d", err, len(first.Certificate))
	}
	same, _ := ca.ServerCertificate(dir, []string{"verifier.example.net"}, now)
	renamed, _ := ca.ServerCertificate(dir, []string{"other.example.net", "10.0.0.1"}, now)
	if string(same.Certificate[0]) != string(first.Certificate[0]) || string(renamed.Certificate[0]) == string(first.Certificate[0]) {
		t.Error("the server certificate is not reused for the same names, or reused for new ones")
	}

	b, pub, err := ca.Enroll("web-01", "https://verifier.example.net:8443/v1/envelopes", now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := b.SigningPrivateKey()
	if err != nil || !pub.Equal(key.Public()) {
		t.Fatalf("signing key: %v", err)
	}
	if serial, err := Serial([]byte(b.Cert)); err != nil || serial == "" {
		t.Fatalf("serial: %q %v", serial, err)
	}
	if _, err := Serial([]byte("not pem")); err == nil {
		t.Error("serial of garbage")
	}
	if _, err := (Bundle{SigningKey: "bad"}).SigningPrivateKey(); err == nil {
		t.Error("bad signing key accepted")
	}
}

func TestEnrollTokenParsing(t *testing.T) {
	tok := EnrollToken{URL: "https://v.example.net:8443/v1/envelopes", Secret: "s", CA: "f"}
	if got, err := ParseEnrollToken(" " + tok.String() + "\n"); err != nil || got != tok {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for _, bad := range []string{"", "tw1.!!!", "xx." + tok.String()[4:],
		EnrollToken{URL: "http://v/x", Secret: "s", CA: "f"}.String(), EnrollToken{URL: "https://v/x", CA: "f"}.String()} {
		if _, err := ParseEnrollToken(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestWriteFileAtomic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	for _, content := range []string{"one", "two"} {
		if err := WriteFileAtomic(p, []byte(content)); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(p); string(got) != content {
			t.Fatalf("content %q", got)
		}
	}
	if info, _ := os.Stat(p); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Errorf("temporary files left: %d entries", len(entries))
	}
}

func TestIdentityPrefersLongerRenewedCertificate(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	ca, _ := LoadOrCreate(t.TempDir(), now)
	b, _, _ := ca.Enroll("web-01", "https://v.example.net/v1/envelopes", now)
	state := t.TempDir()
	id, err := b.ClientIdentity(state)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(nil)
	certPEM, _ := ca.IssueClient("web-01", pub, now.Add(24*time.Hour))
	keyPEM, _ := EncodeKey(key)
	if err := id.Replace(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	reloaded, _ := b.ClientIdentity(state)
	if !reloaded.NotAfter().Equal(id.NotAfter()) || !id.NotAfter().After(now.Add(certValidity)) {
		t.Fatal("renewed certificate not preferred after a restart")
	}
	other, _ := ca.IssueClient("web-02", pub, now)
	if err := id.Replace(other, keyPEM); err == nil {
		t.Fatal("a certificate for another host replaced the identity")
	}
	if cfg := id.TLS(); cfg.GetClientCertificate == nil || cfg.MinVersion != tls.VersionTLS13 {
		t.Fatal("client TLS configuration")
	}
}
