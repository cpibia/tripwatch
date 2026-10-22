// Package pki runs the verifier's private certificate authority: the server certificate the
// sensors connect to, and one client certificate per enrolled host.
package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	caValidity     = 10 * 365 * 24 * time.Hour
	certValidity   = 2 * 365 * 24 * time.Hour
	caCertFile     = "ca.crt"
	caKeyFile      = "ca.key"
	serverCertFile = "server.crt"
	serverKeyFile  = "server.key"
)

// CA is the verifier's certificate authority.
type CA struct {
	Cert *x509.Certificate
	PEM  []byte
	key  ed25519.PrivateKey
}

// LoadOrCreate loads the CA kept in dir, creating it on first use. The key file is readable by
// its owner only.
func LoadOrCreate(dir string, now time.Time) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, caCertFile)) //nolint:gosec // the data directory is the operator's configuration
	if errors.Is(err, os.ErrNotExist) {
		return create(dir, now)
	}
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, caKeyFile)) //nolint:gosec // see above
	if err != nil {
		return nil, err
	}
	cert, key, err := parsePair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, PEM: certPEM, key: key}, nil
}

func create(dir string, now time.Time) (*CA, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "tripwatch verifier CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certPEM, keyPEM, err := encode(der, key)
	if err != nil {
		return nil, err
	}
	if err := writeFiles(dir, caCertFile, certPEM, caKeyFile, keyPEM); err != nil {
		return nil, err
	}
	return &CA{Cert: cert, PEM: certPEM, key: key}, nil
}

// ServerCertificate returns the certificate the ingest endpoint presents, issued for names
// (host names or IP addresses). It is reissued when the names change or expiry is near.
func (ca *CA) ServerCertificate(dir string, names []string, now time.Time) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, serverCertFile)) //nolint:gosec // the data directory is the operator's configuration
	if err == nil {
		keyPEM, err := os.ReadFile(filepath.Join(dir, serverKeyFile)) //nolint:gosec // see above
		if err == nil {
			if cert, _, err := parsePair(certPEM, keyPEM); err == nil && sameNames(cert, names) && now.Add(30*24*time.Hour).Before(cert.NotAfter) {
				return tls.X509KeyPair(certPEM, keyPEM)
			}
		}
	}
	certPEM, keyPEM, err := ca.issue(names[0], names, x509.ExtKeyUsageServerAuth, now)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := writeFiles(dir, serverCertFile, certPEM, serverKeyFile, keyPEM); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func sameNames(cert *x509.Certificate, names []string) bool {
	have := slices.Clone(cert.DNSNames)
	for _, ip := range cert.IPAddresses {
		have = append(have, ip.String())
	}
	want := slices.Clone(names)
	slices.Sort(have)
	slices.Sort(want)
	return slices.Equal(have, want)
}

// Bundle is everything a sensor needs to report to this verifier. It holds private keys and is
// meant to be copied once to the host, readable by root only.
type Bundle struct {
	HostID      string `json:"host_id"`
	VerifierURL string `json:"verifier_url"`
	CA          string `json:"ca"`
	Cert        string `json:"cert"`
	Key         string `json:"key"`
	// SigningKey is the Ed25519 seed the sensor signs envelopes with.
	SigningKey string `json:"signing_key"`
}

// Enroll issues the client certificate and the signing key of a host. The caller registers the
// returned public key with the store.
func (ca *CA) Enroll(hostID, verifierURL string, now time.Time) (Bundle, ed25519.PublicKey, error) {
	certPEM, keyPEM, err := ca.issue(hostID, nil, x509.ExtKeyUsageClientAuth, now)
	if err != nil {
		return Bundle{}, nil, err
	}
	signPub, signKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Bundle{}, nil, err
	}
	return Bundle{
		HostID: hostID, VerifierURL: verifierURL, CA: string(ca.PEM), Cert: string(certPEM), Key: string(keyPEM),
		SigningKey: base64.StdEncoding.EncodeToString(signKey.Seed()),
	}, signPub, nil
}

func (ca *CA) issue(cn string, names []string, usage x509.ExtKeyUsage, now time.Time) ([]byte, []byte, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(certValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.key)
	if err != nil {
		return nil, nil, err
	}
	return encode(der, key)
}

// Pool returns the CA as a certificate pool, to verify sensors' client certificates.
func (ca *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pool
}

// LoadBundle reads a bundle file and returns its signing key. The bundle speaks for the host: a
// copy readable by another user (the web server's, typically) would let that user sign as the
// sensor without root, so the file must belong to the sensor's user and be private to it.
func LoadBundle(path string) (Bundle, ed25519.PrivateKey, error) {
	f, err := os.Open(path) //nolint:gosec // the bundle path is the operator's configuration
	if err != nil {
		return Bundle{}, nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return Bundle{}, nil, err
	}
	if err := checkPrivate(info); err != nil {
		return Bundle{}, nil, fmt.Errorf("bundle %s: %w", path, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return Bundle{}, nil, err
	}
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return Bundle{}, nil, fmt.Errorf("bundle %s: %w", path, err)
	}
	if !strings.HasPrefix(b.VerifierURL, "https://") {
		return Bundle{}, nil, fmt.Errorf("bundle %s: verifier URL %q is not https", path, b.VerifierURL)
	}
	key, err := b.SigningPrivateKey()
	if err != nil {
		return Bundle{}, nil, fmt.Errorf("bundle %s: %w", path, err)
	}
	return b, key, nil
}

// SigningPrivateKey decodes the key the sensor signs envelopes with.
func (b Bundle) SigningPrivateKey() (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(b.SigningKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid signing key")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ClientTLS is the TLS configuration a sensor uses to reach the verifier with its bundle.
func (b Bundle) ClientTLS() (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(b.Cert), []byte(b.Key))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(b.CA)) {
		return nil, errors.New("bundle: invalid CA")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13}, nil
}

func encode(der []byte, key ed25519.PrivateKey) ([]byte, []byte, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func parsePair(certPEM, keyPEM []byte) (*x509.Certificate, ed25519.PrivateKey, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, errors.New("pki: invalid PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, errors.New("pki: not an Ed25519 key")
	}
	return cert, key, nil
}

// writeFiles writes the key, then the certificate, each atomically: a crash leaves either the
// old pair or a new key next to the old certificate, which fails to load instead of half a file.
func writeFiles(dir, certName string, certPEM []byte, keyName string, keyPEM []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := WriteFileAtomic(filepath.Join(dir, keyName), keyPEM); err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(dir, certName), certPEM)
}

// WriteFileAtomic writes data readable by its owner only, durably, replacing path in one step.
func WriteFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// SyncDir makes a rename inside dir durable: without it a crash can bring back the old name.
func SyncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // a directory the caller just wrote to
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}
