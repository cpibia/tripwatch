// Package pki runs the verifier's private certificate authority: the server certificate the
// sensors connect to, and one client certificate per enrolled host.
package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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
	"sync"
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
				return ca.withChain(certPEM, keyPEM)
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
	return ca.withChain(certPEM, keyPEM)
}

// withChain sends the CA certificate after the server's own: a sensor enrolling with a token
// knows only the CA's fingerprint, and checks it against the chain before sending anything.
func (ca *CA) withChain(certPEM, keyPEM []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return cert, err
	}
	cert.Certificate = append(cert.Certificate, ca.Cert.Raw)
	return cert, nil
}

// Fingerprint identifies the CA in enrollment tokens: the SHA-256 of its certificate.
func (ca *CA) Fingerprint() string {
	sum := sha256.Sum256(ca.Cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// IssueClient issues a client certificate for a key the host generated itself, so that its
// private key never leaves it.
func (ca *CA) IssueClient(hostID string, pub ed25519.PublicKey, now time.Time) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: hostID},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(certValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
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

// RenewWindow is how long before expiry a client certificate may be renewed.
const RenewWindow = 90 * 24 * time.Hour

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

// EncodeKey writes a private key as PKCS#8 PEM, the form bundles carry.
func EncodeKey(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
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

// renewedFile keeps, in the sensor's state directory, the client certificate obtained by
// renewal: the bundle itself stays read-only.
const renewedFile = "client-cert.json"

// Identity is the TLS client certificate a sensor presents, which renewal can replace while
// the sensor runs.
type Identity struct {
	mu       sync.Mutex
	cert     tls.Certificate
	leaf     *x509.Certificate
	hostID   string
	pool     *x509.CertPool
	stateDir string
}

// ClientIdentity returns the bundle's client certificate, or the renewed one kept in stateDir
// when it is valid for this host and lasts longer.
func (b Bundle) ClientIdentity(stateDir string) (*Identity, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(b.CA)) {
		return nil, errors.New("bundle: invalid CA")
	}
	id := &Identity{hostID: b.HostID, pool: pool, stateDir: stateDir}
	if err := id.set([]byte(b.Cert), []byte(b.Key)); err != nil {
		return nil, err
	}
	if stateDir != "" {
		if data, err := os.ReadFile(filepath.Join(stateDir, renewedFile)); err == nil { //nolint:gosec // the state directory is the operator's configuration
			var r struct{ Cert, Key string }
			if json.Unmarshal(data, &r) == nil {
				previous := id.cert
				previousLeaf := id.leaf
				if err := id.set([]byte(r.Cert), []byte(r.Key)); err != nil || id.leaf.NotAfter.Before(previousLeaf.NotAfter) {
					id.cert, id.leaf = previous, previousLeaf
				}
			}
		}
	}
	return id, nil
}

// set installs a certificate after checking it is a client certificate of this host signed by
// the verifier's CA.
func (id *Identity) set(certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	if leaf.Subject.CommonName != id.hostID {
		return fmt.Errorf("certificate for %q, not %q", leaf.Subject.CommonName, id.hostID)
	}
	// The chain and the usage are checked here; the validity window is checked by TLS on every
	// connection, and a sensor whose clock is off must still accept its renewed certificate.
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: id.pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: leaf.NotBefore.Add(time.Second)}); err != nil {
		return err
	}
	id.mu.Lock()
	id.cert, id.leaf = cert, leaf
	id.mu.Unlock()
	return nil
}

// NotAfter is when the current certificate expires.
func (id *Identity) NotAfter() time.Time {
	id.mu.Lock()
	defer id.mu.Unlock()
	return id.leaf.NotAfter
}

// Replace installs a renewed certificate and keeps it in the state directory.
func (id *Identity) Replace(certPEM, keyPEM []byte) error {
	if err := id.set(certPEM, keyPEM); err != nil {
		return err
	}
	if id.stateDir == "" {
		return nil
	}
	data, err := json.Marshal(map[string]string{"Cert": string(certPEM), "Key": string(keyPEM)})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(id.stateDir, 0o700); err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(id.stateDir, renewedFile), data)
}

// TLS is the client configuration presenting the current certificate on every connection.
func (id *Identity) TLS() *tls.Config {
	return &tls.Config{
		RootCAs:    id.pool,
		MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			id.mu.Lock()
			defer id.mu.Unlock()
			c := id.cert
			return &c, nil
		},
	}
}

// EnrollToken is what an operator copies to a new host: where the verifier is, the one-time
// secret, and the fingerprint of the CA the sensor must find in the verifier's chain before it
// sends the secret.
type EnrollToken struct {
	URL    string `json:"u"`
	Secret string `json:"s"`
	CA     string `json:"f"`
}

const tokenPrefix = "tw1."

func (t EnrollToken) String() string {
	data, _ := json.Marshal(t) //nolint:gosec // the token is the secret's intended carrier
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(data)
}

// ParseEnrollToken reads a token as printed by String.
func ParseEnrollToken(s string) (EnrollToken, error) {
	var t EnrollToken
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), tokenPrefix))
	if err != nil || !strings.HasPrefix(strings.TrimSpace(s), tokenPrefix) {
		return t, errors.New("not an enrollment token")
	}
	if err := json.Unmarshal(raw, &t); err != nil || t.Secret == "" || t.CA == "" || !strings.HasPrefix(t.URL, "https://") {
		return t, errors.New("malformed enrollment token")
	}
	return t, nil
}

// PinnedTLS trusts exactly the CA whose fingerprint the token carries: the chain the verifier
// presents must end in that CA and its leaf must be valid for the verifier's name.
func (t EnrollToken) PinnedTLS(serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection, which pins the CA from the token
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) < 2 {
				return errors.New("verifier did not present its CA")
			}
			ca := cs.PeerCertificates[len(cs.PeerCertificates)-1]
			sum := sha256.Sum256(ca.Raw)
			if base64.RawURLEncoding.EncodeToString(sum[:]) != t.CA {
				return errors.New("verifier CA does not match the token")
			}
			pool := x509.NewCertPool()
			pool.AddCert(ca)
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, DNSName: serverName})
			return err
		},
	}
}

// Serial returns the serial number of a PEM certificate, as recorded for its host.
func Serial(certPEM []byte) (string, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return "", errors.New("pki: invalid PEM")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return "", err
	}
	return c.SerialNumber.Text(16), nil
}
