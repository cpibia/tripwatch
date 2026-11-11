// Package provenance verifies, offline, that a release file was built by tripwatch's release
// workflow: the Sigstore bundle of the build provenance attestation GitHub makes for every
// release must chain to Sigstore's public-good roots embedded in the binary, name the workflow
// of this repository at the tag of the version being installed, and list the file's digest.
//
// The bundle comes from where releases are published, so everything in it is read as input
// from an attacker to a process running as root: one bundle of one known version, bounded in
// every field, with one certificate and one transparency log entry, and nothing else. Nothing
// here opens a network connection: the log entry carries its own proofs.
//
// It implements the subset of Sigstore verification that those bundles use (a Fulcio
// certificate, a DSSE envelope with an in-toto statement, a Rekor v1 dsse entry with its signed
// entry timestamp and an inclusion proof up to a signed checkpoint) rather than linking
// sigstore-go, which would double the sensor's size and bring network clients along. A
// differential test in the nested reference module checks every fixture against sigstore-go.
// The certificate's SCTs are not checked: forging a certificate the log accepted would need
// Fulcio's key and Rekor's key together.
package provenance

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"sync"
)

// The release workflow's identity. They are constants on purpose: no flag, environment variable
// or configuration file can widen what a sensor installs.
const (
	Issuer       = "https://token.actions.githubusercontent.com"
	Repository   = "https://github.com/cpibia/tripwatch"
	RepositoryID = "1430683523"
	OwnerID      = "172173051"
	Workflow     = ".github/workflows/release.yml"
	Trigger      = "push"
	Runner       = "github-hosted"

	StatementType = "https://in-toto.io/Statement/v1"
	PredicateType = "https://slsa.dev/provenance/v1"
	PayloadType   = "application/vnd.in-toto+json"
)

// MaxBundleSize bounds the bundle file read from a release.
const MaxBundleSize = 1 << 20

// ErrRejected wraps every reason a bundle is refused, as opposed to a failure to fetch it.
var ErrRejected = errors.New("release provenance rejected")

var releaseVersion = regexp.MustCompile(`^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`)

// Digest is the SHA-256 of a release file.
type Digest [sha256.Size]byte

// Subjects are the files a verified attestation lists, by name.
type Subjects map[string]Digest

//go:embed trusted_root.json
var embeddedRoot []byte

// Verifier checks bundles against one trust root.
type Verifier struct {
	root *trustRoot
}

var defaultVerifier = sync.OnceValues(func() (*Verifier, error) { return NewVerifier(embeddedRoot) })

// Default is the verifier for Sigstore's public-good instance, from the trust root embedded at
// build time.
func Default() (*Verifier, error) { return defaultVerifier() }

// NewVerifier parses a trusted_root.json; tests use one of their own.
func NewVerifier(trustedRoot []byte) (*Verifier, error) {
	r, err := parseTrustRoot(trustedRoot)
	if err != nil {
		return nil, fmt.Errorf("trusted root: %w", err)
	}
	return &Verifier{root: r}, nil
}

// SubjectAlternativeName is the only identity a release built for version can carry.
func SubjectAlternativeName(version string) string {
	return Repository + "/" + Workflow + "@refs/tags/v" + version
}

// Verify checks a bundle file, as the release publishes it (JSON Lines holding exactly one
// bundle), for the given release version, and returns the files it attests. Every error wraps
// ErrRejected.
func (v *Verifier) Verify(file []byte, version string) (Subjects, error) {
	s, err := v.verify(file, version)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRejected, err)
	}
	return s, nil
}

func (v *Verifier) verify(file []byte, version string) (Subjects, error) {
	if !releaseVersion.MatchString(version) {
		return nil, fmt.Errorf("%q is not a release version", version)
	}
	b, err := parseBundleFile(file)
	if err != nil {
		return nil, err
	}
	at, err := v.root.verifyEntry(b)
	if err != nil {
		return nil, err
	}
	leaf, err := v.root.verifyCertificate(b.cert, at)
	if err != nil {
		return nil, err
	}
	if err := checkIdentity(b.cert, version); err != nil {
		return nil, err
	}
	if err := verifyEnvelope(b, leaf); err != nil {
		return nil, err
	}
	return parseStatement(b.payload)
}
