// Package reference holds what checks the provenance verifier against sigstore-go, kept out of
// the main module so the sensor never links it: the differential test, the generator of the
// synthetic fixtures and the fetcher of the trust root.
package reference

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/cpibia/tripwatch/internal/provenance"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const testdata = "../testdata"

type fixture struct {
	Name      string `json:"name"`
	File      string `json:"file"`
	Root      string `json:"root"`
	Version   string `json:"version"`
	Asset     string `json:"asset"`
	Digest    string `json:"digest"`
	Want      string `json:"want"`
	Reference string `json:"reference"`
	Why       string `json:"why"`
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network during verification")
}

// TestVerifiersAgree runs every fixture through both verifiers: sigstore-go, configured with the
// same policy, must reach the same outcome, except where the manifest records that it is laxer.
func TestVerifiersAgree(t *testing.T) {
	http.DefaultTransport = failingTransport{}
	var fixtures []fixture
	readJSON(t, filepath.Join(testdata, "manifest.json"), &fixtures)
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			rootPath := filepath.Join(testdata, f.Root)
			if f.Root == "public-good" {
				rootPath = filepath.Join(testdata, "..", "trusted_root.json")
			}
			rootJSON := readFile(t, rootPath)
			file := readFile(t, filepath.Join(testdata, f.File))

			ours, err := provenance.NewVerifier(rootJSON)
			if err != nil {
				t.Fatal(err)
			}
			subjects, oursErr := ours.Verify(file, f.Version)
			if oursErr == nil && hex.EncodeToString(digest(subjects, f.Asset)) != f.Digest {
				oursErr = errors.New("asset digest not attested")
			}
			refErr := referenceVerify(rootJSON, file, f)

			if got := outcome(oursErr); got != f.Want {
				t.Errorf("provenance: %s, want %s (%v)", got, f.Want, oursErr)
			}
			wantRef := f.Want
			if f.Reference != "" {
				wantRef = f.Reference
			}
			if got := outcome(refErr); got != wantRef {
				t.Errorf("sigstore-go: %s, want %s (%v)", got, wantRef, refErr)
			}
		})
	}
}

func referenceVerify(rootJSON, file []byte, f fixture) error {
	tr, err := root.NewTrustedRootFromJSON(rootJSON)
	if err != nil {
		return err
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(file); err != nil {
		return err
	}
	v, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return err
	}
	san := provenance.SubjectAlternativeName(f.Version)
	sanMatcher, err := verify.NewSANMatcher(san, "")
	if err != nil {
		return err
	}
	issuer, err := verify.NewIssuerMatcher(provenance.Issuer, "")
	if err != nil {
		return err
	}
	identity, err := verify.NewCertificateIdentity(sanMatcher, issuer, certificate.Extensions{
		BuildSignerURI:                  san,
		RunnerEnvironment:               provenance.Runner,
		SourceRepositoryURI:             provenance.Repository,
		SourceRepositoryRef:             "refs/tags/v" + f.Version,
		SourceRepositoryIdentifier:      provenance.RepositoryID,
		SourceRepositoryOwnerIdentifier: provenance.OwnerID,
		BuildConfigURI:                  san,
		BuildTrigger:                    provenance.Trigger,
	})
	if err != nil {
		return err
	}
	d, err := hex.DecodeString(f.Digest)
	if err != nil {
		return err
	}
	res, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest("sha256", d), verify.WithCertificateIdentity(identity)))
	if err != nil {
		return err
	}
	if res.Statement == nil || res.Statement.GetType() != provenance.StatementType || res.Statement.GetPredicateType() != provenance.PredicateType {
		return errors.New("not an in-toto statement of SLSA provenance v1")
	}
	return nil
}

func digest(s provenance.Subjects, name string) []byte {
	d, ok := s[name]
	if !ok {
		return nil
	}
	return d[:]
}

func outcome(err error) string {
	if err != nil {
		return "reject"
	}
	return "accept"
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // fixtures of this repository
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := json.Unmarshal(readFile(t, path), v); err != nil {
		t.Fatal(err)
	}
}
