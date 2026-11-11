package provenance

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are written by the generator in the reference module, which also checks each one
// against sigstore-go.
type fixture struct {
	Name    string `json:"name"`
	File    string `json:"file"`
	Root    string `json:"root"`
	Version string `json:"version"`
	Asset   string `json:"asset"`
	Digest  string `json:"digest"`
	Want    string `json:"want"`
}

// rejectedFor is the reason each rejected fixture must be refused for: a fixture refused for
// another reason would test nothing.
var rejectedFor = map[string]string{
	"chain-unknown-ca":            "signed by unknown authority",
	"chain-expired":               "expired or is not yet valid",
	"chain-no-code-signing":       "not for code signing",
	"chain-ca-window":             "no certificate authority valid at the integrated time",
	"identity-other-workflow":     "workflows/other.yml",
	"identity-issuer":             "57264.1.8 is",
	"identity-repository":         "57264.1.12 is",
	"identity-ref":                "57264.1.14 is",
	"identity-repository-id":      "57264.1.15 is",
	"identity-owner-id":           "57264.1.17 is",
	"identity-trigger":            "57264.1.20 is",
	"identity-runner":             "57264.1.11 is",
	"identity-two-uris":           "exactly one URI identity",
	"identity-email":              "exactly one URI identity",
	"identity-raw-issuer":         "57264.1.1 is",
	"identity-printable-string":   "not a DER UTF8String",
	"dsse-signature":              "envelope signature does not verify",
	"dsse-payload-type":           "payload type",
	"statement-type":              "statement type",
	"predicate-type":              "predicate type",
	"statement-duplicate-subject": "listed twice",
	"rekor-unknown-log":           "log the trust root does not know",
	"rekor-log-window":            "log key not valid at the integrated time",
	"rekor-set":                   "signed entry timestamp does not verify",
	"rekor-proof":                 "inclusion proof",
	"rekor-checkpoint-signature":  "checkpoint: signature does not verify",
	"rekor-checkpoint-root":       "checkpoint is not the tree",
	"rekor-checkpoint-size":       "checkpoint is not the tree",
	"rekor-checkpoint-origin":     "checkpoint: origin",
	"binding-payload":             "another payload",
	"binding-signature":           "another signature",
	"binding-certificate":         "another certificate",
	"other-version":               "refs/tags/v1.2.4",
	"other-digest":                "",
}

type noNetwork struct{ t *testing.T }

func (n noNetwork) RoundTrip(r *http.Request) (*http.Response, error) {
	n.t.Errorf("network used: %s", r.URL)
	return nil, errors.New("no network")
}

func TestFixtures(t *testing.T) {
	saved := http.DefaultTransport
	http.DefaultTransport = noNetwork{t}
	t.Cleanup(func() { http.DefaultTransport = saved })

	var fixtures []fixture
	if err := json.Unmarshal(read(t, "testdata/manifest.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) < len(rejectedFor) {
		t.Fatalf("manifest lists %d fixtures", len(fixtures))
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			v := verifierFor(t, f.Root)
			subjects, err := v.Verify(read(t, filepath.Join("testdata", f.File)), f.Version)
			if err == nil {
				d, ok := subjects[f.Asset]
				if !ok || hex.EncodeToString(d[:]) != f.Digest {
					err = errors.New("asset not attested")
				}
			}
			if f.Want == "accept" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			reason, ok := rejectedFor[f.Name]
			if !ok {
				t.Fatalf("no expected reason for %s", f.Name)
			}
			if err == nil || !strings.Contains(err.Error(), reason) {
				t.Fatalf("got %v, want a rejection for %q", err, reason)
			}
		})
	}
}

func TestDefaultTrustsTheEmbeddedRoot(t *testing.T) {
	v, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.root.logs) == 0 || len(v.root.cas) == 0 {
		t.Fatal("embedded root without a log or an authority")
	}
}

func TestRejectionsWrapErrRejected(t *testing.T) {
	v := verifierFor(t, "synthetic/trusted_root.json")
	for _, version := range []string{"1.2.3", "1.2", "v1.2.3", "1.2.3/../x"} {
		if _, err := v.Verify([]byte("{}"), version); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v", version, err)
		}
	}
}

// TestParserRefusesWhatReleasesDoNotCarry alters the valid bundle one field at a time, each into
// something a release's bundle never holds.
func TestParserRefusesWhatReleasesDoNotCarry(t *testing.T) {
	valid := read(t, "testdata/synthetic/valid.jsonl")
	edit := func(change func(m map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(valid, &m); err != nil {
			t.Fatal(err)
		}
		change(m)
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	vm := func(m map[string]any) map[string]any { return m["verificationMaterial"].(map[string]any) }
	entry := func(m map[string]any) map[string]any { return vm(m)["tlogEntries"].([]any)[0].(map[string]any) }
	env := func(m map[string]any) map[string]any { return m["dsseEnvelope"].(map[string]any) }

	cases := map[string][]byte{
		"empty file":            nil,
		"two bundles":           append(append(bytes.TrimSuffix(valid, []byte("\n")), '\n'), valid...),
		"data after the bundle": append(bytes.TrimSuffix(valid, []byte("\n")), []byte(" {}")...),
		"over the size limit":   append(valid, bytes.Repeat([]byte(" "), MaxBundleSize)...),
		"other bundle version":  edit(func(m map[string]any) { m["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.2+json" }),
		"unknown field":         edit(func(m map[string]any) { m["messageSignature"] = map[string]any{} }),
		"public key":            edit(func(m map[string]any) { vm(m)["publicKey"] = map[string]any{"hint": "x"} }),
		"certificate chain":     edit(func(m map[string]any) { vm(m)["x509CertificateChain"] = map[string]any{} }),
		"timestamps": edit(func(m map[string]any) {
			vm(m)["timestampVerificationData"] = map[string]any{"rfc3161Timestamps": []any{}}
		}),
		"two log entries": edit(func(m map[string]any) { vm(m)["tlogEntries"] = append(vm(m)["tlogEntries"].([]any), entry(m)) }),
		"no log entry":    edit(func(m map[string]any) { vm(m)["tlogEntries"] = []any{} }),
		"two signatures": edit(func(m map[string]any) {
			env(m)["signatures"] = append(env(m)["signatures"].([]any), env(m)["signatures"].([]any)[0])
		}),
		"signature key id":     edit(func(m map[string]any) { env(m)["signatures"].([]any)[0].(map[string]any)["keyid"] = "k" }),
		"no inclusion proof":   edit(func(m map[string]any) { delete(entry(m), "inclusionProof") }),
		"no inclusion promise": edit(func(m map[string]any) { delete(entry(m), "inclusionPromise") }),
		"hashedrekord entry": edit(func(m map[string]any) {
			entry(m)["kindVersion"] = map[string]any{"kind": "hashedrekord", "version": "0.0.1"}
		}),
		"numeric log index":     edit(func(m map[string]any) { entry(m)["logIndex"] = 4242 }),
		"negative time":         edit(func(m map[string]any) { entry(m)["integratedTime"] = "-1" }),
		"loose base64":          edit(func(m map[string]any) { env(m)["payload"] = env(m)["payload"].(string) + "\n" }),
		"oversized certificate": edit(func(m map[string]any) { vm(m)["certificate"] = map[string]any{"rawBytes": strings.Repeat("A", 12<<10)} }),
		"short root hash":       edit(func(m map[string]any) { entry(m)["inclusionProof"].(map[string]any)["rootHash"] = "AAAA" }),
		"proof index past tree": edit(func(m map[string]any) { entry(m)["inclusionProof"].(map[string]any)["logIndex"] = "9" }),
		"too many proof hashes": edit(func(m map[string]any) {
			p := entry(m)["inclusionProof"].(map[string]any)
			p["hashes"] = make([]any, 65)
		}),
		"checkpoint missing":     edit(func(m map[string]any) { entry(m)["inclusionProof"].(map[string]any)["checkpoint"] = map[string]any{} }),
		"leading zero log index": edit(func(m map[string]any) { entry(m)["logIndex"] = "04242" }),
	}
	if _, err := parseBundleFile(valid); err != nil {
		t.Fatalf("valid bundle refused: %v", err)
	}
	for name, file := range cases {
		if _, err := parseBundleFile(file); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckpointNeedsExactlyOneSignatureLine(t *testing.T) {
	v := verifierFor(t, "synthetic/trusted_root.json")
	b, err := parseBundleFile(read(t, "testdata/synthetic/valid.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	log := &v.root.logs[0]
	if _, _, err := verifyCheckpoint(log, b.checkpoint); err != nil {
		t.Fatal(err)
	}
	text, sig, _ := strings.Cut(b.checkpoint, "\n\n")
	for name, note := range map[string]string{
		"two signatures":  b.checkpoint + sig,
		"no signature":    text + "\n\n",
		"no blank line":   text + "\n" + sig,
		"other signer":    text + "\n\n" + strings.Replace(sig, log.host, "other.example.test", 1),
		"extra separator": text + "\n\n\n" + sig,
	} {
		if _, _, err := verifyCheckpoint(log, note); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// FuzzParse feeds arbitrary files to the verification and to every parser that reads the bundle
// before or without a signature over it: none may panic or run unbounded.
func FuzzParse(f *testing.F) {
	f.Add(read(f, "testdata/synthetic/valid.jsonl"))
	f.Add(read(f, "testdata/release-0.1.51.jsonl"))
	v := verifierFor(f, "synthetic/trusted_root.json")
	log := &v.root.logs[0]
	f.Fuzz(func(t *testing.T, file []byte) {
		if subjects, err := v.Verify(file, "1.2.3"); err == nil && len(subjects) == 0 {
			t.Fatal("accepted a bundle that attests no file")
		}
		b, err := parseBundleFile(file)
		if err != nil {
			return
		}
		_ = bindEntry(b)
		_ = checkIdentity(b.cert, "1.2.3")
		_, _, _ = verifyCheckpoint(log, b.checkpoint)
		if subjects, err := parseStatement(b.payload); err == nil && len(subjects) == 0 {
			t.Fatal("a statement without subjects parsed")
		}
	})
}

func verifierFor(t testing.TB, root string) *Verifier {
	t.Helper()
	path := filepath.Join("testdata", root)
	if root == "public-good" {
		path = "trusted_root.json"
	}
	v, err := NewVerifier(read(t, path))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func read(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // fixtures of this package
	if err != nil {
		t.Fatal(err)
	}
	return b
}
