package provenance

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// BundleMediaType is the one bundle version GitHub's attestations are known to use: another
// version is refused rather than guessed at.
const BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// Bounds of each field once decoded. They are several times what a release's bundle holds.
const (
	maxCertificate = 8 << 10
	maxPayload     = 512 << 10
	maxSignature   = 512
	maxBody        = 64 << 10
	maxCheckpoint  = 4 << 10
	maxProofHashes = 64
)

// The bundle as its protobuf JSON encoding writes it, only with the fields a release's bundle
// carries: any other field, a key or a chain instead of the certificate, timestamps from an
// authority, makes the decoder fail.
type jsonBundle struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		Certificate struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate"`
		TlogEntries               []jsonEntry `json:"tlogEntries"`
		TimestampVerificationData *struct{}   `json:"timestampVerificationData"`
	} `json:"verificationMaterial"`
	DSSEEnvelope struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			Sig   string `json:"sig"`
			KeyID string `json:"keyid"`
		} `json:"signatures"`
	} `json:"dsseEnvelope"`
}

type jsonEntry struct {
	LogIndex string `json:"logIndex"`
	LogID    struct {
		KeyID string `json:"keyId"`
	} `json:"logId"`
	KindVersion struct {
		Kind    string `json:"kind"`
		Version string `json:"version"`
	} `json:"kindVersion"`
	IntegratedTime   string `json:"integratedTime"`
	InclusionPromise struct {
		SignedEntryTimestamp string `json:"signedEntryTimestamp"`
	} `json:"inclusionPromise"`
	InclusionProof struct {
		LogIndex   string   `json:"logIndex"`
		RootHash   string   `json:"rootHash"`
		TreeSize   string   `json:"treeSize"`
		Hashes     []string `json:"hashes"`
		Checkpoint struct {
			Envelope string `json:"envelope"`
		} `json:"checkpoint"`
	} `json:"inclusionProof"`
	CanonicalizedBody string `json:"canonicalizedBody"`
}

// bundle is a parsed bundle: every field decoded and within bounds, nothing verified yet.
type bundle struct {
	cert        *x509.Certificate
	payload     []byte
	payloadType string
	signature   []byte

	logIndex       int64
	logID          []byte
	integratedTime int64
	set            []byte
	body           []byte

	proofIndex uint64
	treeSize   uint64
	rootHash   []byte
	hashes     [][]byte
	checkpoint string
}

// parseBundleFile reads the JSON Lines file a release publishes: exactly one bundle.
func parseBundleFile(file []byte) (*bundle, error) {
	if len(file) > MaxBundleSize {
		return nil, fmt.Errorf("bundle file over %d bytes", MaxBundleSize)
	}
	line := bytes.TrimSuffix(file, []byte("\n"))
	if len(bytes.TrimSpace(line)) == 0 {
		return nil, errors.New("empty bundle file")
	}
	if bytes.ContainsAny(line, "\r\n") {
		return nil, errors.New("bundle file holds more than one line")
	}
	return parseBundle(line)
}

func parseBundle(data []byte) (*bundle, error) {
	var j jsonBundle
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if dec.More() {
		return nil, errors.New("bundle: data after the bundle")
	}
	if j.MediaType != BundleMediaType {
		return nil, fmt.Errorf("bundle media type %q", j.MediaType)
	}
	vm := j.VerificationMaterial
	if len(vm.TlogEntries) != 1 {
		return nil, fmt.Errorf("bundle has %d transparency log entries, not one", len(vm.TlogEntries))
	}
	env := j.DSSEEnvelope
	if len(env.Signatures) != 1 {
		return nil, fmt.Errorf("envelope has %d signatures, not one", len(env.Signatures))
	}
	if env.Signatures[0].KeyID != "" {
		return nil, errors.New("envelope signature names a key")
	}

	b := &bundle{payloadType: env.PayloadType}
	der, err := decode("certificate", vm.Certificate.RawBytes, maxCertificate)
	if err != nil {
		return nil, err
	}
	if b.cert, err = x509.ParseCertificate(der); err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	if b.payload, err = decode("payload", env.Payload, maxPayload); err != nil {
		return nil, err
	}
	if b.signature, err = decode("signature", env.Signatures[0].Sig, maxSignature); err != nil {
		return nil, err
	}

	e := vm.TlogEntries[0]
	if e.KindVersion.Kind != "dsse" || e.KindVersion.Version != "0.0.1" {
		return nil, fmt.Errorf("log entry kind %q version %q", e.KindVersion.Kind, e.KindVersion.Version)
	}
	if b.logIndex, err = parseInt("log index", e.LogIndex); err != nil {
		return nil, err
	}
	if b.integratedTime, err = parseInt("integrated time", e.IntegratedTime); err != nil {
		return nil, err
	}
	if b.integratedTime == 0 {
		return nil, errors.New("log entry has no integrated time")
	}
	if b.logID, err = decode("log id", e.LogID.KeyID, sha256.Size); err != nil {
		return nil, err
	}
	if b.set, err = decode("signed entry timestamp", e.InclusionPromise.SignedEntryTimestamp, maxSignature); err != nil {
		return nil, err
	}
	if b.body, err = decode("log entry body", e.CanonicalizedBody, maxBody); err != nil {
		return nil, err
	}

	p := e.InclusionProof
	if b.proofIndex, err = parseUint("proof index", p.LogIndex); err != nil {
		return nil, err
	}
	if b.treeSize, err = parseUint("tree size", p.TreeSize); err != nil {
		return nil, err
	}
	if b.proofIndex >= b.treeSize {
		return nil, fmt.Errorf("proof index %d outside a tree of %d", b.proofIndex, b.treeSize)
	}
	if b.rootHash, err = decodeHash("root hash", p.RootHash); err != nil {
		return nil, err
	}
	if len(p.Hashes) > maxProofHashes {
		return nil, fmt.Errorf("inclusion proof of %d hashes", len(p.Hashes))
	}
	for _, h := range p.Hashes {
		d, err := decodeHash("proof hash", h)
		if err != nil {
			return nil, err
		}
		b.hashes = append(b.hashes, d)
	}
	if p.Checkpoint.Envelope == "" || len(p.Checkpoint.Envelope) > maxCheckpoint {
		return nil, errors.New("checkpoint missing or too large")
	}
	b.checkpoint = p.Checkpoint.Envelope
	return b, nil
}

// decode reads a base64 field that must be present and at most limit bytes once decoded.
func decode(name, s string, limit int) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("%s missing", name)
	}
	// Even the strict decoder skips line breaks: a value is refused if it holds any.
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("%s: line break in base64", name)
	}
	if base64.StdEncoding.DecodedLen(len(s)) > limit+2 {
		return nil, fmt.Errorf("%s too large", name)
	}
	d, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(d) > limit {
		return nil, fmt.Errorf("%s too large", name)
	}
	return d, nil
}

func decodeHash(name, s string) ([]byte, error) {
	d, err := decode(name, s, sha256.Size)
	if err == nil && len(d) != sha256.Size {
		err = fmt.Errorf("%s of %d bytes", name, len(d))
	}
	return d, err
}

// parseInt reads the decimal string protobuf JSON writes for a 64-bit integer; only the
// canonical form of a non-negative one is accepted.
func parseInt(name, s string) (int64, error) {
	if !canonicalDecimal(s) {
		return 0, fmt.Errorf("%s %q", name, s)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s %q", name, s)
	}
	return n, nil
}

// parseUint is parseInt for the sizes and positions of a Merkle tree.
func parseUint(name, s string) (uint64, error) {
	if !canonicalDecimal(s) {
		return 0, fmt.Errorf("%s %q", name, s)
	}
	n, err := strconv.ParseUint(s, 10, 63)
	if err != nil {
		return 0, fmt.Errorf("%s %q", name, s)
	}
	return n, nil
}

func canonicalDecimal(s string) bool {
	if len(s) == 0 || len(s) > 19 || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
