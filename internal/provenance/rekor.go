package provenance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// verifyEntry checks the bundle's Rekor v1 entry and returns the time the log signed for it,
// the only time the rest of the verification trusts.
func (r *trustRoot) verifyEntry(b *bundle) (time.Time, error) {
	at := time.Unix(b.integratedTime, 0)
	var log *rekorLog
	for i := range r.logs {
		if bytes.Equal(r.logs[i].keyHash[:], b.logID) {
			log = &r.logs[i]
			break
		}
	}
	if log == nil {
		return at, errors.New("log entry from a log the trust root does not know")
	}
	if !log.validFor.contains(at) {
		return at, errors.New("log key not valid at the integrated time")
	}
	if err := verifySET(log, b); err != nil {
		return at, err
	}
	if err := verifyInclusion(log, b); err != nil {
		return at, err
	}
	if err := bindEntry(b); err != nil {
		return at, err
	}
	return at, nil
}

// verifySET checks the signed entry timestamp: the log's signature over the canonical JSON of
// the entry's body, integrated time, log id and index. It is what makes the integrated time
// trustworthy; the inclusion proof alone does not cover it.
func verifySET(log *rekorLog, b *bundle) error {
	// RFC 8785 canonical form: keys sorted, no spaces; base64 and hex need no escaping.
	payload := `{"body":"` + base64.StdEncoding.EncodeToString(b.body) +
		`","integratedTime":` + strconv.FormatInt(b.integratedTime, 10) +
		`,"logID":"` + hex.EncodeToString(b.logID) +
		`","logIndex":` + strconv.FormatInt(b.logIndex, 10) + `}`
	digest := sha256.Sum256([]byte(payload))
	if !ecdsa.VerifyASN1(log.key, digest[:], b.set) {
		return errors.New("signed entry timestamp does not verify")
	}
	return nil
}

// verifyInclusion checks that the entry's body is a leaf of the tree the proof leads to, and
// that the log signed that tree in the checkpoint.
func verifyInclusion(log *rekorLog, b *bundle) error {
	leaf := rfc6962.DefaultHasher.HashLeaf(b.body)
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, b.proofIndex, b.treeSize, leaf, b.hashes, b.rootHash); err != nil {
		return fmt.Errorf("inclusion proof: %w", err)
	}
	size, root, err := verifyCheckpoint(log, b.checkpoint)
	if err != nil {
		return err
	}
	if size != b.treeSize || !bytes.Equal(root, b.rootHash) {
		return errors.New("checkpoint is not the tree of the inclusion proof")
	}
	return nil
}

// verifyCheckpoint checks a signed note from a Rekor v1 log: origin "<host> - <tree id>", tree
// size, root hash, then after a blank line exactly one signature line from the log, whose key
// hint is the first four bytes of the SHA-256 of its key.
func verifyCheckpoint(log *rekorLog, note string) (uint64, []byte, error) {
	text, sigs, ok := strings.Cut(note, "\n\n")
	if !ok || strings.Contains(sigs, "\n\n") {
		return 0, nil, errors.New("checkpoint: malformed note")
	}
	text += "\n"
	// A note's signature lines start with an em dash, U+2014.
	sigLine, ok := strings.CutSuffix(sigs, "\n")
	if !ok || strings.Contains(sigLine, "\n") {
		return 0, nil, errors.New("checkpoint: not exactly one signature")
	}
	fields := strings.Split(sigLine, " ")
	if len(fields) != 3 || fields[0] != "\xe2\x80\x94" || fields[1] != log.host {
		return 0, nil, errors.New("checkpoint: signature line not from the log")
	}
	sig, err := decode("checkpoint signature", fields[2], maxSignature)
	if err != nil || len(sig) < 5 {
		return 0, nil, errors.New("checkpoint: malformed signature")
	}
	if !bytes.Equal(sig[:4], log.keyHash[:4]) {
		return 0, nil, errors.New("checkpoint: signed by another key")
	}
	digest := sha256.Sum256([]byte(text))
	if !ecdsa.VerifyASN1(log.key, digest[:], sig[4:]) {
		return 0, nil, errors.New("checkpoint: signature does not verify")
	}

	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 {
		return 0, nil, errors.New("checkpoint: too few lines")
	}
	treeID, ok := strings.CutPrefix(lines[0], log.host+" - ")
	if !ok {
		return 0, nil, fmt.Errorf("checkpoint: origin %q", lines[0])
	}
	if _, err := parseInt("checkpoint tree id", treeID); err != nil {
		return 0, nil, err
	}
	size, err := parseUint("checkpoint size", lines[1])
	if err != nil {
		return 0, nil, err
	}
	root, err := decodeHash("checkpoint root", lines[2])
	if err != nil {
		return 0, nil, err
	}
	return size, root, nil
}

// The body of a Rekor v1 dsse entry. The envelope hash is not compared: it is the hash of the
// envelope as the log serialised it, and the payload hash, signature and certificate already
// pin everything the verification relies on.
type dsseBody struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		EnvelopeHash hashValue `json:"envelopeHash"`
		PayloadHash  hashValue `json:"payloadHash"`
		Signatures   []struct {
			Signature string `json:"signature"`
			Verifier  string `json:"verifier"`
		} `json:"signatures"`
	} `json:"spec"`
}

type hashValue struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// bindEntry ties the log entry to this bundle: the same payload, signature and certificate.
// Without it, a genuine entry of any other artifact would vouch for this one.
func bindEntry(b *bundle) error {
	var body dsseBody
	dec := json.NewDecoder(bytes.NewReader(b.body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		return fmt.Errorf("log entry body: %w", err)
	}
	if body.APIVersion != "0.0.1" || body.Kind != "dsse" {
		return fmt.Errorf("log entry body is %s %s", body.Kind, body.APIVersion)
	}
	payloadHash := sha256.Sum256(b.payload)
	if body.Spec.PayloadHash.Algorithm != "sha256" || body.Spec.PayloadHash.Value != hex.EncodeToString(payloadHash[:]) {
		return errors.New("log entry is for another payload")
	}
	if len(body.Spec.Signatures) != 1 {
		return errors.New("log entry does not hold exactly one signature")
	}
	s := body.Spec.Signatures[0]
	sig, err := decode("log entry signature", s.Signature, maxSignature)
	if err != nil || !bytes.Equal(sig, b.signature) {
		return errors.New("log entry holds another signature")
	}
	pemBytes, err := decode("log entry certificate", s.Verifier, 2*maxCertificate)
	if err != nil {
		return errors.New("log entry certificate is malformed")
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(block.Bytes, b.cert.Raw) {
		return errors.New("log entry holds another certificate")
	}
	return nil
}
