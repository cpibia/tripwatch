package provenance

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// Bounds of the attested subjects: a release has a few dozen files.
const (
	maxSubjects    = 256
	maxSubjectName = 256
)

// verifyEnvelope checks the DSSE signature of the leaf over the pre-authentication encoding of
// the payload and its type.
func verifyEnvelope(b *bundle, key *ecdsa.PublicKey) error {
	if b.payloadType != PayloadType {
		return fmt.Errorf("payload type %q", b.payloadType)
	}
	pae := "DSSEv1 " + strconv.Itoa(len(b.payloadType)) + " " + b.payloadType + " " + strconv.Itoa(len(b.payload)) + " "
	h := sha256.New()
	h.Write([]byte(pae))
	h.Write(b.payload)
	if !ecdsa.VerifyASN1(key, h.Sum(nil), b.signature) {
		return errors.New("envelope signature does not verify")
	}
	return nil
}

type statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
}

// parseStatement reads the files an in-toto statement of SLSA provenance v1 lists. The
// predicate is not read: the certificate already says which workflow, repository and tag built
// them.
func parseStatement(payload []byte) (Subjects, error) {
	var s statement
	if err := json.Unmarshal(payload, &s); err != nil {
		return nil, fmt.Errorf("statement: %w", err)
	}
	if s.Type != StatementType {
		return nil, fmt.Errorf("statement type %q", s.Type)
	}
	if s.PredicateType != PredicateType {
		return nil, fmt.Errorf("predicate type %q", s.PredicateType)
	}
	if len(s.Subject) == 0 || len(s.Subject) > maxSubjects {
		return nil, fmt.Errorf("statement lists %d subjects", len(s.Subject))
	}
	subjects := make(Subjects, len(s.Subject))
	for _, sub := range s.Subject {
		if sub.Name == "" || len(sub.Name) > maxSubjectName {
			return nil, errors.New("subject without a valid name")
		}
		d, err := hex.DecodeString(sub.Digest["sha256"])
		if err != nil || len(d) != sha256.Size {
			return nil, fmt.Errorf("subject %q has no SHA-256", sub.Name)
		}
		if _, dup := subjects[sub.Name]; dup {
			return nil, fmt.Errorf("subject %q listed twice", sub.Name)
		}
		subjects[sub.Name] = Digest(d)
	}
	return subjects, nil
}
