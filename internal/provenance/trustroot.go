package provenance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

const trustRootMediaType = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

// The part of a trusted_root.json this package uses. The file is trusted input (embedded at
// build time, or a test's own), so fields it does not use are ignored.
type jsonTrustRoot struct {
	MediaType string `json:"mediaType"`
	Tlogs     []struct {
		BaseURL   string `json:"baseUrl"`
		PublicKey struct {
			RawBytes   []byte     `json:"rawBytes"`
			KeyDetails string     `json:"keyDetails"`
			ValidFor   jsonPeriod `json:"validFor"`
		} `json:"publicKey"`
		LogID struct {
			KeyID []byte `json:"keyId"`
		} `json:"logId"`
	} `json:"tlogs"`
	CertificateAuthorities []struct {
		CertChain struct {
			Certificates []struct {
				RawBytes []byte `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"certChain"`
		ValidFor jsonPeriod `json:"validFor"`
	} `json:"certificateAuthorities"`
}

type jsonPeriod struct {
	Start *time.Time `json:"start"`
	End   *time.Time `json:"end"`
}

// period is a validity window; a zero end is open.
type period struct{ start, end time.Time }

func (p period) contains(t time.Time) bool {
	return !t.Before(p.start) && (p.end.IsZero() || !t.After(p.end))
}

func (j jsonPeriod) period() (period, error) {
	if j.Start == nil {
		return period{}, errors.New("validity without a start")
	}
	p := period{start: *j.Start}
	if j.End != nil {
		p.end = *j.End
	}
	return p, nil
}

// rekorLog is a Rekor v1 log: an ECDSA P-256 key, identified by the SHA-256 of its DER.
type rekorLog struct {
	host     string
	key      *ecdsa.PublicKey
	keyHash  [sha256.Size]byte
	validFor period
}

type fulcioCA struct {
	root          *x509.Certificate
	intermediates []*x509.Certificate
	validFor      period
}

type trustRoot struct {
	logs []rekorLog
	cas  []fulcioCA
}

func parseTrustRoot(data []byte) (*trustRoot, error) {
	var j jsonTrustRoot
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, err
	}
	if j.MediaType != trustRootMediaType {
		return nil, fmt.Errorf("media type %q", j.MediaType)
	}
	r := &trustRoot{}
	for _, l := range j.Tlogs {
		// Rekor v2 logs (Ed25519, tiles) sign entries no release bundle carries yet.
		if l.PublicKey.KeyDetails != "PKIX_ECDSA_P256_SHA_256" {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(l.PublicKey.RawBytes)
		if err != nil {
			return nil, fmt.Errorf("log key: %w", err)
		}
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() {
			return nil, errors.New("log key is not ECDSA P-256")
		}
		hash := sha256.Sum256(l.PublicKey.RawBytes)
		if !bytes.Equal(hash[:], l.LogID.KeyID) {
			return nil, errors.New("log id is not the hash of its key")
		}
		u, err := url.Parse(l.BaseURL)
		if err != nil || u.Hostname() == "" {
			return nil, fmt.Errorf("log URL %q", l.BaseURL)
		}
		p, err := l.PublicKey.ValidFor.period()
		if err != nil {
			return nil, err
		}
		r.logs = append(r.logs, rekorLog{host: u.Hostname(), key: key, keyHash: hash, validFor: p})
	}
	for _, ca := range j.CertificateAuthorities {
		certs := ca.CertChain.Certificates
		if len(certs) == 0 {
			return nil, errors.New("certificate authority without certificates")
		}
		var chain []*x509.Certificate
		for _, c := range certs {
			cert, err := x509.ParseCertificate(c.RawBytes)
			if err != nil {
				return nil, fmt.Errorf("certificate authority: %w", err)
			}
			chain = append(chain, cert)
		}
		p, err := ca.ValidFor.period()
		if err != nil {
			return nil, err
		}
		r.cas = append(r.cas, fulcioCA{root: chain[len(chain)-1], intermediates: chain[:len(chain)-1], validFor: p})
	}
	if len(r.logs) == 0 || len(r.cas) == 0 {
		return nil, errors.New("no Rekor v1 log or no certificate authority")
	}
	return r, nil
}
