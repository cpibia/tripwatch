package provenance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"
)

// verifyCertificate checks the leaf against the Fulcio authorities valid at the integrated
// time, and at that time, not now: the leaf lives ten minutes, the release for months.
func (r *trustRoot) verifyCertificate(leaf *x509.Certificate, at time.Time) (*ecdsa.PublicKey, error) {
	var errs []error
	for _, ca := range r.cas {
		if !ca.validFor.contains(at) {
			continue
		}
		roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
		roots.AddCert(ca.root)
		for _, c := range ca.intermediates {
			intermediates.AddCert(c)
		}
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   at,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		})
		// Verify reads a leaf without extended key usages as allowed any usage; Fulcio always
		// sets code signing, so its absence is refused.
		if err == nil && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
			return nil, errors.New("certificate is not for code signing")
		}
		if err == nil {
			key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
			if !ok || key.Curve != elliptic.P256() {
				return nil, errors.New("certificate key is not ECDSA P-256")
			}
			return key, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return nil, errors.New("no certificate authority valid at the integrated time")
	}
	return nil, fmt.Errorf("certificate: %w", errors.Join(errs...))
}

// Fulcio's extensions (1.3.6.1.4.1.57264.1.x). The first ones hold the raw string as the
// extension value; from .8 on the value is a DER UTF8String.
var (
	oidIssuerV1        = fulcioOID(1)
	oidTriggerV1       = fulcioOID(2)
	oidRepositoryV1    = fulcioOID(5)
	oidRefV1           = fulcioOID(6)
	oidIssuer          = fulcioOID(8)
	oidBuildSignerURI  = fulcioOID(9)
	oidRunner          = fulcioOID(11)
	oidSourceRepoURI   = fulcioOID(12)
	oidSourceRepoRef   = fulcioOID(14)
	oidSourceRepoID    = fulcioOID(15)
	oidSourceOwnerID   = fulcioOID(17)
	oidBuildConfigURI  = fulcioOID(18)
	oidBuildTrigger    = fulcioOID(20)
	oidSubjectAltNames = asn1.ObjectIdentifier{2, 5, 29, 17}
)

func fulcioOID(n int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, n}
}

// checkIdentity requires the certificate to name the release workflow of this repository, run
// by a push of the tag of version on a runner GitHub hosts. Every value is compared whole.
func checkIdentity(cert *x509.Certificate, version string) error {
	san := SubjectAlternativeName(version)
	ref := "refs/tags/v" + version
	if len(cert.URIs) != 1 || len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.IPAddresses) != 0 {
		return errors.New("certificate does not hold exactly one URI identity")
	}
	if got := cert.URIs[0].String(); got != san {
		return fmt.Errorf("certificate identity %q, not %q", got, san)
	}
	// Names Go does not parse (other names, directory names) would otherwise go unseen.
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSubjectAltNames) {
			if err := onlyOneURI(ext.Value); err != nil {
				return err
			}
		}
	}

	required := []struct {
		oid  asn1.ObjectIdentifier
		want string
	}{
		{oidIssuer, Issuer},
		{oidBuildSignerURI, san},
		{oidRunner, Runner},
		{oidSourceRepoURI, Repository},
		{oidSourceRepoRef, ref},
		{oidSourceRepoID, RepositoryID},
		{oidSourceOwnerID, OwnerID},
		{oidBuildConfigURI, san},
		{oidBuildTrigger, Trigger},
	}
	for _, r := range required {
		value, ok := extension(cert, r.oid)
		if !ok {
			return fmt.Errorf("certificate lacks extension %s", r.oid)
		}
		got, err := derUTF8String(value)
		if err != nil {
			return fmt.Errorf("extension %s: %w", r.oid, err)
		}
		if got != r.want {
			return fmt.Errorf("extension %s is %q, not %q", r.oid, got, r.want)
		}
	}
	// The deprecated raw extensions are optional, but when present must agree.
	raw := []struct {
		oid  asn1.ObjectIdentifier
		want string
	}{
		{oidIssuerV1, Issuer},
		{oidTriggerV1, Trigger},
		{oidRepositoryV1, "cpibia/tripwatch"},
		{oidRefV1, ref},
	}
	for _, r := range raw {
		if value, ok := extension(cert, r.oid); ok && string(value) != r.want {
			return fmt.Errorf("extension %s is %q, not %q", r.oid, value, r.want)
		}
	}
	return nil
}

func extension(cert *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return ext.Value, true
		}
	}
	return nil, false
}

// derUTF8String reads exactly one DER UTF8String; another string type is refused rather than
// converted, as encoding/asn1 would.
func derUTF8String(value []byte) (string, error) {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(value, &v)
	if err != nil {
		return "", err
	}
	if len(rest) != 0 || v.Class != asn1.ClassUniversal || v.Tag != asn1.TagUTF8String || v.IsCompound || !utf8.Valid(v.Bytes) {
		return "", errors.New("not a DER UTF8String")
	}
	return string(v.Bytes), nil
}

// onlyOneURI checks the subject alternative names extension holds a single URI name.
func onlyOneURI(value []byte) error {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(value, &seq)
	if err != nil || len(rest) != 0 || !seq.IsCompound || seq.Tag != asn1.TagSequence {
		return errors.New("malformed subject alternative names")
	}
	var names int
	for b := seq.Bytes; len(b) > 0; names++ {
		var n asn1.RawValue
		if b, err = asn1.Unmarshal(b, &n); err != nil {
			return errors.New("malformed subject alternative names")
		}
		const uriTag = 6
		if n.Class != asn1.ClassContextSpecific || n.Tag != uriTag {
			return errors.New("certificate holds a name other than a URI")
		}
	}
	if names != 1 {
		return errors.New("certificate does not hold exactly one URI identity")
	}
	return nil
}
