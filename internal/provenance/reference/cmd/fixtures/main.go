// Command fixtures writes the synthetic bundles the provenance tests use: a small Sigstore of its
// own (a Fulcio root and intermediate, a Rekor v1 log, its trust root) signs one valid release
// bundle and one bundle per way a bundle can be wrong. Bundles and trust root are encoded with
// Sigstore's protobuf types, so they have the shape real ones have.
//
//	go run ./cmd/fixtures -out ../testdata
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cpibia/tripwatch/internal/provenance"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	prototrust "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Version is the release the valid bundle attests, and Asset the file the tests install.
const (
	Version  = "1.2.3"
	Asset    = "tripwatch-sensor_1.2.3_linux_amd64"
	rekorURL = "https://rekor.example.test"
)

// Base is the integrated time of the valid bundle. The trust root's windows are set around it:
// the certificate authority from 30 days before to 30 days after, the log from 10 days before.
var Base = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// Assets are the files of the synthetic release; each holds "contents of <name>".
var Assets = []string{
	"tripwatch-sensor_1.2.3_amd64.deb",
	"tripwatch-sensor-1.2.3-1.x86_64.rpm",
	"tripwatch-sensor_1.2.3_linux_amd64",
	"tripwatch-sensor_1.2.3_arm64.deb",
}

// Manifest describes each fixture for the tests of both verifiers.
type Manifest struct {
	Name    string `json:"name"`
	File    string `json:"file"`
	Root    string `json:"root"`
	Version string `json:"version"`
	Asset   string `json:"asset"`
	Digest  string `json:"digest"`
	Want    string `json:"want"`
	// Reference, when set, is sigstore-go's outcome where it is laxer than this verifier.
	Reference string `json:"reference,omitempty"`
	Why       string `json:"why"`
}

type ext struct {
	n     int
	value string
	// raw extensions (.1 to .7) hold the string itself; the others a DER string.
	raw       bool
	printable bool
}

type spec struct {
	name, why, want, reference string
	version                    string

	uris          []string
	emails        []string
	exts          []ext
	codeSigning   bool
	foreignCA     bool
	leafNotBefore time.Time
	leafNotAfter  time.Time
	integrated    time.Time

	payloadType   string
	statementType string
	predicateType string
	subjects      []subject

	signOtherPayload   bool
	setOtherTime       bool
	foreignLog         bool
	tamperProof        bool
	checkpointBadSig   bool
	checkpointRoot     bool
	checkpointSize     bool
	checkpointOrigin   string
	bodyOtherPayload   bool
	bodyOtherSignature bool
	bodyOtherCert      bool
}

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

func base() spec {
	san := provenance.SubjectAlternativeName(Version)
	ref := "refs/tags/v" + Version
	sha := "0123456789abcdef0123456789abcdef01234567"
	s := spec{
		version: Version, want: "accept",
		uris:        []string{san},
		codeSigning: true,
		exts: []ext{
			{n: 1, value: provenance.Issuer, raw: true},
			{n: 2, value: provenance.Trigger, raw: true},
			{n: 3, value: sha, raw: true},
			{n: 4, value: "release", raw: true},
			{n: 5, value: "cpibia/tripwatch", raw: true},
			{n: 6, value: ref, raw: true},
			{n: 8, value: provenance.Issuer},
			{n: 9, value: san},
			{n: 10, value: sha},
			{n: 11, value: provenance.Runner},
			{n: 12, value: provenance.Repository},
			{n: 13, value: sha},
			{n: 14, value: ref},
			{n: 15, value: provenance.RepositoryID},
			{n: 16, value: "https://github.com/cpibia"},
			{n: 17, value: provenance.OwnerID},
			{n: 18, value: san},
			{n: 19, value: sha},
			{n: 20, value: provenance.Trigger},
			{n: 21, value: provenance.Repository + "/actions/runs/1/attempts/1"},
			{n: 22, value: "public"},
		},
		leafNotBefore: Base.Add(-time.Minute),
		leafNotAfter:  Base.Add(9 * time.Minute),
		integrated:    Base,
		payloadType:   provenance.PayloadType,
		statementType: provenance.StatementType,
		predicateType: provenance.PredicateType,
	}
	for _, a := range Assets {
		s.subjects = append(s.subjects, subject{Name: a, Digest: map[string]string{"sha256": hexSum([]byte("contents of " + a))}})
	}
	return s
}

func (s *spec) setExt(n int, value string) {
	for i := range s.exts {
		if s.exts[i].n == n {
			s.exts[i].value = value
			return
		}
	}
	panic(n)
}

func variants() []spec {
	v := func(name, why string, change func(*spec)) spec {
		s := base()
		s.name, s.why, s.want = name, why, "reject"
		change(&s)
		return s
	}
	laxer := func(s spec, why string) spec {
		s.reference, s.why = "accept", s.why+"; sigstore-go accepts it: "+why
		return s
	}
	valid := base()
	valid.name, valid.why = "valid", "every check passes"
	return []spec{
		valid,
		v("chain-unknown-ca", "leaf issued by a certificate authority outside the trust root", func(s *spec) { s.foreignCA = true }),
		v("chain-expired", "leaf no longer valid at the integrated time", func(s *spec) {
			s.leafNotBefore, s.leafNotAfter = Base.Add(-20*time.Minute), Base.Add(-10*time.Minute)
		}),
		laxer(v("chain-no-code-signing", "leaf without the code signing usage", func(s *spec) { s.codeSigning = false }), "Go reads a leaf without extended key usages as allowed any usage"),
		v("chain-ca-window", "integrated after the end of the authority's window in the trust root", func(s *spec) {
			t := Base.Add(31 * 24 * time.Hour)
			s.integrated, s.leafNotBefore, s.leafNotAfter = t, t.Add(-time.Minute), t.Add(9*time.Minute)
		}),
		v("identity-other-workflow", "built by another workflow of the repository", func(s *spec) {
			san := provenance.Repository + "/.github/workflows/other.yml@refs/tags/v" + Version
			s.uris = []string{san}
			s.setExt(9, san)
			s.setExt(18, san)
		}),
		v("identity-issuer", "token from another issuer", func(s *spec) {
			s.setExt(1, "https://issuer.example.test")
			s.setExt(8, "https://issuer.example.test")
		}),
		v("identity-repository", "another repository", func(s *spec) {
			s.setExt(5, "someone/tripwatch")
			s.setExt(12, "https://github.com/someone/tripwatch")
		}),
		v("identity-ref", "built from a branch, not the tag", func(s *spec) {
			s.setExt(6, "refs/heads/main")
			s.setExt(14, "refs/heads/main")
		}),
		v("identity-repository-id", "same name, another repository id (a recreated repository)", func(s *spec) { s.setExt(15, "1") }),
		v("identity-owner-id", "same name, another owner id (a recreated account)", func(s *spec) { s.setExt(17, "2") }),
		v("identity-trigger", "run by hand, not by the tag push", func(s *spec) {
			s.setExt(2, "workflow_dispatch")
			s.setExt(20, "workflow_dispatch")
		}),
		v("identity-runner", "built on a self-hosted runner", func(s *spec) { s.setExt(11, "self-hosted") }),
		laxer(v("identity-two-uris", "a second URI identity next to the expected one", func(s *spec) {
			s.uris = append(s.uris, "https://example.test/other")
		}), "it compares the first URI only"),
		laxer(v("identity-email", "an email identity next to the expected URI", func(s *spec) { s.emails = []string{"someone@example.test"} }), "it reads the URI and ignores the other names"),
		laxer(v("identity-raw-issuer", "the deprecated raw issuer disagrees with the new one", func(s *spec) {
			s.setExt(1, "https://issuer.example.test")
		}), "it reads the issuer from the new extension only"),
		laxer(v("identity-printable-string", "an identity extension that is not a UTF8String", func(s *spec) {
			for i := range s.exts {
				if s.exts[i].n == 15 {
					s.exts[i].printable = true
				}
			}
		}), "encoding/asn1 converts any string type"),
		v("dsse-signature", "envelope signature over another payload", func(s *spec) { s.signOtherPayload = true }),
		v("dsse-payload-type", "envelope of another payload type", func(s *spec) { s.payloadType = "application/json" }),
		v("statement-type", "statement of an older in-toto version", func(s *spec) { s.statementType = "https://in-toto.io/Statement/v0.1" }),
		v("predicate-type", "provenance of an older SLSA version", func(s *spec) { s.predicateType = "https://slsa.dev/provenance/v0.2" }),
		laxer(v("statement-duplicate-subject", "a file listed twice with two digests", func(s *spec) {
			s.subjects = append(s.subjects, subject{Name: Asset, Digest: map[string]string{"sha256": hexSum([]byte("other"))}})
		}), "it only looks for the expected digest"),
		v("rekor-unknown-log", "entry from a log the trust root does not know", func(s *spec) { s.foreignLog = true }),
		v("rekor-log-window", "integrated before the log key's window", func(s *spec) {
			t := Base.Add(-20 * 24 * time.Hour)
			s.integrated, s.leafNotBefore, s.leafNotAfter = t, t.Add(-time.Minute), t.Add(9*time.Minute)
		}),
		v("rekor-set", "signed entry timestamp for another integrated time", func(s *spec) { s.setOtherTime = true }),
		v("rekor-proof", "an inclusion proof hash altered", func(s *spec) { s.tamperProof = true }),
		v("rekor-checkpoint-signature", "checkpoint signature over another note", func(s *spec) { s.checkpointBadSig = true }),
		v("rekor-checkpoint-root", "checkpoint of another tree root", func(s *spec) { s.checkpointRoot = true }),
		laxer(v("rekor-checkpoint-size", "checkpoint of another tree size with the same root", func(s *spec) { s.checkpointSize = true }), "it compares the checkpoint root, not its size"),
		laxer(v("rekor-checkpoint-origin", "checkpoint of another origin, signed by the log key", func(s *spec) {
			s.checkpointOrigin = "evil.example.test - 1"
		}), "it does not check a Rekor v1 checkpoint origin"),
		v("binding-payload", "log entry for another payload", func(s *spec) { s.bodyOtherPayload = true }),
		v("binding-signature", "log entry holding another signature", func(s *spec) { s.bodyOtherSignature = true }),
		v("binding-certificate", "log entry holding another certificate", func(s *spec) { s.bodyOtherCert = true }),
	}
}

// authority is a Fulcio-like root and intermediate.
type authority struct {
	root, intermediate *x509.Certificate
	key                *ecdsa.PrivateKey
}

func newAuthority(name string) authority {
	rootKey := must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	interKey := must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	notBefore, notAfter := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	rootT := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{Organization: []string{name}, CommonName: name},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	root := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, rootT, rootT, rootKey.Public(), rootKey))))
	interT := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{Organization: []string{name}, CommonName: name + "-intermediate"},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	inter := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, interT, root, interKey.Public(), rootKey))))
	return authority{root: root, intermediate: inter, key: interKey}
}

type sigstore struct {
	ca, foreignCA     authority
	logKey, foreignLg *ecdsa.PrivateKey
}

func (s spec) leaf(ss sigstore, key *ecdsa.PrivateKey) *x509.Certificate {
	ca := ss.ca
	if s.foreignCA {
		ca = ss.foreignCA
	}
	t := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    s.leafNotBefore, NotAfter: s.leafNotAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		EmailAddresses: s.emails,
	}
	if s.codeSigning {
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	for _, u := range s.uris {
		t.URIs = append(t.URIs, must(url.Parse(u)))
	}
	for _, e := range s.exts {
		value := []byte(e.value)
		if !e.raw {
			tag := "utf8"
			if e.printable {
				tag = "printable"
			}
			value = must(asn1.MarshalWithParams(e.value, tag))
		}
		t.ExtraExtensions = append(t.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, e.n}, Value: value})
	}
	return must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, t, ca.intermediate, key.Public(), ca.key))))
}

func (s spec) bundle(ss sigstore) []byte {
	payload := must(json.Marshal(map[string]any{
		"_type":         s.statementType,
		"subject":       s.subjects,
		"predicateType": s.predicateType,
		"predicate": map[string]any{
			"buildDefinition": map[string]any{"buildType": "https://actions.github.io/buildtypes/workflow/v1", "externalParameters": map[string]any{}},
			"runDetails":      map[string]any{"builder": map[string]any{"id": "https://github.com/actions/runner/github-hosted"}},
		},
	}))
	leafKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	leaf := s.leaf(ss, leafKey)
	signed := payload
	if s.signOtherPayload {
		signed = []byte(`{"other":true}`)
	}
	sig := sign(leafKey, pae(s.payloadType, signed))

	bodyPayload, bodySig, bodyCert := payload, sig, leaf.Raw
	if s.bodyOtherPayload {
		bodyPayload = []byte("another payload")
	}
	if s.bodyOtherSignature {
		bodySig = sign(leafKey, []byte("another message"))
	}
	if s.bodyOtherCert {
		bodyCert = s.leaf(ss, leafKey).Raw
	}
	body := rekorBody(bodyPayload, bodySig, bodyCert)

	logKey := ss.logKey
	if s.foreignLog {
		logKey = ss.foreignLg
	}
	logID := keyID(&logKey.PublicKey)
	const logIndex = 4242

	// A tree of nine leaves, this entry the seventh.
	leaves := [][]byte{}
	for i := range 9 {
		leaves = append(leaves, []byte("leaf "+strconv.Itoa(i)))
	}
	const index = 6
	leaves[index] = body
	root := treeHash(leaves)
	path := treePath(index, leaves)
	if s.tamperProof {
		path[1][0] ^= 1
	}

	integrated := s.integrated.Unix()
	setTime := integrated
	if s.setOtherTime {
		setTime++
	}
	set := signSET(logKey, body, setTime, logIndex, logID)

	origin := "rekor.example.test - 1193050959916656506"
	if s.checkpointOrigin != "" {
		origin = s.checkpointOrigin
	}
	cpSize, cpRoot := len(leaves), root
	if s.checkpointSize {
		cpSize++
	}
	if s.checkpointRoot {
		cpRoot = treeHash(leaves[:8])
	}
	checkpoint := signCheckpoint(logKey, origin, cpSize, cpRoot, s.checkpointBadSig)

	pb := &protobundle.Bundle{
		MediaType: provenance.BundleMediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: leaf.Raw}},
			TlogEntries: []*protorekor.TransparencyLogEntry{{
				LogIndex:          logIndex,
				LogId:             &protocommon.LogId{KeyId: logID},
				KindVersion:       &protorekor.KindVersion{Kind: "dsse", Version: "0.0.1"},
				IntegratedTime:    integrated,
				InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: set},
				InclusionProof:    &protorekor.InclusionProof{LogIndex: index, RootHash: root, TreeSize: int64(len(leaves)), Hashes: path, Checkpoint: &protorekor.Checkpoint{Envelope: checkpoint}},
				CanonicalizedBody: body,
			}},
			TimestampVerificationData: &protobundle.TimestampVerificationData{},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			Payload: payload, PayloadType: s.payloadType, Signatures: []*protodsse.Signature{{Sig: sig}},
		}},
	}
	return append(must(protojson.Marshal(pb)), '\n')
}

func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func sign(key *ecdsa.PrivateKey, msg []byte) []byte {
	d := sha256.Sum256(msg)
	return must(ecdsa.SignASN1(rand.Reader, key, d[:]))
}

func rekorBody(payload, sig, cert []byte) []byte {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	type hash struct {
		Algorithm string `json:"algorithm"`
		Value     string `json:"value"`
	}
	type signature struct {
		Signature string `json:"signature"`
		Verifier  string `json:"verifier"`
	}
	body := struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			EnvelopeHash hash        `json:"envelopeHash"`
			PayloadHash  hash        `json:"payloadHash"`
			Signatures   []signature `json:"signatures"`
		} `json:"spec"`
	}{APIVersion: "0.0.1", Kind: "dsse"}
	body.Spec.EnvelopeHash = hash{"sha256", hexSum(append(append([]byte{}, payload...), sig...))}
	body.Spec.PayloadHash = hash{"sha256", hexSum(payload)}
	body.Spec.Signatures = []signature{{base64.StdEncoding.EncodeToString(sig), base64.StdEncoding.EncodeToString(certPEM)}}
	return must(json.Marshal(body))
}

func signSET(key *ecdsa.PrivateKey, body []byte, integrated, logIndex int64, logID []byte) []byte {
	payload := must(json.Marshal(map[string]any{
		"body": base64.StdEncoding.EncodeToString(body), "integratedTime": integrated,
		"logIndex": logIndex, "logID": hex.EncodeToString(logID),
	}))
	return sign(key, must(jsoncanonicalizer.Transform(payload)))
}

func signCheckpoint(key *ecdsa.PrivateKey, origin string, size int, root []byte, wrong bool) string {
	text := origin + "\n" + strconv.Itoa(size) + "\n" + base64.StdEncoding.EncodeToString(root) + "\n"
	signed := text
	if wrong {
		signed = text + "x"
	}
	id := keyID(&key.PublicKey)
	sig := append(id[:4:4], sign(key, []byte(signed))...)
	// U+2014 starts a note's signature line.
	return text + "\n\xe2\x80\x94 rekor.example.test " + base64.StdEncoding.EncodeToString(sig) + "\n"
}

func keyID(pub *ecdsa.PublicKey) []byte {
	d := sha256.Sum256(must(x509.MarshalPKIXPublicKey(pub)))
	return d[:]
}

// treeHash and treePath follow RFC 6962, section 2.1.
func treeHash(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		h := sha256.Sum256(append([]byte{0}, leaves[0]...))
		return h[:]
	}
	k := split(len(leaves))
	h := sha256.Sum256(append(append([]byte{1}, treeHash(leaves[:k])...), treeHash(leaves[k:])...))
	return h[:]
}

func treePath(m int, leaves [][]byte) [][]byte {
	if len(leaves) == 1 {
		return nil
	}
	k := split(len(leaves))
	if m < k {
		return append(treePath(m, leaves[:k]), treeHash(leaves[k:]))
	}
	return append(treePath(m-k, leaves[k:]), treeHash(leaves[:k]))
}

func split(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func trustRoot(ss sigstore) []byte {
	logPub := must(x509.MarshalPKIXPublicKey(&ss.logKey.PublicKey))
	tr := &prototrust.TrustedRoot{
		MediaType: "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		Tlogs: []*prototrust.TransparencyLogInstance{{
			BaseUrl:       rekorURL,
			HashAlgorithm: protocommon.HashAlgorithm_SHA2_256,
			PublicKey: &protocommon.PublicKey{
				RawBytes: logPub, KeyDetails: protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
				ValidFor: &protocommon.TimeRange{Start: timestamppb.New(Base.Add(-10 * 24 * time.Hour))},
			},
			LogId: &protocommon.LogId{KeyId: keyID(&ss.logKey.PublicKey)},
		}},
		CertificateAuthorities: []*prototrust.CertificateAuthority{{
			Subject: &protocommon.DistinguishedName{Organization: "example.test", CommonName: "fulcio"},
			Uri:     "https://fulcio.example.test",
			CertChain: &protocommon.X509CertificateChain{Certificates: []*protocommon.X509Certificate{
				{RawBytes: ss.ca.intermediate.Raw}, {RawBytes: ss.ca.root.Raw},
			}},
			ValidFor: &protocommon.TimeRange{Start: timestamppb.New(Base.Add(-30 * 24 * time.Hour)), End: timestamppb.New(Base.Add(30 * 24 * time.Hour))},
		}},
	}
	return must(protojson.MarshalOptions{Multiline: true}.Marshal(tr))
}

func hexSum(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func main() {
	out := flag.String("out", "../testdata", "directory for the fixtures")
	flag.Parse()
	ss := sigstore{
		ca: newAuthority("fulcio.example.test"), foreignCA: newAuthority("other.example.test"),
		logKey: must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)), foreignLg: must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)),
	}
	dir := filepath.Join(*out, "synthetic")
	check(os.MkdirAll(dir, 0o750))
	check(os.WriteFile(filepath.Join(dir, "trusted_root.json"), trustRoot(ss), 0o600))

	manifest := []Manifest{{
		Name: "release-0.1.51", File: "release-0.1.51.jsonl", Root: "public-good", Version: "0.1.51",
		Asset: "tripwatch-sensor_linux_amd64", Digest: "34d6f1273fb68b59d998888ef55ab723885829c11ee2810912032d12e0489f09",
		Want: "accept", Why: "the bundle GitHub made for a published release",
	}}
	for _, s := range variants() {
		file := filepath.Join("synthetic", s.name+".jsonl")
		check(os.WriteFile(filepath.Join(*out, file), s.bundle(ss), 0o600))
		manifest = append(manifest, Manifest{
			Name: s.name, File: file, Root: "synthetic/trusted_root.json", Version: s.version,
			Asset: Asset, Digest: hexSum([]byte("contents of " + Asset)), Want: s.want, Reference: s.reference, Why: s.why,
		})
	}
	manifest = append(manifest,
		Manifest{
			Name: "other-version", File: "synthetic/valid.jsonl", Root: "synthetic/trusted_root.json", Version: "1.2.4",
			Asset: Asset, Digest: hexSum([]byte("contents of " + Asset)), Want: "reject", Why: "a valid bundle of 1.2.3 offered for 1.2.4",
		},
		Manifest{
			Name: "other-digest", File: "synthetic/valid.jsonl", Root: "synthetic/trusted_root.json", Version: Version,
			Asset: Asset, Digest: hexSum([]byte("other contents")), Want: "reject", Why: "a file the valid bundle does not attest",
		})
	check(os.WriteFile(filepath.Join(*out, "manifest.json"), append(must(json.MarshalIndent(manifest, "", "  ")), '\n'), 0o600))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
