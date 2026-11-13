package webauthn

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// Size caps on what a browser posts. A credential ID is at most 1023 bytes by the
// specification; the rest leave room for every authenticator met in practice.
const (
	MaxCredentialID   = 1023
	MaxClientData     = 4096
	MaxAuthData       = 2048
	MaxAttestation    = 8192
	MaxSignature      = 256
	ChallengeSize     = 32
	authDataMinLength = 37
)

// Authenticator data flags.
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
	flagED = 0x80
)

var (
	ErrMalformed     = errors.New("webauthn: malformed response")
	ErrType          = errors.New("webauthn: wrong ceremony type")
	ErrChallenge     = errors.New("webauthn: wrong challenge")
	ErrOrigin        = errors.New("webauthn: wrong origin")
	ErrRelyingParty  = errors.New("webauthn: wrong relying party")
	ErrUserPresence  = errors.New("webauthn: the user was not present")
	ErrSignature     = errors.New("webauthn: bad signature")
	ErrUnsupported   = errors.New("webauthn: unsupported key")
	ErrNotConfigured = errors.New("webauthn: no public URL for the console")
)

// RelyingParty is the console as browsers see it: the ID credentials are scoped to, and the one
// origin responses must come from.
type RelyingParty struct {
	ID     string
	Origin string
	idHash [32]byte
}

// NewRelyingParty derives the relying party from the console's public URL. Browsers offer
// WebAuthn only in a secure context: HTTPS, or plain HTTP on localhost for development.
func NewRelyingParty(publicURL string) (RelyingParty, error) {
	u, err := url.Parse(strings.TrimSpace(publicURL))
	if err != nil || u.Host == "" || u.User != nil {
		return RelyingParty{}, ErrNotConfigured
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && (host == "localhost" || strings.HasSuffix(host, ".localhost")):
	default:
		return RelyingParty{}, ErrNotConfigured
	}
	return RelyingParty{ID: host, Origin: u.Scheme + "://" + strings.ToLower(u.Host), idHash: sha256.Sum256([]byte(host))}, nil
}

// Enabled reports whether security keys can be used with this console.
func (rp RelyingParty) Enabled() bool { return rp.ID != "" }

// Registration is a new credential, checked.
type Registration struct {
	CredentialID []byte
	// PublicKey is the COSE_Key as the authenticator sent it, to store and parse at each use.
	PublicKey    []byte
	Alg          int
	SignCount    uint32
	UserVerified bool
}

// Assertion is what a checked sign-in tells about the authenticator.
type Assertion struct {
	SignCount    uint32
	UserVerified bool
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// checkClientData checks what the browser says it signed for: the ceremony, our challenge, our
// origin, and no embedding in another site's frame.
func (rp RelyingParty) checkClientData(raw []byte, ceremony string, challenge []byte) error {
	if len(raw) == 0 || len(raw) > MaxClientData {
		return ErrMalformed
	}
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return ErrMalformed
	}
	if cd.Type != ceremony {
		return ErrType
	}
	got, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil || len(challenge) != ChallengeSize || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return ErrChallenge
	}
	if cd.Origin != rp.Origin || cd.CrossOrigin {
		return ErrOrigin
	}
	return nil
}

type authData struct {
	flags     byte
	signCount uint32
	credID    []byte
	key       value
	keyRaw    []byte
}

// parseAuthData reads the authenticator data, which must hold a new credential at registration
// and must not at sign-in, and checks it is scoped to this relying party with the user present.
func (rp RelyingParty) parseAuthData(b []byte, registration bool) (authData, error) {
	if len(b) < authDataMinLength || len(b) > MaxAuthData {
		return authData{}, ErrMalformed
	}
	if subtle.ConstantTimeCompare(b[:32], rp.idHash[:]) != 1 {
		return authData{}, ErrRelyingParty
	}
	ad := authData{flags: b[32], signCount: u32(b[33:37])}
	if ad.flags&flagUP == 0 {
		return authData{}, ErrUserPresence
	}
	if ad.flags&flagBS != 0 && ad.flags&flagBE == 0 {
		return authData{}, ErrMalformed
	}
	if (ad.flags&flagAT != 0) != registration {
		return authData{}, ErrMalformed
	}
	rest := b[37:]
	if registration {
		// AAGUID, then the credential ID's length, the ID and its COSE key.
		if len(rest) < 18 {
			return authData{}, ErrMalformed
		}
		n := u16(rest[16:18])
		rest = rest[18:]
		if n == 0 || n > MaxCredentialID || n > len(rest) {
			return authData{}, ErrMalformed
		}
		ad.credID, rest = rest[:n], rest[n:]
		key, after, err := decodeCBOR(rest)
		if err != nil {
			return authData{}, ErrMalformed
		}
		ad.key, ad.keyRaw, rest = key, rest[:len(rest)-len(after)], after
	}
	if ad.flags&flagED != 0 {
		ext, after, err := decodeCBOR(rest)
		if err != nil || ext.kind != kindMap {
			return authData{}, ErrMalformed
		}
		rest = after
	}
	if len(rest) != 0 {
		return authData{}, ErrMalformed
	}
	return ad, nil
}

// VerifyRegistration checks the response to navigator.credentials.create for the challenge the
// verifier issued. Attestation is asked as "none" and never evaluated: the key is trusted
// because a signed-in user, who proved a second factor already if they had one, registered it,
// not because of who made it. An attestation statement some browser still sends is skipped.
func (rp RelyingParty) VerifyRegistration(challenge, clientDataJSON, attestationObject []byte) (Registration, error) {
	if err := rp.checkClientData(clientDataJSON, "webauthn.create", challenge); err != nil {
		return Registration{}, err
	}
	if len(attestationObject) == 0 || len(attestationObject) > MaxAttestation {
		return Registration{}, ErrMalformed
	}
	att, rest, err := decodeCBOR(attestationObject)
	if err != nil || len(rest) != 0 || att.kind != kindMap {
		return Registration{}, ErrMalformed
	}
	format, ok1 := att.field("fmt")
	stmt, ok2 := att.field("attStmt")
	raw, ok3 := att.field("authData")
	if !ok1 || !ok2 || !ok3 || format.kind != kindText || len(format.bytes) == 0 || len(format.bytes) > 32 || stmt.kind != kindMap || raw.kind != kindBytes {
		return Registration{}, ErrMalformed
	}
	if string(format.bytes) == "none" && len(stmt.keys) != 0 {
		return Registration{}, ErrMalformed
	}
	ad, err := rp.parseAuthData(raw.bytes, true)
	if err != nil {
		return Registration{}, err
	}
	key, err := publicKey(ad.key)
	if err != nil {
		return Registration{}, ErrUnsupported
	}
	return Registration{
		CredentialID: bytes.Clone(ad.credID),
		PublicKey:    bytes.Clone(ad.keyRaw),
		Alg:          key.Alg,
		SignCount:    ad.signCount,
		UserVerified: ad.flags&flagUV != 0,
	}, nil
}

// VerifyAssertion checks the response to navigator.credentials.get against the stored key of
// the credential it names. Whether that credential belongs to the user signing in, and whether
// its counter moved forward, is the caller's to check.
func (rp RelyingParty) VerifyAssertion(challenge, publicKeyCOSE, clientDataJSON, authenticatorData, signature []byte) (Assertion, error) {
	if err := rp.checkClientData(clientDataJSON, "webauthn.get", challenge); err != nil {
		return Assertion{}, err
	}
	ad, err := rp.parseAuthData(authenticatorData, false)
	if err != nil {
		return Assertion{}, err
	}
	key, err := ParsePublicKey(publicKeyCOSE)
	if err != nil {
		return Assertion{}, ErrUnsupported
	}
	if len(signature) == 0 || len(signature) > MaxSignature {
		return Assertion{}, ErrSignature
	}
	signed := make([]byte, 0, len(authenticatorData)+sha256.Size)
	signed = append(append(signed, authenticatorData...), sha256Sum(clientDataJSON)...)
	if !key.verify(signed, signature) {
		return Assertion{}, ErrSignature
	}
	return Assertion{SignCount: ad.signCount, UserVerified: ad.flags&flagUV != 0}, nil
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
