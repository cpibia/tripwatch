package webauthn

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
)

// The COSE algorithms accepted: ES256 is what every security key and platform authenticator
// offers, Ed25519 what some keys prefer. RSA and the rest are refused rather than half-checked.
const (
	AlgES256   = -7
	AlgEdDSA   = -8
	coseKty    = 1
	coseAlg    = 3
	coseCrv    = -1
	coseX      = -2
	coseY      = -3
	ktyOKP     = 1
	ktyEC2     = 2
	crvP256    = 1
	crvEd25519 = 6
)

var errKey = errors.New("webauthn: unsupported or malformed public key")

// PublicKey is a credential's key, parsed from its COSE form.
type PublicKey struct {
	Alg     int
	ecdsa   *ecdsa.PublicKey
	ed25519 ed25519.PublicKey
}

// ParsePublicKey parses a COSE_Key as stored with a credential; the whole input must be the key.
func ParsePublicKey(cose []byte) (PublicKey, error) {
	v, rest, err := decodeCBOR(cose)
	if err != nil || len(rest) != 0 {
		return PublicKey{}, errKey
	}
	return publicKey(v)
}

func publicKey(v value) (PublicKey, error) {
	if v.kind != kindMap {
		return PublicKey{}, errKey
	}
	kty, ok1 := v.get(coseKty)
	alg, ok2 := v.get(coseAlg)
	crv, ok3 := v.get(coseCrv)
	x, ok4 := v.get(coseX)
	if !ok1 || !ok2 || !ok3 || !ok4 || !kty.isInt() || !alg.isInt() || !crv.isInt() || x.kind != kindBytes {
		return PublicKey{}, errKey
	}
	switch {
	case alg.int == AlgES256 && kty.int == ktyEC2 && crv.int == crvP256:
		y, ok := v.get(coseY)
		if !ok || y.kind != kindBytes || len(x.bytes) != 32 || len(y.bytes) != 32 {
			return PublicKey{}, errKey
		}
		point := make([]byte, 0, 65)
		point = append(append(append(point, 4), x.bytes...), y.bytes...)
		// The parser checks the point is on the curve: an off-curve key must not reach
		// verification.
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			return PublicKey{}, errKey
		}
		return PublicKey{Alg: AlgES256, ecdsa: pub}, nil
	case alg.int == AlgEdDSA && kty.int == ktyOKP && crv.int == crvEd25519:
		if len(x.bytes) != ed25519.PublicKeySize {
			return PublicKey{}, errKey
		}
		return PublicKey{Alg: AlgEdDSA, ed25519: ed25519.PublicKey(append([]byte(nil), x.bytes...))}, nil
	}
	return PublicKey{}, errKey
}

// verify checks a signature over data: ES256 signatures come DER-encoded, Ed25519 ones raw.
func (k PublicKey) verify(data, sig []byte) bool {
	switch k.Alg {
	case AlgES256:
		return k.ecdsa != nil && ecdsa.VerifyASN1(k.ecdsa, sha256Sum(data), sig)
	case AlgEdDSA:
		return len(k.ed25519) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && ed25519.Verify(k.ed25519, data, sig)
	}
	return false
}
