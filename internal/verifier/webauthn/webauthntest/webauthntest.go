// Package webauthntest plays a browser and a security key for tests: real ES256 and Ed25519
// keys, and responses encoded as authenticators encode them. It does not import the package it
// tests, so that package's own tests can use it.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
)

// COSE algorithms and authenticator data flags, as the specification numbers them.
const (
	ES256  = -7
	EdDSA  = -8
	FlagUP = 0x01
	FlagUV = 0x04
	FlagBE = 0x08
	FlagBS = 0x10
	FlagAT = 0x40
	FlagED = 0x80
)

// Head encodes a CBOR item's major type and argument.
func Head(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	case n < 1<<32:
		return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
	}
	return binary.BigEndian.AppendUint64([]byte{major<<5 | 27}, n)
}

func Int(n int64) []byte {
	if n >= 0 {
		return Head(0, uint64(n))
	}
	return Head(1, uint64(-1-n))
}

func Bytes(b []byte) []byte { return append(Head(2, uint64(len(b))), b...) }
func Text(s string) []byte  { return append(Head(3, uint64(len(s))), s...) }

// Map writes alternating keys and values, already encoded.
func Map(kv ...[]byte) []byte {
	out := Head(5, uint64(len(kv)/2))
	for _, b := range kv {
		out = append(out, b...)
	}
	return out
}

// Authenticator is one credential on a key.
type Authenticator struct {
	Alg   int
	ID    []byte
	Count uint32
	ec    *ecdsa.PrivateKey
	ed    ed25519.PrivateKey
}

// New makes a credential with a fresh key for an algorithm, ES256 or EdDSA.
func New(alg int) *Authenticator {
	a := &Authenticator{Alg: alg, ID: make([]byte, 32)}
	_, _ = rand.Read(a.ID)
	var err error
	if alg == EdDSA {
		_, a.ed, err = ed25519.GenerateKey(rand.Reader)
	} else {
		a.ec, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		panic(err)
	}
	return a
}

// COSE is the credential's public key as a COSE_Key.
func (a *Authenticator) COSE() []byte {
	if a.Alg == EdDSA {
		return Map(Int(1), Int(1), Int(3), Int(EdDSA), Int(-1), Int(6), Int(-2), Bytes(a.ed.Public().(ed25519.PublicKey)))
	}
	point, _ := a.ec.PublicKey.Bytes()
	return Map(Int(1), Int(2), Int(3), Int(ES256), Int(-1), Int(1), Int(-2), Bytes(point[1:33]), Int(-3), Bytes(point[33:]))
}

// ClientData is the clientDataJSON a browser writes.
func ClientData(typ string, challenge []byte, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": origin, "crossOrigin": false})
	return b
}

// Header is the fixed start of authenticator data: the relying party's hash, flags, counter.
func Header(rpID string, flags byte, count uint32) []byte {
	sum := sha256.Sum256([]byte(rpID))
	return binary.BigEndian.AppendUint32(append(sum[:], flags), count)
}

// RegistrationData is the authenticator data of a new credential; AT is set by itself.
func (a *Authenticator) RegistrationData(rpID string, flags byte) []byte {
	ad := Header(rpID, flags|FlagAT, a.Count)
	ad = append(ad, make([]byte, 16)...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(a.ID))) //nolint:gosec // test IDs are short
	ad = append(ad, a.ID...)
	return append(ad, a.COSE()...)
}

// Attest wraps authenticator data in a "none" attestation object.
func Attest(authData []byte) []byte {
	return Map(Text("fmt"), Text("none"), Text("attStmt"), Map(), Text("authData"), Bytes(authData))
}

// Register answers navigator.credentials.create.
func (a *Authenticator) Register(rpID, origin string, challenge []byte) (clientData, attestation []byte) {
	return ClientData("webauthn.create", challenge, origin), Attest(a.RegistrationData(rpID, FlagUP|FlagUV))
}

// Sign signs authenticator data and client data as an assertion does.
func (a *Authenticator) Sign(authData, clientData []byte) []byte {
	sum := sha256.Sum256(clientData)
	msg := append(append([]byte(nil), authData...), sum[:]...)
	if a.Alg == EdDSA {
		return ed25519.Sign(a.ed, msg)
	}
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, a.ec, digest[:])
	if err != nil {
		panic(err)
	}
	return sig
}

// Assert answers navigator.credentials.get, moving the counter forward as a key does.
func (a *Authenticator) Assert(rpID, origin string, challenge []byte) (clientData, authData, sig []byte) {
	a.Count++
	clientData = ClientData("webauthn.get", challenge, origin)
	authData = Header(rpID, FlagUP, a.Count)
	return clientData, authData, a.Sign(authData, clientData)
}
