package webauthn

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	wt "github.com/cpibia/tripwatch/internal/verifier/webauthn/webauthntest"
)

func testRP(t testing.TB) RelyingParty {
	t.Helper()
	rp, err := NewRelyingParty("https://console.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

func challenge() []byte {
	c := make([]byte, ChallengeSize)
	_, _ = rand.Read(c)
	return c
}

func TestNewRelyingParty(t *testing.T) {
	for in, want := range map[string]RelyingParty{
		"https://Console.Example.com:8443/path": {ID: "console.example.com", Origin: "https://console.example.com:8443"},
		"http://localhost:8080":                 {ID: "localhost", Origin: "http://localhost:8080"},
	} {
		got, err := NewRelyingParty(in)
		if err != nil || got.ID != want.ID || got.Origin != want.Origin || !got.Enabled() {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "http://console.example.com", "ftp://console.example.com", "https://user@console.example.com", "://"} {
		if rp, err := NewRelyingParty(in); !errors.Is(err, ErrNotConfigured) || rp.Enabled() {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestRegisterAndAssert(t *testing.T) {
	rp := testRP(t)
	for _, alg := range []int{wt.ES256, wt.EdDSA} {
		a := wt.New(alg)
		c := challenge()
		cd, att := a.Register(rp.ID, rp.Origin, c)
		reg, err := rp.VerifyRegistration(c, cd, att)
		if err != nil {
			t.Fatalf("alg %d: %v", alg, err)
		}
		if reg.Alg != alg || !bytes.Equal(reg.CredentialID, a.ID) || !bytes.Equal(reg.PublicKey, a.COSE()) || !reg.UserVerified {
			t.Fatalf("alg %d: %+v", alg, reg)
		}
		c = challenge()
		cd, ad, sig := a.Assert(rp.ID, rp.Origin, c)
		got, err := rp.VerifyAssertion(c, reg.PublicKey, cd, ad, sig)
		if err != nil || got.SignCount != 1 || got.UserVerified {
			t.Fatalf("alg %d: %+v %v", alg, got, err)
		}
	}
}

// TestRegistrationRefused covers each condition a registration is refused for.
func TestRegistrationRefused(t *testing.T) {
	rp := testRP(t)
	a := wt.New(wt.ES256)
	c := challenge()
	good := wt.ClientData("webauthn.create", c, rp.Origin)
	data := a.RegistrationData(rp.ID, wt.FlagUP)
	rsa := wt.Map(wt.Int(1), wt.Int(3), wt.Int(3), wt.Int(-257), wt.Int(-1), wt.Bytes(make([]byte, 256)), wt.Int(-2), wt.Bytes([]byte{1, 0, 1}))
	withKey := func(key []byte) []byte {
		ad := wt.Header(rp.ID, wt.FlagUP|wt.FlagAT, 0)
		ad = append(ad, make([]byte, 16)...)
		ad = binary.BigEndian.AppendUint16(ad, 4)
		return append(append(ad, 1, 2, 3, 4), key...)
	}
	offCurve := wt.Map(wt.Int(1), wt.Int(2), wt.Int(3), wt.Int(-7), wt.Int(-1), wt.Int(1), wt.Int(-2), wt.Bytes(make([]byte, 32)), wt.Int(-3), wt.Bytes(make([]byte, 32)))
	longID := wt.Header(rp.ID, wt.FlagUP|wt.FlagAT, 0)
	longID = append(longID, make([]byte, 16)...)
	longID = binary.BigEndian.AppendUint16(longID, 1024)
	longID = append(append(longID, make([]byte, 1024)...), a.COSE()...)
	cases := []struct {
		name       string
		clientData []byte
		att        []byte
		want       error
	}{
		{"type", wt.ClientData("webauthn.get", c, rp.Origin), wt.Attest(data), ErrType},
		{"challenge", wt.ClientData("webauthn.create", challenge(), rp.Origin), wt.Attest(data), ErrChallenge},
		{"origin", wt.ClientData("webauthn.create", c, "https://evil.example.com"), wt.Attest(data), ErrOrigin},
		{"cross origin", []byte(strings.Replace(string(good), `"crossOrigin":false`, `"crossOrigin":true`, 1)), wt.Attest(data), ErrOrigin},
		{"client data not JSON", []byte("{"), wt.Attest(data), ErrMalformed},
		{"client data too big", append(good[:len(good)-1], []byte(`,"x":"`+strings.Repeat("a", MaxClientData)+`"}`)...), wt.Attest(data), ErrMalformed},
		{"relying party", good, wt.Attest(a.RegistrationData("evil.example.com", wt.FlagUP)), ErrRelyingParty},
		{"user not present", good, wt.Attest(a.RegistrationData(rp.ID, 0)), ErrUserPresence},
		{"backup state without eligibility", good, wt.Attest(a.RegistrationData(rp.ID, wt.FlagUP|wt.FlagBS)), ErrMalformed},
		{"no credential", good, wt.Attest(wt.Header(rp.ID, wt.FlagUP, 0)), ErrMalformed},
		{"credential ID too long", good, wt.Attest(longID), ErrMalformed},
		{"trailing bytes", good, wt.Attest(append(data, 0)), ErrMalformed},
		{"extensions flag without extensions", good, wt.Attest(a.RegistrationData(rp.ID, wt.FlagUP|wt.FlagED)), ErrMalformed},
		{"RSA key", good, wt.Attest(withKey(rsa)), ErrUnsupported},
		{"point off the curve", good, wt.Attest(withKey(offCurve)), ErrUnsupported},
		{"none with a statement", good, wt.Map(wt.Text("fmt"), wt.Text("none"), wt.Text("attStmt"), wt.Map(wt.Text("alg"), wt.Int(-7)), wt.Text("authData"), wt.Bytes(data)), ErrMalformed},
		{"no authData", good, wt.Map(wt.Text("fmt"), wt.Text("none"), wt.Text("attStmt"), wt.Map()), ErrMalformed},
		{"attestation not CBOR", good, []byte{0xff}, ErrMalformed},
		{"attestation trailing bytes", good, append(wt.Attest(data), 0), ErrMalformed},
		{"attestation too big", good, wt.Map(wt.Text("x"), wt.Bytes(make([]byte, MaxAttestation))), ErrMalformed},
	}
	for _, tc := range cases {
		if _, err := rp.VerifyRegistration(c, tc.clientData, tc.att); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	// Extensions after the key are read and must be a map.
	ext := append(a.RegistrationData(rp.ID, wt.FlagUP|wt.FlagED), wt.Map(wt.Text("credProtect"), wt.Int(2))...)
	if _, err := rp.VerifyRegistration(c, good, wt.Attest(ext)); err != nil {
		t.Errorf("extensions: %v", err)
	}
	// A browser that keeps a self attestation is not refused for it: the statement is skipped.
	packed := wt.Map(wt.Text("fmt"), wt.Text("packed"), wt.Text("attStmt"), wt.Map(wt.Text("alg"), wt.Int(-7), wt.Text("sig"), wt.Bytes([]byte{1})), wt.Text("authData"), wt.Bytes(data))
	if _, err := rp.VerifyRegistration(c, good, packed); err != nil {
		t.Errorf("packed: %v", err)
	}
}

// TestAssertionRefused covers each condition a sign-in is refused for.
func TestAssertionRefused(t *testing.T) {
	rp := testRP(t)
	a := wt.New(wt.ES256)
	other := wt.New(wt.ES256)
	c := challenge()
	signed := func(ad, cd []byte) []byte { return a.Sign(ad, cd) }
	good := wt.ClientData("webauthn.get", c, rp.Origin)
	head := wt.Header(rp.ID, wt.FlagUP, 7)
	cases := []struct {
		name           string
		cd, ad, sig, k []byte
		want           error
	}{
		{"type", wt.ClientData("webauthn.create", c, rp.Origin), head, nil, nil, ErrType},
		{"challenge", wt.ClientData("webauthn.get", challenge(), rp.Origin), head, nil, nil, ErrChallenge},
		{"origin", wt.ClientData("webauthn.get", c, "https://console.example.com.evil.test"), head, nil, nil, ErrOrigin},
		{"relying party", good, wt.Header("example.com", wt.FlagUP, 7), nil, nil, ErrRelyingParty},
		{"user not present", good, wt.Header(rp.ID, wt.FlagUV, 7), nil, nil, ErrUserPresence},
		{"credential data at sign-in", good, a.RegistrationData(rp.ID, wt.FlagUP), nil, nil, ErrMalformed},
		{"short authenticator data", good, head[:36], nil, nil, ErrMalformed},
		{"signature by another key", good, head, other.Sign(head, good), nil, ErrSignature},
		{"signature over other client data", good, head, signed(head, wt.ClientData("webauthn.get", challenge(), rp.Origin)), nil, ErrSignature},
		{"signature over other authenticator data", good, head, signed(wt.Header(rp.ID, wt.FlagUP, 8), good), nil, ErrSignature},
		{"no signature", good, head, []byte{}, nil, ErrSignature},
		{"signature too long", good, head, make([]byte, MaxSignature+1), nil, ErrSignature},
		{"stored key unreadable", good, head, signed(head, good), []byte{0xa0, 0}, ErrUnsupported},
	}
	for _, tc := range cases {
		key := tc.k
		if key == nil {
			key = a.COSE()
		}
		sig := tc.sig
		if sig == nil {
			sig = signed(tc.ad, tc.cd)
		}
		if _, err := rp.VerifyAssertion(c, key, tc.cd, tc.ad, sig); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	// An Ed25519 signature of the wrong size is refused before verification.
	ed := wt.New(wt.EdDSA)
	if _, err := rp.VerifyAssertion(c, ed.COSE(), good, head, ed.Sign(head, good)[:63]); !errors.Is(err, ErrSignature) {
		t.Errorf("short Ed25519 signature: %v", err)
	}
}

func TestCBORLimits(t *testing.T) {
	deep := []byte{}
	for range maxDepth + 2 {
		deep = append(deep, 0x81)
	}
	deep = append(deep, 0)
	many := wt.Head(4, maxItems+1)
	for range maxItems + 1 {
		many = append(many, 0)
	}
	for name, in := range map[string][]byte{
		"empty":               {},
		"too deep":            deep,
		"too many items":      many,
		"indefinite length":   {0x5f, 0x41, 0, 0xff},
		"reserved info":       {0x1c},
		"short argument":      {0x19, 1},
		"bytes past the end":  {0x5a, 0xff, 0xff, 0xff, 0xff, 1},
		"count past the end":  {0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"tag":                 {0xc0, 0},
		"float":               {0xf9, 0, 0},
		"undefined":           {0xf7},
		"uint over int64":     {0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0},
		"negint over int64":   {0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0},
		"duplicate int key":   wt.Map(wt.Int(1), wt.Int(1), wt.Int(1), wt.Int(2)),
		"duplicate text key":  wt.Map(wt.Text("a"), wt.Int(1), wt.Text("a"), wt.Int(2)),
		"byte string map key": wt.Map(wt.Bytes([]byte{1}), wt.Int(1)),
	} {
		if _, _, err := decodeCBOR(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	v, rest, err := decodeCBOR(append(wt.Map(wt.Text("t"), []byte{0xf5}, wt.Int(-3), []byte{0xf6}), 9))
	if err != nil || len(rest) != 1 || v.kind != kindMap {
		t.Fatalf("%+v %v %v", v, rest, err)
	}
	if b, ok := v.field("t"); !ok || b.kind != kindSimple || b.int != 21 {
		t.Errorf("true: %+v", b)
	}
	if _, ok := v.get(-3); !ok {
		t.Error("negative key not found")
	}
}

func FuzzDecodeCBOR(f *testing.F) {
	a := wt.New(wt.ES256)
	f.Add(a.COSE())
	f.Add(wt.Attest(a.RegistrationData("console.example.com", wt.FlagUP)))
	f.Add([]byte{0x9f, 0xff})
	f.Fuzz(func(t *testing.T, in []byte) {
		v, rest, err := decodeCBOR(in)
		if err != nil {
			return
		}
		if len(rest) > len(in) || countItems(v) > maxItems {
			t.Fatalf("decoded past the limits: %d items", countItems(v))
		}
	})
}

func countItems(v value) int {
	n := 1
	for _, k := range v.keys {
		n += countItems(k)
	}
	for _, e := range v.items {
		n += countItems(e)
	}
	return n
}

func FuzzParsePublicKey(f *testing.F) {
	f.Add(wt.New(wt.ES256).COSE())
	f.Add(wt.New(wt.EdDSA).COSE())
	f.Fuzz(func(t *testing.T, in []byte) {
		k, err := ParsePublicKey(in)
		if err == nil && k.Alg != AlgES256 && k.Alg != AlgEdDSA {
			t.Fatalf("algorithm %d accepted", k.Alg)
		}
	})
}

func FuzzVerifyRegistration(f *testing.F) {
	rp := testRP(f)
	c := make([]byte, ChallengeSize)
	a := wt.New(wt.ES256)
	_, att := a.Register(rp.ID, rp.Origin, c)
	f.Add(att)
	f.Add(wt.Attest(append(a.RegistrationData(rp.ID, wt.FlagUP|wt.FlagED), wt.Map(wt.Text("credProtect"), wt.Int(2))...)))
	cd := wt.ClientData("webauthn.create", c, rp.Origin)
	f.Fuzz(func(t *testing.T, att []byte) {
		reg, err := rp.VerifyRegistration(c, cd, att)
		if err != nil {
			return
		}
		if len(reg.CredentialID) == 0 || len(reg.CredentialID) > MaxCredentialID {
			t.Fatalf("credential ID of %d bytes accepted", len(reg.CredentialID))
		}
		if _, err := ParsePublicKey(reg.PublicKey); err != nil {
			t.Fatalf("stored key does not parse: %v", err)
		}
	})
}

func FuzzVerifyAssertion(f *testing.F) {
	rp := testRP(f)
	c := make([]byte, ChallengeSize)
	a := wt.New(wt.ES256)
	cd, ad, sig := a.Assert(rp.ID, rp.Origin, c)
	f.Add(ad, sig)
	key := a.COSE()
	f.Fuzz(func(t *testing.T, ad, sig []byte) {
		got, err := rp.VerifyAssertion(c, key, cd, ad, sig)
		// Only the signed seed can pass: anything else the fuzzer makes is a forgery.
		if err == nil && len(ad) != 37 {
			t.Fatalf("assertion with %d trailing bytes accepted: %+v", len(ad)-37, got)
		}
	})
}
