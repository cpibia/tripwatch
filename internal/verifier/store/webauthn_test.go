package store

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/webauthn"
	wt "github.com/cpibia/tripwatch/internal/verifier/webauthn/webauthntest"
)

const keyUser = "keys@example.net"

func keyStore(t *testing.T) (*Store, webauthn.RelyingParty) {
	t.Helper()
	s := open(t)
	if err := s.SetUser(context.Background(), keyUser, "a long enough password", t0); err != nil {
		t.Fatal(err)
	}
	rp, err := webauthn.NewRelyingParty("https://console.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return s, rp
}

// addKey registers a key for keyUser through the prompt of a setup session.
func addKey(t *testing.T, s *Store, rp webauthn.RelyingParty, a *wt.Authenticator, at time.Time) []string {
	t.Helper()
	ctx := context.Background()
	c, err := s.NewChallenge(ctx, "setup", PurposeRegister, at)
	if err != nil {
		t.Fatal(err)
	}
	cd, att := a.Register(rp.ID, rp.Origin, c)
	codes, err := s.AddSecurityKey(ctx, rp, keyUser, "setup", "  my\tkey  ", "usb,nfc,bogus,usb", cd, att, at)
	if err != nil {
		t.Fatal(err)
	}
	return codes
}

// signIn answers a session's sign-in prompt with a key.
func signIn(s *Store, rp webauthn.RelyingParty, token string, a *wt.Authenticator, at time.Time) error {
	ctx := context.Background()
	c, err := s.NewChallenge(ctx, token, PurposeAssert, at)
	if err != nil {
		return err
	}
	cd, ad, sig := a.Assert(rp.ID, rp.Origin, c)
	_, err = s.CheckSecurityKey(ctx, rp, keyUser, token, a.ID, cd, ad, sig, at)
	return err
}

// A key turns the second factor on by itself, with recovery codes; sign-ins then wait for it;
// the key answers once per prompt; removing the last key takes the codes with it.
func TestSecurityKeys(t *testing.T) {
	s, rp := keyStore(t)
	ctx := context.Background()
	a := wt.New(wt.ES256)
	codes := addKey(t, s, rp, a, t0)
	if len(codes) != recoveryCodes {
		t.Fatalf("first factor gave %d codes", len(codes))
	}
	if on, err := s.SecondFactorEnabled(ctx, keyUser); err != nil || !on {
		t.Fatalf("enabled: %v %v", on, err)
	}
	if on, _ := s.TOTPEnabled(ctx, keyUser); on {
		t.Fatal("a key turned the app on")
	}
	keys, err := s.SecurityKeys(ctx, keyUser)
	if err != nil || len(keys) != 1 || keys[0].Name != "my key" || keys[0].Alg != wt.ES256 || !keys[0].UserVerified {
		t.Fatalf("keys: %+v %v", keys, err)
	}
	refs, err := s.SecurityKeyRefs(ctx, keyUser)
	if err != nil || len(refs) != 1 || refs[0].ID != base64.RawURLEncoding.EncodeToString(a.ID) || len(refs[0].Transports) != 2 {
		t.Fatalf("refs: %+v %v", refs, err)
	}

	// A second key, an Ed25519 one, adds no codes.
	b := wt.New(wt.EdDSA)
	if codes := addKey(t, s, rp, b, t0); codes != nil {
		t.Fatal("second key replaced the codes")
	}

	at := t0.Add(time.Hour)
	token, err := s.Login(ctx, keyUser, "a long enough password", at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, token, at); !errors.Is(err, ErrSecondFactorRequired) {
		t.Fatalf("session before the key: %v", err)
	}
	if err := signIn(s, rp, token, b, at); err != nil {
		t.Fatalf("Ed25519 sign-in: %v", err)
	}
	if err := signIn(s, rp, token, a, at); err != nil {
		t.Fatalf("ES256 sign-in: %v", err)
	}
	keys, _ = s.SecurityKeys(ctx, keyUser)
	if !keys[0].LastUsed.Equal(at) || keys[0].UserVerified {
		t.Fatalf("use not recorded: %+v", keys[0])
	}

	// The prompt is spent by the first answer, whatever it was.
	c, _ := s.NewChallenge(ctx, token, PurposeAssert, at)
	cd, ad, sig := a.Assert(rp.ID, rp.Origin, c)
	if _, err := s.CheckSecurityKey(ctx, rp, keyUser, token, a.ID, cd, ad, sig, at); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckSecurityKey(ctx, rp, keyUser, token, a.ID, cd, ad, sig, at); !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("replayed answer: %v", err)
	}

	if _, err := s.RemoveSecurityKey(ctx, keyUser, "not base64!"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}
	if name, err := s.RemoveSecurityKey(ctx, keyUser, base64.RawURLEncoding.EncodeToString(a.ID)); err != nil || name != "my key" {
		t.Fatalf("remove: %q %v", name, err)
	}
	if n, _ := s.RecoveryCodesLeft(ctx, keyUser); n != recoveryCodes {
		t.Fatalf("codes dropped with a key left: %d", n)
	}
	if _, err := s.RemoveSecurityKey(ctx, keyUser, base64.RawURLEncoding.EncodeToString(b.ID)); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.RecoveryCodesLeft(ctx, keyUser); n != 0 {
		t.Fatalf("codes kept with no factor: %d", n)
	}
	if on, _ := s.SecondFactorEnabled(ctx, keyUser); on {
		t.Fatal("still on")
	}
}

// Each condition a key answer is refused for, as the store checks it.
func TestSecurityKeyRefused(t *testing.T) {
	s, rp := keyStore(t)
	ctx := context.Background()
	a := wt.New(wt.ES256)
	addKey(t, s, rp, a, t0)

	// The same credential cannot be registered twice.
	c, _ := s.NewChallenge(ctx, "setup", PurposeRegister, t0)
	cd, att := a.Register(rp.ID, rp.Origin, c)
	if _, err := s.AddSecurityKey(ctx, rp, keyUser, "setup", "", "", cd, att, t0); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("twice: %v", err)
	}
	// A prompt of another session, or an expired one, does not count.
	c, _ = s.NewChallenge(ctx, "other", PurposeRegister, t0)
	cd, att = wt.New(wt.ES256).Register(rp.ID, rp.Origin, c)
	if _, err := s.AddSecurityKey(ctx, rp, keyUser, "setup", "", "", cd, att, t0); !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("other session's prompt: %v", err)
	}
	if _, err := s.AddSecurityKey(ctx, rp, keyUser, "other", "", "", cd, att, t0.Add(ChallengeLifetime)); !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("expired prompt: %v", err)
	}
	// A bad registration is refused by the checks of the webauthn package.
	c, _ = s.NewChallenge(ctx, "setup", PurposeRegister, t0)
	cd, att = wt.New(wt.ES256).Register(rp.ID, "https://evil.example.com", c)
	if _, err := s.AddSecurityKey(ctx, rp, keyUser, "setup", "", "", cd, att, t0); !errors.Is(err, webauthn.ErrOrigin) {
		t.Fatalf("other origin: %v", err)
	}

	at := t0.Add(time.Hour)
	token, _ := s.Login(ctx, keyUser, "a long enough password", at)

	// A key of another user is not this user's.
	if err := signIn(s, rp, token, wt.New(wt.ES256), at); !errors.Is(err, ErrBadCode) {
		t.Fatalf("unknown key: %v", err)
	}
	// An over-long credential ID is refused before the lookup.
	if _, err := s.NewChallenge(ctx, token, PurposeAssert, at); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckSecurityKey(ctx, rp, keyUser, token, make([]byte, webauthn.MaxCredentialID+1), nil, nil, nil, at); !errors.Is(err, ErrBadCode) {
		t.Fatalf("long id: %v", err)
	}
	// A counter that does not go up is a copy of the key.
	if err := signIn(s, rp, token, a, at); err != nil {
		t.Fatal(err)
	}
	a.Count--
	if err := signIn(s, rp, token, a, at); !errors.Is(err, ErrClonedKey) {
		t.Fatalf("counter repeated: %v", err)
	}
	// A key without a counter keeps working.
	a.Count = 0xffffffff
	if err := signIn(s, rp, token, a, at); err != nil {
		t.Fatalf("counter zero: %v", err)
	}
}

// Wrong key answers and wrong codes spend the same attempts and share the lock.
func TestSecurityKeyLock(t *testing.T) {
	s, rp := keyStore(t)
	ctx := context.Background()
	a := wt.New(wt.ES256)
	addKey(t, s, rp, a, t0)
	at := t0.Add(time.Hour)
	token, _ := s.Login(ctx, keyUser, "a long enough password", at)
	for i := range MaxSecondFactorFailures - 1 {
		if err := s.CheckSecondFactor(ctx, keyUser, "000000", at); !errors.Is(err, ErrBadCode) {
			t.Fatalf("wrong code %d: %v", i, err)
		}
	}
	if err := signIn(s, rp, token, wt.New(wt.ES256), at); !errors.Is(err, ErrBadCode) {
		t.Fatalf("wrong key: %v", err)
	}
	if err := signIn(s, rp, token, a, at); !errors.Is(err, ErrSecondFactorLocked) {
		t.Fatalf("right key while locked: %v", err)
	}
	after := at.Add(SecondFactorLock)
	if err := signIn(s, rp, token, a, after); err != nil {
		t.Fatalf("after the lock: %v", err)
	}
}

// Recovery codes belong to the user, not to a factor: they stay while one factor is left, an
// app added next to a key gives none, and an administrator's reset clears everything.
func TestSharedRecoveryCodes(t *testing.T) {
	s, rp := keyStore(t)
	ctx := context.Background()
	addKey(t, s, rp, wt.New(wt.ES256), t0)
	secret, _ := s.BeginTOTP(ctx, keyUser)
	codes, err := s.ConfirmTOTP(ctx, keyUser, codeAt(t, secret, t0), t0)
	if err != nil || codes != nil {
		t.Fatalf("app next to a key: %v %v", codes, err)
	}
	if err := s.DisableTOTP(ctx, keyUser); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.RecoveryCodesLeft(ctx, keyUser); n != recoveryCodes {
		t.Fatalf("codes after the app went, key left: %d", n)
	}
	if on, _ := s.SecondFactorEnabled(ctx, keyUser); !on {
		t.Fatal("key no longer counted")
	}
	if err := s.ResetSecondFactor(ctx, keyUser); err != nil {
		t.Fatal(err)
	}
	keys, _ := s.SecurityKeys(ctx, keyUser)
	n, _ := s.RecoveryCodesLeft(ctx, keyUser)
	if on, _ := s.SecondFactorEnabled(ctx, keyUser); on || len(keys) != 0 || n != 0 {
		t.Fatalf("after reset: on=%v keys=%d codes=%d", on, len(keys), n)
	}
	if err := s.ResetSecondFactor(ctx, "nobody@example.net"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	if err := s.DisableTOTP(ctx, "nobody@example.net"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	if _, err := s.SecondFactorEnabled(ctx, "nobody@example.net"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestSecurityKeysBounded(t *testing.T) {
	s, rp := keyStore(t)
	ctx := context.Background()
	for range MaxSecurityKeys {
		addKey(t, s, rp, wt.New(wt.ES256), t0)
	}
	c, _ := s.NewChallenge(ctx, "setup", PurposeRegister, t0)
	cd, att := wt.New(wt.ES256).Register(rp.ID, rp.Origin, c)
	if _, err := s.AddSecurityKey(ctx, rp, keyUser, "setup", "", "", cd, att, t0); !errors.Is(err, ErrTooManyKeys) {
		t.Fatalf("past the cap: %v", err)
	}
	// Removing the user removes their keys: an account invited again starts without them.
	if err := s.SetUser(ctx, "admin@example.net", "a long enough password", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, keyUser); err != nil {
		t.Fatal(err)
	}
	if keys, _ := s.SecurityKeys(ctx, keyUser); len(keys) != 0 {
		t.Fatalf("%d keys left", len(keys))
	}
}

func TestSessionConfirmed(t *testing.T) {
	s, _ := keyStore(t)
	ctx := context.Background()
	token, _ := s.Login(ctx, keyUser, "a long enough password", t0)
	if ok, err := s.SessionConfirmed(ctx, token, t0); ok || err != nil {
		t.Fatalf("fresh session confirmed: %v %v", ok, err)
	}
	if err := s.ConfirmSession(ctx, token, t0); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.SessionConfirmed(ctx, token, t0.Add(ConfirmWindow)); !ok {
		t.Fatal("not confirmed within the window")
	}
	if ok, _ := s.SessionConfirmed(ctx, token, t0.Add(ConfirmWindow+time.Second)); ok {
		t.Fatal("confirmed past the window")
	}
	if ok, _ := s.SessionConfirmed(ctx, "unknown", t0); ok {
		t.Fatal("unknown session confirmed")
	}
	if err := s.ConfirmSession(ctx, "unknown", t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown session: %v", err)
	}
	if KeyName("") != "Security key" || len(KeyName(string(make([]byte, 100))+"x")) > 60 {
		t.Fatal("key name not bounded")
	}
}
