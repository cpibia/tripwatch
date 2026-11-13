package ui

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// keyPrompt is what webauthn.js needs to ask the browser for a security key, rendered as data
// attributes of the form that posts the answer.
type keyPrompt struct {
	Challenge string
	RPID      string
	// Keys is the JSON list of the user's credentials: the ones a sign-in may use, or the ones a
	// registration must not create again on the same authenticator.
	Keys string
	// User is the handle a new credential is stored under on the authenticator. It is random:
	// sign-in names the user by email, never by handle, and the handle must not identify them.
	User string
}

// keyPrompt makes a session's challenge for a purpose. A sign-in prompt is nil for a user with
// no key, and every prompt is nil while keys are off.
func (s *server) keyPrompt(ctx context.Context, email, token, purpose string) (*keyPrompt, error) {
	if !s.rp.Enabled() {
		return nil, nil
	}
	refs, err := s.Store.SecurityKeyRefs(ctx, email)
	if err != nil {
		return nil, err
	}
	if purpose == store.PurposeAssert && len(refs) == 0 {
		return nil, nil
	}
	if refs == nil {
		refs = []store.KeyRef{}
	}
	keys, err := json.Marshal(refs)
	if err != nil {
		return nil, err
	}
	c, err := s.Store.NewChallenge(ctx, token, purpose, s.Now())
	if err != nil {
		return nil, err
	}
	p := &keyPrompt{Challenge: base64.RawURLEncoding.EncodeToString(c), RPID: s.rp.ID, Keys: string(keys)}
	if purpose == store.PurposeRegister {
		handle := make([]byte, 16)
		if _, err := rand.Read(handle); err != nil {
			return nil, err
		}
		p.User = base64.RawURLEncoding.EncodeToString(handle)
	}
	return p, nil
}

// formBytes decodes a base64url field webauthn.js filled. A field that does not decode is empty,
// and the checks refuse it like any other wrong answer.
func formBytes(r *http.Request, name string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(r.PostFormValue(name))
	return b
}

// checkKey checks a security key's answer to a session's sign-in prompt, posted by webauthn.js,
// and returns the key's name.
func (s *server) checkKey(r *http.Request, email, token string) (string, error) {
	return s.Store.CheckSecurityKey(r.Context(), s.rp, email, token, formBytes(r, "credential"), formBytes(r, "clientData"),
		formBytes(r, "authenticatorData"), formBytes(r, "signature"), s.Now())
}

// refused reports whether a second factor was wrong, as opposed to the database failing.
func refused(err error) bool {
	return errors.Is(err, store.ErrBadCode) || errors.Is(err, store.ErrNoChallenge) ||
		errors.Is(err, store.ErrClonedKey) || errors.Is(err, store.ErrKeyRefused)
}

// auditKeyRefusal records a refused key answer. A counter that went back is the one trace a
// copied key leaves, so it gets an entry of its own.
func (s *server) auditKeyRefusal(ctx context.Context, actor, email, name string, err error) {
	action, detail := "security key refused", ""
	if errors.Is(err, store.ErrClonedKey) {
		s.Log.Warn("security key counter went back", "email", email, "key", name)
		action, detail = "possible cloned security key", name+": its signature counter did not go forward"
	}
	if aerr := s.Store.Audit(ctx, actor, action, email, detail, s.Now()); aerr != nil {
		s.Log.Error("audit", "err", aerr)
	}
}
