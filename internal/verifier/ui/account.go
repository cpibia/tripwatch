package ui

import (
	"errors"
	"net/http"
	"net/url"

	"rsc.io/qr"

	"github.com/cpibia/tripwatch/internal/verifier/store"
	"github.com/cpibia/tripwatch/internal/verifier/webauthn"
)

type accountData struct {
	Email string
	Role  string
	// Factor is set when any second factor is on, TOTP when the authenticator app is.
	Factor   bool
	TOTP     bool
	Codes    int
	Keys     []store.SecurityKey
	KeysOff  bool
	MaxKeys  int
	Sessions []store.SessionInfo
	// Confirmed is set while the session may change the second factors: it proved one of them
	// again in the last few minutes, or there is none yet.
	Confirmed bool
	// Register and Confirm are the security key prompts of the page: adding a key, and
	// confirming it is the user with one.
	Register *keyPrompt
	Confirm  *keyPrompt
	// Setup is the secret being set up, shown as text beside its QR code; Recovery the new
	// recovery codes, shown once.
	Setup    string
	Recovery []string
	Error    string
	Notice   string
}

// account is the signed-in user's own page: second factors and sessions.
func (s *server) account(w http.ResponseWriter, r *http.Request, se session) {
	s.renderAccount(w, r, se, http.StatusOK, accountData{})
}

func (s *server) renderAccount(w http.ResponseWriter, r *http.Request, se session, status int, d accountData) {
	ctx := r.Context()
	var err error
	d.Email, d.Role, d.KeysOff, d.MaxKeys = se.Email, se.Role, !s.rp.Enabled(), store.MaxSecurityKeys
	if d.TOTP, err = s.Store.TOTPEnabled(ctx, se.Email); err == nil {
		d.Factor, err = s.Store.SecondFactorEnabled(ctx, se.Email)
	}
	if err == nil {
		d.Codes, err = s.Store.RecoveryCodesLeft(ctx, se.Email)
	}
	if err == nil {
		d.Keys, err = s.Store.SecurityKeys(ctx, se.Email)
	}
	if err == nil {
		d.Confirmed, err = s.mayChangeFactors(r, se)
	}
	if err == nil {
		d.Sessions, err = s.Store.UserSessions(ctx, se.Email, se.token, s.Now())
	}
	if err == nil && d.Recovery == nil {
		if d.Confirmed && len(d.Keys) < store.MaxSecurityKeys {
			d.Register, err = s.keyPrompt(ctx, se.Email, se.token, store.PurposeRegister)
		}
		if err == nil && !d.Confirmed {
			d.Confirm, err = s.keyPrompt(ctx, se.Email, se.token, store.PurposeAssert)
		}
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.render(w, r, status, "account", page{Title: "Account", Nav: "account", User: se.Email, CSRF: se.csrf(), Keys: d.Register != nil || d.Confirm != nil, Data: d})
}

// mayChangeFactors reports whether a session may add or remove second factors: a session alone
// must not be enough to move them to another phone or key, so once one is on, the user proves
// it again first.
func (s *server) mayChangeFactors(r *http.Request, se session) (bool, error) {
	on, err := s.Store.SecondFactorEnabled(r.Context(), se.Email)
	if err != nil || !on {
		return !on, err
	}
	return s.Store.SessionConfirmed(r.Context(), se.token, s.Now())
}

const confirmFirst = "Confirm it is you first, with a code or a security key: changing the second factor takes it."

// accountAction sets the second factors up or off, and ends sessions.
func (s *server) accountAction(w http.ResponseWriter, r *http.Request, se session) {
	ctx := r.Context()
	action := r.PathValue("action")
	switch action {
	case "2fa-begin", "key-add", "key-remove":
		ok, err := s.mayChangeFactors(r, se)
		if err != nil {
			s.internal(w, r, err)
			return
		}
		if !ok {
			s.renderAccount(w, r, se, http.StatusForbidden, accountData{Error: confirmFirst})
			return
		}
	}
	switch action {
	case "confirm":
		s.confirmFactor(w, r, se)
	case "2fa-begin":
		// Replacing the app goes through turning it off: the new secret must not silently take
		// the old one's place.
		if on, err := s.Store.TOTPEnabled(ctx, se.Email); err != nil || on {
			s.renderAccount(w, r, se, http.StatusConflict, accountData{Error: "The authenticator app is on already: turn it off first."})
			return
		}
		secret, err := s.Store.BeginTOTP(ctx, se.Email)
		if err != nil {
			s.internal(w, r, err)
			return
		}
		s.renderAccount(w, r, se, http.StatusOK, accountData{Setup: secret})
	case "2fa-confirm":
		codes, err := s.Store.ConfirmTOTP(ctx, se.Email, r.PostFormValue("code"), s.Now())
		if errors.Is(err, store.ErrBadCode) {
			secret, _ := s.Store.PendingTOTP(ctx, se.Email)
			s.renderAccount(w, r, se, http.StatusBadRequest, accountData{Setup: secret, Error: "That code does not match: check the app's clock and type the code it shows now."})
			return
		}
		if err != nil {
			s.internal(w, r, err)
			return
		}
		s.audit(r, se, "second factor turned on", se.Email, "authenticator app")
		s.factorAdded(r, se)
		d := accountData{Recovery: codes}
		if codes == nil {
			d.Notice = "The authenticator app is on, next to your security keys."
		}
		s.renderAccount(w, r, se, http.StatusOK, d)
	case "2fa-off":
		ok, err := s.Store.SessionConfirmed(ctx, se.token, s.Now())
		if err != nil {
			s.internal(w, r, err)
			return
		}
		if !ok {
			if err := s.Store.CheckSecondFactor(ctx, se.Email, r.PostFormValue("code"), s.Now()); err != nil {
				if !refused(err) && !errors.Is(err, store.ErrSecondFactorLocked) {
					s.internal(w, r, err)
					return
				}
				msg := "Give a current code from your app, or a recovery code, to turn the authenticator app off."
				if errors.Is(err, store.ErrSecondFactorLocked) {
					msg = lockedMessage
				}
				s.renderAccount(w, r, se, http.StatusBadRequest, accountData{Error: msg})
				return
			}
		}
		if err := s.Store.DisableTOTP(ctx, se.Email); err != nil {
			s.internal(w, r, err)
			return
		}
		s.audit(r, se, "second factor turned off", se.Email, "authenticator app")
		notice := "The second factor is off: signing in takes the password only."
		if on, _ := s.Store.SecondFactorEnabled(ctx, se.Email); on {
			notice = "The authenticator app is off: your security keys still guard the sign-in."
		}
		s.renderAccount(w, r, se, http.StatusOK, accountData{Notice: notice})
	case "key-add":
		s.addKey(w, r, se)
	case "key-remove":
		name, err := s.Store.RemoveSecurityKey(ctx, se.Email, r.PostFormValue("id"))
		if errors.Is(err, store.ErrNotFound) {
			http.Redirect(w, r, "/account", http.StatusSeeOther)
			return
		}
		if err != nil {
			s.internal(w, r, err)
			return
		}
		s.audit(r, se, "security key removed", se.Email, name)
		s.renderAccount(w, r, se, http.StatusOK, accountData{Notice: "The key " + name + " is removed: it no longer signs in."})
	case "end-session":
		// Only a session that existed is recorded: anyone signed in could otherwise flood the
		// audit log with made-up IDs and push older entries out.
		switch err := s.Store.EndSession(ctx, se.Email, r.PostFormValue("id")); {
		case err == nil:
			s.audit(r, se, "session ended", se.Email, "")
		case !errors.Is(err, store.ErrNotFound):
			s.internal(w, r, err)
			return
		}
		http.Redirect(w, r, "/account", http.StatusSeeOther)
	default:
		s.fail(w, r, http.StatusNotFound, "Unknown action", "This action does not exist.")
	}
}

// confirmFactor lets a session change the second factors for a few minutes once it proves one
// of them again, with a code or a key. Wrong answers spend the attempts sign-ins spend.
func (s *server) confirmFactor(w http.ResponseWriter, r *http.Request, se session) {
	ctx := r.Context()
	var err error
	if r.PostFormValue("credential") != "" {
		var name string
		if name, err = s.checkKey(r, se.Email, se.token); refused(err) {
			s.auditKeyRefusal(ctx, se.Email, se.Email, name, err)
		}
	} else {
		err = s.Store.CheckSecondFactor(ctx, se.Email, r.PostFormValue("code"), s.Now())
	}
	switch {
	case errors.Is(err, store.ErrSecondFactorLocked):
		s.renderAccount(w, r, se, http.StatusTooManyRequests, accountData{Error: lockedMessage})
		return
	case refused(err):
		s.renderAccount(w, r, se, http.StatusBadRequest, accountData{Error: "That did not confirm it is you: give a current code, a recovery code, or use one of your keys."})
		return
	case err != nil:
		s.internal(w, r, err)
		return
	}
	if err := s.Store.ConfirmSession(ctx, se.token, s.Now()); err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r, se, "second factor confirmed", se.Email, "to change the second factors")
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

// addKey stores the key webauthn.js registered.
func (s *server) addKey(w http.ResponseWriter, r *http.Request, se session) {
	if !s.rp.Enabled() {
		s.fail(w, r, http.StatusNotFound, "Security keys off", "Security keys need the console's public HTTPS address in TRIPWATCH_PUBLIC_UI_URL.")
		return
	}
	name := store.KeyName(r.PostFormValue("name"))
	codes, err := s.Store.AddSecurityKey(r.Context(), s.rp, se.Email, se.token, name, r.PostFormValue("transports"),
		formBytes(r, "clientData"), formBytes(r, "attestation"), s.Now())
	msg := ""
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNoChallenge):
		msg = "The key prompt expired, or was answered from another page: try again."
	case errors.Is(err, store.ErrKeyExists):
		msg = "That key is registered already."
	case errors.Is(err, store.ErrTooManyKeys):
		msg = "That is as many keys as an account may hold: remove one first."
	case errors.Is(err, webauthn.ErrUnsupported):
		msg = "That key offers no algorithm the console accepts (ES256 or Ed25519)."
	case errors.Is(err, store.ErrKeyRefused):
		msg = "The key's answer was refused: try again from this page."
	default:
		s.internal(w, r, err)
		return
	}
	if msg != "" {
		s.renderAccount(w, r, se, http.StatusBadRequest, accountData{Error: msg})
		return
	}
	s.audit(r, se, "security key added", se.Email, name)
	s.factorAdded(r, se)
	d := accountData{Recovery: codes}
	if codes == nil {
		d.Notice = "The key " + name + " is added: it signs in from now on."
	}
	s.renderAccount(w, r, se, http.StatusOK, d)
}

// factorAdded follows a new second factor: the session that set it up just proved it, and the
// other sessions, opened without it, end.
func (s *server) factorAdded(r *http.Request, se session) {
	if err := s.Store.ConfirmSession(r.Context(), se.token, s.Now()); err != nil {
		s.Log.Error("confirm session", "err", err)
	}
	if err := s.Store.EndOtherSessions(r.Context(), se.Email, se.token); err != nil {
		s.Log.Error("end other sessions", "err", err)
	}
}

// totpQR draws the secret being set up as a QR code for authenticator apps. It is served by the
// verifier, as images must be under the page's policy, and only to the user setting it up.
func (s *server) totpQR(w http.ResponseWriter, r *http.Request, se session) {
	secret, err := s.Store.PendingTOTP(r.Context(), se.Email)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	uri := (&url.URL{Scheme: "otpauth", Host: "totp", Path: "/tripwatch:" + se.Email,
		RawQuery: url.Values{"secret": {secret}, "issuer": {"tripwatch"}, "digits": {"6"}, "period": {"30"}}.Encode()}).String()
	code, err := qr.Encode(uri, qr.M)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	code.Scale = 6
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(code.PNG())
}

type secondFactorData struct {
	Next, Error string
	// App is set when the user has an authenticator app; Key is the prompt of their keys.
	App bool
	Key *keyPrompt
}

// secondFactorForm asks the second factor of a session that gave its password.
func (s *server) secondFactorForm(w http.ResponseWriter, r *http.Request) {
	email, ok := s.halfOpen(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderSecondFactor(w, r, http.StatusOK, email, secondFactorData{Next: localPath(r.URL.Query().Get("next"), "/")})
}

// renderSecondFactor shows the sign-in's second step with a fresh key prompt: the one shown
// before was spent by the answer that brought the page back.
func (s *server) renderSecondFactor(w http.ResponseWriter, r *http.Request, status int, email string, d secondFactorData) {
	c, _ := r.Cookie(sessionCookie)
	var err error
	if d.App, err = s.Store.TOTPEnabled(r.Context(), email); err == nil {
		d.Key, err = s.keyPrompt(r.Context(), email, c.Value, store.PurposeAssert)
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.render(w, r, status, "secondfactor", page{Title: "Second factor", Keys: d.Key != nil, Data: d})
}

func (s *server) secondFactor(w http.ResponseWriter, r *http.Request) {
	// A key's answer is a few kilobytes at most; the code alone is far less.
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	email, ok := s.halfOpen(r)
	if !ok || !sameOrigin(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	next := localPath(r.PostFormValue("next"), "/")
	c, _ := r.Cookie(sessionCookie)
	key := r.PostFormValue("credential") != ""
	var err error
	name := ""
	if key {
		name, err = s.checkKey(r, email, c.Value)
	} else {
		err = s.Store.CheckSecondFactor(r.Context(), email, r.PostFormValue("code"), s.Now())
	}
	if errors.Is(err, store.ErrSecondFactorLocked) {
		s.renderSecondFactor(w, r, http.StatusTooManyRequests, email, secondFactorData{Next: next, Error: lockedMessage})
		return
	}
	if refused(err) {
		s.Log.Warn("wrong second factor", "email", email)
		msg := "Wrong code. After a few wrong codes the password is asked again."
		if key {
			s.auditKeyRefusal(r.Context(), email, email, name, err)
			msg = "The security key was refused. After a few refusals the password is asked again."
		} else if aerr := s.Store.Audit(r.Context(), email, "wrong second factor code", "", "", s.Now()); aerr != nil {
			s.Log.Error("audit", "err", aerr)
		}
		alive, ferr := s.Store.FailSecondFactor(r.Context(), c.Value)
		if ferr != nil || !alive {
			s.cookie(w, sessionCookie, "", -1)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		s.renderSecondFactor(w, r, http.StatusUnauthorized, email, secondFactorData{Next: next, Error: msg})
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if err := s.Store.CompleteSecondFactor(r.Context(), c.Value); err != nil {
		s.internal(w, r, err)
		return
	}
	detail := ""
	if key {
		detail = "with the security key " + name
	}
	if err := s.Store.Audit(r.Context(), email, "second factor given", "", detail, s.Now()); err != nil {
		s.Log.Error("audit", "err", err)
	}
	// The browser becomes a known one, with a sign-in lane of its own, only once the second
	// factor checked out: the password alone must not buy a way around the email's lane.
	s.rememberDevice(w, r, email)
	http.Redirect(w, r, next, http.StatusSeeOther) //nolint:gosec // next went through localPath
}

// lockedMessage tells a user their second factor is locked, without saying for how long exactly.
const lockedMessage = "Too many wrong codes or keys: they are refused for a while. Try again in 15 minutes, or ask an administrator to reset your second factor."

// halfOpen returns the user of a session that gave its password and waits for its code.
func (s *server) halfOpen(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	email, err := s.Store.Session(r.Context(), c.Value, s.Now())
	return email, errors.Is(err, store.ErrSecondFactorRequired)
}
