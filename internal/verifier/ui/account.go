package ui

import (
	"errors"
	"net/http"
	"net/url"

	"rsc.io/qr"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

type accountData struct {
	Email    string
	Role     string
	TOTP     bool
	Codes    int
	Sessions []store.SessionInfo
	// Setup is the secret being set up, shown as text beside its QR code; Recovery the new
	// recovery codes, shown once.
	Setup    string
	Recovery []string
	Error    string
	Notice   string
}

// account is the signed-in user's own page: second factor and sessions.
func (s *server) account(w http.ResponseWriter, r *http.Request, se session) {
	s.renderAccount(w, r, se, http.StatusOK, accountData{})
}

func (s *server) renderAccount(w http.ResponseWriter, r *http.Request, se session, status int, d accountData) {
	ctx := r.Context()
	var err error
	d.Email, d.Role = se.Email, se.Role
	if d.TOTP, err = s.Store.TOTPEnabled(ctx, se.Email); err != nil {
		s.internal(w, r, err)
		return
	}
	if d.Codes, err = s.Store.RecoveryCodesLeft(ctx, se.Email); err != nil {
		s.internal(w, r, err)
		return
	}
	if d.Sessions, err = s.Store.UserSessions(ctx, se.Email, se.token, s.Now()); err != nil {
		s.internal(w, r, err)
		return
	}
	s.render(w, r, status, "account", page{Title: "Account", Nav: "account", User: se.Email, CSRF: se.csrf(), Data: d})
}

// accountAction sets the second factor up or off, and ends sessions.
func (s *server) accountAction(w http.ResponseWriter, r *http.Request, se session) {
	ctx := r.Context()
	switch r.PathValue("action") {
	case "2fa-begin":
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
		s.audit(r, se, "second factor turned on", se.Email, "")
		s.renderAccount(w, r, se, http.StatusOK, accountData{Recovery: codes})
	case "2fa-off":
		if err := s.Store.CheckSecondFactor(ctx, se.Email, r.PostFormValue("code"), s.Now()); err != nil {
			s.renderAccount(w, r, se, http.StatusBadRequest, accountData{Error: "Give a current code from your app, or a recovery code, to turn the second factor off."})
			return
		}
		if err := s.Store.DisableTOTP(ctx, se.Email); err != nil {
			s.internal(w, r, err)
			return
		}
		s.audit(r, se, "second factor turned off", se.Email, "")
		s.renderAccount(w, r, se, http.StatusOK, accountData{Notice: "The second factor is off: signing in takes the password only."})
	case "end-session":
		if err := s.Store.EndSession(ctx, se.Email, r.PostFormValue("id")); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internal(w, r, err)
			return
		}
		s.audit(r, se, "session ended", se.Email, "")
		http.Redirect(w, r, "/account", http.StatusSeeOther)
	default:
		s.fail(w, r, http.StatusNotFound, "Unknown action", "This action does not exist.")
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
}

// secondFactorForm asks the code of a session that gave its password.
func (s *server) secondFactorForm(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.halfOpen(r); !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "secondfactor", page{Title: "Code", Data: secondFactorData{Next: localPath(r.URL.Query().Get("next"), "/")}})
}

func (s *server) secondFactor(w http.ResponseWriter, r *http.Request) {
	email, ok := s.halfOpen(r)
	if !ok || !sameOrigin(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	next := localPath(r.PostFormValue("next"), "/")
	c, _ := r.Cookie(sessionCookie)
	if err := s.Store.CheckSecondFactor(r.Context(), email, r.PostFormValue("code"), s.Now()); err != nil {
		s.Log.Warn("wrong second factor", "email", email)
		alive, ferr := s.Store.FailSecondFactor(r.Context(), c.Value)
		if ferr != nil || !alive {
			s.cookie(w, sessionCookie, "", -1)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		s.render(w, r, http.StatusUnauthorized, "secondfactor", page{Title: "Code", Data: secondFactorData{Next: next, Error: "Wrong code. After a few wrong codes the password is asked again."}})
		return
	}
	if err := s.Store.CompleteSecondFactor(r.Context(), c.Value); err != nil {
		s.internal(w, r, err)
		return
	}
	if err := s.Store.Audit(r.Context(), email, "second factor given", "", "", s.Now()); err != nil {
		s.Log.Error("audit", "err", err)
	}
	http.Redirect(w, r, next, http.StatusSeeOther) //nolint:gosec // next went through localPath
}

// halfOpen returns the user of a session that gave its password and waits for its code.
func (s *server) halfOpen(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	email, err := s.Store.Session(r.Context(), c.Value, s.Now())
	return email, errors.Is(err, store.ErrSecondFactorRequired)
}
