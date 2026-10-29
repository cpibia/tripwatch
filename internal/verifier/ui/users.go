package ui

import (
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

type usersData struct {
	Users []store.User
	Roles []string
	Self  string
	Error string
	// Link is a new invitation's address, shown once; Invited and Expires describe it.
	Link    string
	Invited string
	Expires time.Time
}

// audit records an action of the signed-in user. A failure to record is logged and does not
// undo the action, which already happened.
func (s *server) audit(r *http.Request, se session, action, target, detail string) {
	if err := s.Store.Audit(r.Context(), se.Email, action, target, detail, s.Now()); err != nil {
		s.Log.Error("audit", "action", action, "err", err)
	}
}

func (s *server) users(w http.ResponseWriter, r *http.Request, se session) {
	s.renderUsers(w, r, se, http.StatusOK, usersData{})
}

func (s *server) renderUsers(w http.ResponseWriter, r *http.Request, se session, status int, d usersData) {
	users, err := s.Store.Users(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	d.Users, d.Roles, d.Self = users, store.Roles, se.Email
	s.render(w, r, status, "users", page{Title: "Users", Nav: "users", User: se.Email, CSRF: se.csrf(), Data: d})
}

// invite makes a one-time link for a new user, shown once to the administrator, who sends it.
func (s *server) invite(w http.ResponseWriter, r *http.Request, se session) {
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	role := r.PostFormValue("role")
	if a, err := mail.ParseAddress(email); err != nil || a.Address != email {
		s.renderUsers(w, r, se, http.StatusBadRequest, usersData{Error: "That is not a valid email address."})
		return
	}
	token, expires, err := s.Store.CreateInvite(r.Context(), email, role, se.Email, s.Now())
	switch {
	case errors.Is(err, store.ErrUserExists):
		s.renderUsers(w, r, se, http.StatusBadRequest, usersData{Error: email + " already has an account."})
		return
	case err != nil:
		s.internal(w, r, err)
		return
	}
	s.audit(r, se, "user invited", email, "role "+role)
	scheme := "http"
	if s.SecureCookies {
		scheme = "https"
	}
	link := (&url.URL{Scheme: scheme, Host: r.Host, Path: "/invite", RawQuery: url.Values{"t": {token}}.Encode()}).String()
	s.renderUsers(w, r, se, http.StatusOK, usersData{Link: link, Invited: email, Expires: expires})
}

// userAction changes a user's role or removes them.
func (s *server) userAction(w http.ResponseWriter, r *http.Request, se session) {
	email := r.PostFormValue("email")
	var err error
	action := r.PathValue("action")
	switch action {
	case "role":
		err = s.Store.SetRole(r.Context(), email, r.PostFormValue("role"))
		if err == nil {
			s.audit(r, se, "role changed", email, "to "+r.PostFormValue("role"))
		}
	case "remove":
		err = s.Store.DeleteUser(r.Context(), email)
		if err == nil {
			s.audit(r, se, "user removed", email, "")
		}
	case "reset-2fa":
		// For someone who lost their phone and their recovery codes: they sign in with the
		// password only, and set a new second factor up.
		err = s.Store.DisableTOTP(r.Context(), email)
		if err == nil {
			s.audit(r, se, "second factor reset", email, "")
		}
	default:
		s.fail(w, r, http.StatusNotFound, "Unknown action", "This action does not exist.")
		return
	}
	switch {
	case errors.Is(err, store.ErrLastAdmin):
		s.renderUsers(w, r, se, http.StatusConflict, usersData{Error: "There must stay at least one administrator: make someone else administrator first."})
		return
	case errors.Is(err, store.ErrNotFound):
		s.fail(w, r, http.StatusNotFound, "Unknown user", "No user has this email.")
		return
	case err != nil:
		s.internal(w, r, err)
		return
	}
	if action == "remove" && strings.EqualFold(email, se.Email) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

type inviteData struct {
	Token, Email, Role, Error string
	Min                       int
}

// inviteForm shows a new user the account an invitation is for, to choose a password.
func (s *server) inviteForm(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("t")
	email, role, err := s.Store.Invite(r.Context(), token, s.Now())
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "Invitation not valid", "The link was used already or it expired: ask an administrator for a new one.")
		return
	}
	s.render(w, r, http.StatusOK, "invite", page{Title: "Welcome", Data: inviteData{Token: token, Email: email, Role: role, Min: store.MinPassword}})
}

func (s *server) acceptInvite(w http.ResponseWriter, r *http.Request) {
	token, password := r.PostFormValue("t"), r.PostFormValue("password")
	email, role, err := s.Store.Invite(r.Context(), token, s.Now())
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "Invitation not valid", "The link was used already or it expired: ask an administrator for a new one.")
		return
	}
	problem := ""
	switch {
	case len(password) < store.MinPassword:
		problem = "Choose a password of at least 12 characters."
	case password != r.PostFormValue("again"):
		problem = "The two passwords differ."
	}
	if problem != "" {
		s.render(w, r, http.StatusBadRequest, "invite", page{Title: "Welcome", Data: inviteData{Token: token, Email: email, Role: role, Min: store.MinPassword, Error: problem}})
		return
	}
	email, session, err := s.Store.AcceptInvite(r.Context(), token, password, s.Now())
	if err != nil {
		s.fail(w, r, http.StatusConflict, "Invitation not valid", "The link was used already, it expired, or this email has an account already.")
		return
	}
	if err := s.Store.Audit(r.Context(), email, "invitation accepted", email, "role "+role, s.Now()); err != nil {
		s.Log.Error("audit", "err", err)
	}
	s.cookie(w, sessionCookie, session, store.SessionLifetime)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// maxAuditShown bounds the audit log page.
const maxAuditShown = 500

func (s *server) auditLog(w http.ResponseWriter, r *http.Request, se session) {
	entries, err := s.Store.AuditLog(r.Context(), maxAuditShown)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "audit", page{Title: "Audit log", Nav: "audit", User: se.Email, CSRF: se.csrf(), Data: entries})
}
