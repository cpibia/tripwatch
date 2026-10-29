package ui

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// Lifetimes an API token can be made with, in days.
var tokenLifetimes = []int{30, 90, 365}

type apiTokensData struct {
	Tokens    []store.APIToken
	Lifetimes []int
	Error     string
	// New is a token just made, shown once.
	New, NewName string
}

func (s *server) apiTokens(w http.ResponseWriter, r *http.Request, se session) {
	s.renderAPITokens(w, r, se, http.StatusOK, apiTokensData{})
}

func (s *server) renderAPITokens(w http.ResponseWriter, r *http.Request, se session, status int, d apiTokensData) {
	tokens, err := s.Store.APITokens(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	d.Tokens, d.Lifetimes = tokens, tokenLifetimes
	s.render(w, r, status, "apitokens", page{Title: "API tokens", Nav: "api", User: se.Email, CSRF: se.csrf(), Data: d})
}

// createAPIToken makes a token owned by the administrator who asks: it reads, and writes when
// asked, as they would.
func (s *server) createAPIToken(w http.ResponseWriter, r *http.Request, se session) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	days, err := strconv.Atoi(r.PostFormValue("days"))
	if name == "" || utf8.RuneCountInString(name) > 60 || strings.ContainsAny(name, "\r\n\t") {
		s.renderAPITokens(w, r, se, http.StatusBadRequest, apiTokensData{Error: "Name the token after what uses it, in up to 60 characters."})
		return
	}
	if err != nil || !slices.Contains(tokenLifetimes, days) {
		days = tokenLifetimes[1]
	}
	write := r.PostFormValue("write") == "on"
	token, err := s.Store.CreateAPIToken(r.Context(), name, se.Email, write, time.Duration(days)*24*time.Hour, s.Now())
	if err != nil {
		s.renderAPITokens(w, r, se, http.StatusBadRequest, apiTokensData{Error: "The token could not be made: " + err.Error()})
		return
	}
	access := "read"
	if write {
		access = "read and handle alerts"
	}
	s.audit(r, se, "API token made", name, access+", "+strconv.Itoa(days)+" days")
	s.renderAPITokens(w, r, se, http.StatusOK, apiTokensData{New: token, NewName: name})
}

func (s *server) revokeAPIToken(w http.ResponseWriter, r *http.Request, se session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		err = s.Store.RevokeAPIToken(r.Context(), id)
	}
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "Unknown token", "No API token has this number.")
		return
	}
	s.audit(r, se, "API token revoked", "#"+strconv.FormatInt(id, 10), "")
	http.Redirect(w, r, "/settings/api", http.StatusSeeOther)
}
