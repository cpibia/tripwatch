package ui

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// Bounds on what people write about a server.
const (
	maxHostName   = 80
	maxHostLabels = 12
	maxHostNote   = 2000
)

// labelPattern is a key=value pair: a short key, and a value without spaces, so a label reads
// and searches as one word.
var labelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}=[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,63}$`)

// parseLabels reads labels separated by commas, spaces or lines, sorted and without duplicates.
func parseLabels(text string) ([]string, string) {
	var out []string
	for _, l := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		if !labelPattern.MatchString(l) {
			return nil, "A label is key=value, such as env=prod or client=acme: " + l + " is not."
		}
		if !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	if len(out) > maxHostLabels {
		return nil, "At most 12 labels."
	}
	slices.Sort(out)
	return out, ""
}

// hostDetails changes what people call a server, its labels and its note. Its ID stays: it is
// the name in its certificate.
func (s *server) hostDetails(w http.ResponseWriter, r *http.Request, se session) {
	id := r.PathValue("id")
	name := strings.TrimSpace(r.PostFormValue("name"))
	note := strings.TrimSpace(strings.ReplaceAll(r.PostFormValue("note"), "\r\n", "\n"))
	labels, problem := parseLabels(r.PostFormValue("labels"))
	switch {
	case utf8.RuneCountInString(name) > maxHostName || strings.ContainsAny(name, "\n\r\t"):
		problem = "The name takes up to 80 characters on one line."
	case utf8.RuneCountInString(note) > maxHostNote:
		problem = "The note takes up to 2000 characters."
	}
	if problem != "" {
		s.fail(w, r, http.StatusBadRequest, "Details not saved", problem)
		return
	}
	if name == id {
		name = ""
	}
	if err := s.Store.SetHostDetails(r.Context(), id, name, labels, note); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, "Unknown server", "No server is enrolled with this name.")
			return
		}
		s.internal(w, r, err)
		return
	}
	s.audit(r, se, "server details changed", id, "name "+orDash(name)+", labels "+orDash(strings.Join(labels, " ")))
	http.Redirect(w, r, "/hosts/"+url.PathEscape(id), http.StatusSeeOther)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
