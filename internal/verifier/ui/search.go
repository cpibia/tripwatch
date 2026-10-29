package ui

import (
	"net/http"
	"strings"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// Bounds on what one search shows of each kind: enough to find what was looked for, a link to
// the full list for the rest.
const (
	searchAlerts = 50
	searchEvents = 30
)

// maxSearch bounds the text searched for.
const maxSearch = 200

// searchEvent is an event found by a search, with the server it happened on.
type searchEvent struct {
	Host string
	eventRow
}

type searchData struct {
	Text   string
	Hosts  []hostRow
	Alerts []store.Alert
	Events []searchEvent
	// More says a list was cut at its bound.
	MoreAlerts, MoreEvents bool
}

// search looks for a text across the fleet at once: the servers (name, addresses, system, the
// applications and the sites they serve), the alerts (server, title, what the server reported)
// and the changes seen in real time (path, command).
func (s *server) search(w http.ResponseWriter, r *http.Request, se session) {
	ctx := r.Context()
	text := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(text) > maxSearch {
		text = strings.ToValidUTF8(text[:maxSearch], "")
	}
	d := searchData{Text: text}
	if text != "" {
		hosts, err := s.Store.Hosts(ctx)
		if err != nil {
			s.internal(w, r, err)
			return
		}
		summaries, err := s.Store.Summaries(ctx)
		if err != nil {
			s.internal(w, r, err)
			return
		}
		facts, err := s.Store.Facts(ctx)
		if err != nil {
			s.internal(w, r, err)
			return
		}
		q := serverQuery{Text: text}
		for _, h := range hosts {
			if h.Revoked {
				continue
			}
			sum, has := summaries[h.ID]
			row := s.hostRow(h, sum, has)
			row.Facts = facts[h.ID]
			if q.matches(row) {
				d.Hosts = append(d.Hosts, row)
			}
		}
		if d.Alerts, err = s.Store.Alerts(ctx, store.AlertFilter{Query: text, Current: true, Limit: searchAlerts + 1}); err != nil {
			s.internal(w, r, err)
			return
		}
		if len(d.Alerts) > searchAlerts {
			d.Alerts, d.MoreAlerts = d.Alerts[:searchAlerts], true
		}
		events, err := s.Store.SearchEvents(ctx, text, searchEvents+1)
		if err != nil {
			s.internal(w, r, err)
			return
		}
		if len(events) > searchEvents {
			events, d.MoreEvents = events[:searchEvents], true
		}
		for i, row := range eventRows(events) {
			d.Events = append(d.Events, searchEvent{Host: events[i].HostID, eventRow: row})
		}
	}
	s.render(w, r, http.StatusOK, "search", page{Title: "Search", User: se.Email, CSRF: se.csrf(), Data: d})
}
