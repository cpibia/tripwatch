package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// apiCaller is who an API request acts for: a token, as its owner.
type apiCaller struct {
	Token store.APIToken
	Role  string
}

// maxAPIAlerts bounds one page of alerts.
const maxAPIAlerts = 500

type apiAlert struct {
	ID          int64     `json:"id"`
	Host        string    `json:"host"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Kind        string    `json:"kind"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Occurrences int       `json:"occurrences"`
}

type apiHost struct {
	ID            string    `json:"id"`
	Name          string    `json:"name,omitempty"`
	Labels        []string  `json:"labels,omitempty"`
	Revoked       bool      `json:"revoked,omitempty"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	LastSnapshot  time.Time `json:"last_snapshot"`
	Open          int       `json:"open_alerts"`
	Worst         string    `json:"worst_severity,omitempty"`
}

// api authenticates a request by its bearer token. A token reads as its owner; writing takes a
// write token whose owner is at least an operator. No cookie is read: a browser's session can
// never call these routes for a page of another site.
func (s *server) api(write bool, h func(http.ResponseWriter, *http.Request, apiCaller)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			apiError(w, http.StatusUnauthorized, "a bearer token is required")
			return
		}
		t, err := s.Store.UseAPIToken(r.Context(), strings.TrimSpace(raw), s.Now())
		if err != nil {
			apiError(w, http.StatusUnauthorized, "unknown or expired token")
			return
		}
		role, scope, err := s.Store.UserAccess(r.Context(), t.Owner)
		if err != nil {
			apiError(w, http.StatusUnauthorized, "unknown or expired token")
			return
		}
		if write && (!t.Write || !store.RoleAtLeast(role, store.RoleOperator)) {
			apiError(w, http.StatusForbidden, "this token cannot change alerts")
			return
		}
		h(w, r.WithContext(store.WithScope(r.Context(), scope)), apiCaller{Token: t, Role: role})
	}
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func toAPIAlert(a store.Alert) apiAlert {
	return apiAlert{ID: a.ID, Host: a.HostID, Severity: a.Severity, Status: a.Status, Kind: a.Kind, Title: a.Title, Detail: a.Detail,
		CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt, Occurrences: a.Occurrences}
}

// apiAlerts lists alerts: status, severity and host narrow them, limit bounds them. With after,
// a cursor, they come in the order they were raised, from the one after that ID, and next is the
// cursor of the following page when there may be one; total counts every alert the filters match.
func (s *server) apiAlerts(w http.ResponseWriter, r *http.Request, _ apiCaller) {
	q := r.URL.Query()
	f := store.AlertFilter{Current: true, HostID: q.Get("host"), Limit: 100}
	for _, st := range strings.Split(q.Get("status"), ",") {
		if slices.Contains([]string{store.StatusOpen, store.StatusAcked, store.StatusResolved}, st) {
			f.Statuses = append(f.Statuses, st)
		}
	}
	for _, sev := range strings.Split(q.Get("severity"), ",") {
		if slices.Contains(allSeverities, sev) {
			f.Severities = append(f.Severities, sev)
		}
	}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		f.Limit = min(n, maxAPIAlerts)
	}
	total, err := s.Store.CountAlerts(r.Context(), f)
	if err != nil {
		s.Log.Error("api alerts", "err", err)
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if raw := q.Get("after"); raw != "" {
		after, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || after < 0 {
			apiError(w, http.StatusBadRequest, "after is the ID of the last alert read")
			return
		}
		f.AfterID, f.Sort = after, store.SortID
	}
	alerts, err := s.Store.Alerts(r.Context(), f)
	if err != nil {
		s.Log.Error("api alerts", "err", err)
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]apiAlert, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, toAPIAlert(a))
	}
	resp := map[string]any{"alerts": out, "total": total}
	if f.Sort == store.SortID && len(alerts) == f.Limit {
		resp["next"] = alerts[len(alerts)-1].ID
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) apiAlert(w http.ResponseWriter, r *http.Request, _ apiCaller) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		apiError(w, http.StatusNotFound, "no such alert")
		return
	}
	a, err := s.Store.Alert(r.Context(), id)
	if err != nil {
		apiError(w, http.StatusNotFound, "no such alert")
		return
	}
	writeJSON(w, http.StatusOK, toAPIAlert(a))
}

// apiHosts lists the servers with their latest contact and open alerts.
func (s *server) apiHosts(w http.ResponseWriter, r *http.Request, _ apiCaller) {
	hosts, err := s.Store.Hosts(r.Context())
	if err != nil {
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	summaries, err := s.Store.Summaries(r.Context())
	if err != nil {
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]apiHost, 0, len(hosts))
	for _, h := range hosts {
		row := apiHost{ID: h.ID, Name: h.Name, Labels: h.Labels, Revoked: h.Revoked, LastHeartbeat: h.LastHeartbeat, LastSnapshot: h.LastSnapshot}
		if sum, ok := summaries[h.ID]; ok {
			row.Open, row.Worst = sum.Open, sum.Worst.Severity
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
}

// apiTransition acknowledges or resolves an alert for a write token.
func (s *server) apiTransition(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		apiError(w, http.StatusNotFound, "no such alert")
		return
	}
	a, err := s.Store.Alert(r.Context(), id)
	if err != nil {
		apiError(w, http.StatusNotFound, "no such alert")
		return
	}
	actor := "api:" + c.Token.Name
	var apply func(context.Context, int64, string, time.Time) error
	var action string
	switch r.PathValue("action") {
	case "ack":
		apply, action = s.Store.Ack, "alert acknowledged"
	case "resolve":
		apply, action = s.Store.Resolve, "alert resolved"
	default:
		apiError(w, http.StatusNotFound, "unknown action: ack or resolve")
		return
	}
	if err := apply(r.Context(), a.ID, actor, s.Now()); err != nil && !errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.Store.Audit(r.Context(), actor, action, a.HostID, "#"+strconv.FormatInt(a.ID, 10)+" "+a.Title+" (token of "+c.Token.Owner+")", s.Now()); err != nil {
		s.Log.Error("audit", "err", err)
	}
	a, _ = s.Store.Alert(r.Context(), id)
	writeJSON(w, http.StatusOK, toAPIAlert(a))
}
