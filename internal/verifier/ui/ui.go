// Package ui serves the verifier's web interface: the traces of the enrolled hosts, the alerts
// and their handling, and the enrollment of new hosts.
package ui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/pki"
	"github.com/cpibia/tripwatch/internal/verifier/store"
)

//go:embed templates static
var assets embed.FS

const (
	sessionCookie = "tw_session"
	themeCookie   = "tw_theme"
)

// hostPattern is the shape accepted for a new host name: it becomes a certificate common name
// and a file name on the operator's machine.
var hostPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

// version changes with the embedded assets, so browsers refetch them after an upgrade.
var version = func() string {
	h := sha256.New()
	for _, name := range []string{"static/app.css", "static/app.js"} {
		b, _ := assets.ReadFile(name)
		h.Write(b)
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:6])
}()

// Config is what the interface needs from the verifier.
type Config struct {
	Store     *store.Store
	CA        *pki.CA
	IngestURL string
	// Notify reports whether alerts are also sent by email.
	Notify bool
	// SecureCookies marks cookies HTTPS-only; on whenever the interface is reached over HTTPS.
	SecureCookies bool
	SilenceAfter  time.Duration
	Now           func() time.Time
	Log           *slog.Logger
}

type server struct {
	Config
	pages  map[string]*template.Template
	static http.Handler
	logins *limiter
}

// New returns the web interface handler.
func New(c Config) (http.Handler, error) {
	s := &server{Config: c, pages: map[string]*template.Template{}, logins: newLimiter(10, 15*time.Minute)}
	for _, name := range []string{"login", "overview", "host", "alerts", "alert", "enroll", "error"} {
		t, err := template.New(name).Funcs(funcs(c.Now)).Funcs(template.FuncMap{"actx": actx, "table": table, "hosttable": hostTable, "version": func() string { return version }}).ParseFS(assets, "templates/layout.html", "templates/parts.html", "templates/"+name+".html")
		if err != nil {
			return nil, err
		}
		s.pages[name] = t
	}
	static, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	s.static = http.StripPrefix("/static/", http.FileServer(http.FS(static)))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /static/", s.serveStatic)
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.authed(s.logout))
	mux.HandleFunc("POST /theme", s.authed(s.theme))
	mux.HandleFunc("GET /{$}", s.authed(s.overview))
	mux.HandleFunc("GET /hosts/{id}", s.authed(s.host))
	mux.HandleFunc("POST /hosts/{id}/revoke", s.authed(s.revoke))
	mux.HandleFunc("GET /alerts", s.authed(s.alerts))
	mux.HandleFunc("GET /alerts/{id}", s.authed(s.alert))
	mux.HandleFunc("POST /alerts/{id}/ack", s.authed(s.ack))
	mux.HandleFunc("POST /alerts/{id}/resolve", s.authed(s.resolve))
	mux.HandleFunc("GET /enroll", s.authed(s.enrollForm))
	mux.HandleFunc("POST /enroll", s.authed(s.enroll))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.fail(w, r, http.StatusNotFound, "Pagina inesistente", "L'indirizzo non corrisponde a nessuna pagina della console.")
	})
	return headers(mux), nil
}

// headers sets the security headers of every response. Pages carry data written by monitored
// hosts, and therefore possibly by an attacker: no inline script or style may run.
func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func (s *server) serveStatic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	s.static.ServeHTTP(w, r)
}

// session is the signed-in user of a request.
type session struct {
	Email string
	token string
}

func (se session) csrf() string {
	sum := sha256.Sum256([]byte("tripwatch-csrf\x00" + se.token))
	return base64.RawURLEncoding.EncodeToString(sum[:18])
}

type authedHandler func(http.ResponseWriter, *http.Request, session)

// authed requires a valid session, and for state-changing requests a same-origin form carrying
// the session's CSRF token.
func (s *server) authed(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		var se session
		if err == nil {
			se.token = c.Value
			se.Email, err = s.Store.Session(r.Context(), c.Value, s.Now())
		}
		safe := r.Method == http.MethodGet || r.Method == http.MethodHead
		if err != nil {
			if !safe {
				s.fail(w, r, http.StatusForbidden, "Sessione scaduta", "Accedi di nuovo e ripeti l'operazione.")
				return
			}
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		if !safe {
			if !sameOrigin(r) || subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(se.csrf())) != 1 {
				s.fail(w, r, http.StatusForbidden, "Richiesta rifiutata", "Il modulo non viene da questa console, oppure è scaduto. Ricarica la pagina e riprova.")
				return
			}
		}
		h(w, r, se)
	}
}

// sameOrigin rejects requests a browser marks as coming from another site.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
		u, err := url.Parse(origin)
		return err == nil && u.Host == r.Host
	}
	return true
}

// page is what every template receives.
type page struct {
	Title   string
	Nav     string
	User    string
	CSRF    string
	Theme   string
	Refresh bool
	Notify  bool
	Path    string
	Data    any
}

func (s *server) render(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	p.Theme = themeOf(r)
	p.Notify = s.Notify
	p.Path = r.URL.RequestURI()
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		s.Log.Error("render page", "page", name, "err", err)
		http.Error(w, "errore interno", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

type failure struct {
	Heading string
	Message string
}

func (s *server) fail(w http.ResponseWriter, r *http.Request, status int, heading, message string) {
	s.render(w, r, status, "error", page{Title: heading, Data: failure{heading, message}})
}

func (s *server) internal(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	s.Log.Error("ui request", "path", r.URL.Path, "err", err)
	s.fail(w, r, http.StatusInternalServerError, "Errore interno", "La richiesta non è andata a buon fine. Il dettaglio è nel log del verificatore.")
}

func (s *server) cookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	//nolint:gosec // Secure follows the deployment: on whenever the interface is served over HTTPS
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: int(maxAge / time.Second),
		HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteLaxMode})
}

func themeOf(r *http.Request) string {
	if c, err := r.Cookie(themeCookie); err == nil && (c.Value == "light" || c.Value == "dark") {
		return c.Value
	}
	return ""
}

// localPath accepts only paths on this site as redirect targets.
func localPath(p, fallback string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") {
		return fallback
	}
	return p
}

// Login.

type loginData struct {
	Next  string
	Email string
	Error string
}

func (s *server) loginForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "login", page{Title: "Accesso", Data: loginData{Next: localPath(r.URL.Query().Get("next"), "/")}})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	email := strings.TrimSpace(strings.ToLower(r.PostFormValue("email")))
	data := loginData{Next: localPath(r.PostFormValue("next"), "/"), Email: email}
	if !sameOrigin(r) {
		s.fail(w, r, http.StatusForbidden, "Richiesta rifiutata", "Il modulo di accesso non viene da questa console.")
		return
	}
	if !s.logins.allow(email, s.Now()) {
		data.Error = "Troppi tentativi falliti per questo indirizzo. Riprova tra qualche minuto."
		s.render(w, r, http.StatusTooManyRequests, "login", page{Title: "Accesso", Data: data})
		return
	}
	token, err := s.Store.Login(r.Context(), email, r.PostFormValue("password"), s.Now())
	if errors.Is(err, store.ErrBadCredentials) {
		s.logins.fail(email, s.Now())
		s.Log.Warn("failed login", "email", email)
		data.Error = "Email o password non corretti."
		s.render(w, r, http.StatusUnauthorized, "login", page{Title: "Accesso", Data: data})
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.logins.reset(email)
	s.Log.Info("login", "email", email)
	s.cookie(w, sessionCookie, token, store.SessionLifetime)
	http.Redirect(w, r, data.Next, http.StatusSeeOther) //nolint:gosec // data.Next went through localPath
}

func (s *server) logout(w http.ResponseWriter, r *http.Request, se session) {
	if err := s.Store.Logout(r.Context(), se.token); err != nil {
		s.internal(w, r, err)
		return
	}
	s.cookie(w, sessionCookie, "", -time.Second)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// theme cycles between the system's theme, light and dark.
func (s *server) theme(w http.ResponseWriter, r *http.Request, _ session) {
	next := map[string]string{"": "light", "light": "dark", "dark": ""}[themeOf(r)]
	if next == "" {
		s.cookie(w, themeCookie, "", -time.Second)
	} else {
		s.cookie(w, themeCookie, next, 365*24*time.Hour)
	}
	http.Redirect(w, r, localPath(r.PostFormValue("back"), "/"), http.StatusSeeOther) //nolint:gosec // localPath accepts only paths on this site
}

// Hosts.

// hostRow is a host as listed on the overview: its state, its worst unresolved alert, and since
// when it deviates.
type hostRow struct {
	store.Host
	State     string
	StateText string
	Since     time.Time
	Open      int
	Worst     *store.Alert
}

// More is the number of unresolved alerts besides the one shown.
func (r hostRow) More() int { return max(r.Open-1, 0) }

func (s *server) hostRow(h store.Host, alerts []store.Alert) hostRow {
	now := s.Now()
	row := hostRow{Host: h}
	var mine []store.Alert
	for _, a := range alerts {
		if a.HostID == h.ID && a.Status != store.StatusResolved {
			mine = append(mine, a)
		}
	}
	row.Open = len(mine)
	row.Worst = mostUrgent(mine)
	last := h.LastHeartbeat
	switch {
	case h.Revoked:
		row.State, row.StateText = "revoked", "revocato"
	case last.IsZero() && now.Sub(h.EnrolledAt) <= s.SilenceAfter:
		row.State, row.StateText = "waiting", "in attesa del primo battito"
	case last.IsZero():
		row.State, row.StateText, row.Since = "silent", "muto dalla registrazione", h.EnrolledAt
	case now.Sub(last) > s.SilenceAfter:
		row.State, row.StateText, row.Since = "silent", "muto", last
	case row.Worst != nil:
		row.State, row.StateText, row.Since = row.Worst.Severity, severityLabels[row.Worst.Severity], row.Worst.CreatedAt
		if row.Worst.Status == store.StatusAcked {
			row.State += " acked"
		}
	default:
		row.State, row.StateText = "ok", "regolare"
	}
	return row
}

// rank orders hosts for the overview: silent first, then by worst alert, the oldest deviation
// first within each level; healthy, waiting and revoked hosts last, by name.
func (r hostRow) rank() int {
	switch {
	case r.State == "silent":
		return 0
	case r.Worst != nil && !r.Revoked:
		return 1 + severityRank(r.Worst.Severity)
	case r.State == "waiting":
		return 6
	case r.State == "revoked":
		return 8
	}
	return 7
}

// counter is one figure of the overview's top line, with the age of its oldest member.
type counter struct {
	Key    string
	Label  string
	N      int
	Oldest time.Time
}

func (c *counter) add(at time.Time) {
	c.N++
	if c.Oldest.IsZero() || at.Before(c.Oldest) {
		c.Oldest = at
	}
}

type overviewData struct {
	Hosts    []hostRow
	Alerts   []store.Alert
	Counters []*counter
	Focus    *store.Alert
	Healthy  int
}

func (s *server) overview(w http.ResponseWriter, r *http.Request, se session) {
	ctx := r.Context()
	hosts, err := s.Store.Hosts(ctx)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	open, err := s.Store.Alerts(ctx, store.AlertFilter{Statuses: []string{store.StatusOpen, store.StatusAcked}, Limit: 500})
	if err != nil {
		s.internal(w, r, err)
		return
	}
	critical := &counter{Key: "critical", Label: "critici"}
	silent := &counter{Key: "silent", Label: "muti"}
	high := &counter{Key: "high", Label: "alti"}
	acked := &counter{Key: "acked", Label: "in carico"}
	d := overviewData{Alerts: open, Counters: []*counter{critical, silent, high, acked}, Focus: mostUrgent(open)}
	for _, a := range open {
		switch {
		case a.Kind == "silence":
			// Counted as a silent host below, not twice.
		case a.Status == store.StatusAcked:
			acked.add(a.CreatedAt)
		case a.Severity == "critical":
			critical.add(a.CreatedAt)
		case a.Severity == "high":
			high.add(a.CreatedAt)
		}
	}
	for _, h := range hosts {
		row := s.hostRow(h, open)
		switch row.State {
		case "silent":
			silent.add(row.Since)
		case "ok":
			d.Healthy++
		}
		d.Hosts = append(d.Hosts, row)
	}
	slices.SortStableFunc(d.Hosts, func(a, b hostRow) int {
		if ra, rb := a.rank(), b.rank(); ra != rb {
			return ra - rb
		}
		if !a.Since.Equal(b.Since) {
			return a.Since.Compare(b.Since)
		}
		return strings.Compare(a.ID, b.ID)
	})
	s.render(w, r, http.StatusOK, "overview", page{Title: "Panoramica", Nav: "overview", User: se.Email, CSRF: se.csrf(), Refresh: true, Data: d})
}

type hostData struct {
	Row          hostRow
	SilenceAfter time.Duration
	Alerts       []store.Alert
	Silences     []Gap
	Snapshots    []store.SnapshotHead
}

func (s *server) host(w http.ResponseWriter, r *http.Request, se session) {
	ctx := r.Context()
	h, err := s.Store.Host(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, http.StatusNotFound, "Server sconosciuto", "Nessun server registrato con questo nome.")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	now := s.Now()
	alerts, err := s.Store.Alerts(ctx, store.AlertFilter{HostID: h.ID, Limit: 300})
	if err != nil {
		s.internal(w, r, err)
		return
	}
	marks, err := s.Store.Activity(ctx, h.ID, now.Add(-store.ActivityRetention))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	snaps, err := s.Store.SnapshotHeads(ctx, h.ID, 30)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	d := hostData{Row: s.hostRow(h, alerts), SilenceAfter: s.SilenceAfter, Alerts: alerts, Snapshots: snaps,
		Silences: silences(marks, h.EnrolledAt, now, store.ActivityRetention, s.SilenceAfter)}
	if h.Revoked && len(d.Silences) > 0 && d.Silences[0].Ongoing {
		d.Silences = d.Silences[1:]
	}
	s.render(w, r, http.StatusOK, "host", page{Title: h.ID, Nav: "overview", User: se.Email, CSRF: se.csrf(), Refresh: true, Data: d})
}

func (s *server) revoke(w http.ResponseWriter, r *http.Request, se session) {
	id := r.PathValue("id")
	if r.PostFormValue("confirm") != id {
		s.fail(w, r, http.StatusBadRequest, "Revoca non confermata", "Per revocare il server scrivi il suo nome esatto nel campo di conferma.")
		return
	}
	if err := s.Store.Revoke(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, "Server sconosciuto", "Nessun server registrato con questo nome.")
			return
		}
		s.internal(w, r, err)
		return
	}
	s.Log.Info("host revoked", "host", id, "by", se.Email)
	http.Redirect(w, r, "/hosts/"+url.PathEscape(id), http.StatusSeeOther)
}

// Alerts.

// alertTable is what the alert table template receives: the rows, and what their action forms
// need to post and come back.
type alertTable struct {
	Alerts  []store.Alert
	CSRF    string
	Back    string
	OneHost bool
}

type alertAction struct {
	Alert store.Alert
	CSRF  string
	Back  string
}

func table(alerts []store.Alert, csrf, back string) alertTable {
	return alertTable{Alerts: alerts, CSRF: csrf, Back: back}
}

// hostTable is table for a page about one host, where a host column would repeat its name.
func hostTable(alerts []store.Alert, csrf, back string) alertTable {
	return alertTable{Alerts: alerts, CSRF: csrf, Back: back, OneHost: true}
}

func actx(a store.Alert, csrf, back string) alertAction { return alertAction{a, csrf, back} }

var alertViews = []struct{ Key, Label string }{
	{"open", "Da gestire"}, {"acknowledged", "Presi in carico"}, {"resolved", "Risolti"}, {"all", "Tutti"},
}

type alertsData struct {
	View   string
	Views  []struct{ Key, Label string }
	Host   string
	Alerts []store.Alert
	Limit  int
}

func (s *server) alerts(w http.ResponseWriter, r *http.Request, se session) {
	view := r.URL.Query().Get("view")
	f := store.AlertFilter{HostID: r.URL.Query().Get("host"), Limit: 500}
	switch view {
	case "acknowledged":
		f.Statuses = []string{store.StatusAcked}
	case "resolved":
		f.Statuses = []string{store.StatusResolved}
	case "all":
	default:
		view = "open"
		f.Statuses = []string{store.StatusOpen, store.StatusAcked}
	}
	list, err := s.Store.Alerts(r.Context(), f)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "alerts", page{Title: "Allarmi", Nav: "alerts", User: se.Email, CSRF: se.csrf(), Refresh: true,
		Data: alertsData{View: view, Views: alertViews, Host: f.HostID, Alerts: list, Limit: f.Limit}})
}

func (s *server) alertByPath(w http.ResponseWriter, r *http.Request) (store.Alert, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		var a store.Alert
		if a, err = s.Store.Alert(r.Context(), id); err == nil {
			return a, true
		}
	}
	if err == nil || errors.Is(err, store.ErrNotFound) || errors.Is(err, strconv.ErrSyntax) || errors.Is(err, strconv.ErrRange) {
		s.fail(w, r, http.StatusNotFound, "Allarme inesistente", "Nessun allarme con questo numero.")
		return store.Alert{}, false
	}
	s.internal(w, r, err)
	return store.Alert{}, false
}

func (s *server) alert(w http.ResponseWriter, r *http.Request, se session) {
	a, ok := s.alertByPath(w, r)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "alert", page{Title: a.Title, Nav: "alerts", User: se.Email, CSRF: se.csrf(), Data: a})
}

func (s *server) ack(w http.ResponseWriter, r *http.Request, se session) {
	s.transition(w, r, se, s.Store.Ack, "alert acknowledged")
}

func (s *server) resolve(w http.ResponseWriter, r *http.Request, se session) {
	s.transition(w, r, se, s.Store.Resolve, "alert resolved")
}

func (s *server) transition(w http.ResponseWriter, r *http.Request, se session, apply func(context.Context, int64, string, time.Time) error, msg string) {
	a, ok := s.alertByPath(w, r)
	if !ok {
		return
	}
	// A concurrent change by a colleague is not an error: the page they land on shows it.
	if err := apply(r.Context(), a.ID, se.Email, s.Now()); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, r, err)
		return
	}
	s.Log.Info(msg, "alert", a.ID, "host", a.HostID, "by", se.Email)
	http.Redirect(w, r, localPath(r.PostFormValue("back"), "/alerts/"+strconv.FormatInt(a.ID, 10)), http.StatusSeeOther) //nolint:gosec // localPath accepts only paths on this site
}

// Enrollment.

type enrollData struct {
	Host      string
	Error     string
	Existing  bool
	IngestURL string
}

func (s *server) enrollForm(w http.ResponseWriter, r *http.Request, se session) {
	s.render(w, r, http.StatusOK, "enroll", page{Title: "Registra un server", Nav: "enroll", User: se.Email, CSRF: se.csrf(),
		Data: enrollData{IngestURL: s.IngestURL}})
}

// enroll issues a host's certificate and keys and hands them over as a download. The bundle is
// not kept: if it is lost, the host is enrolled again, which invalidates the previous keys.
func (s *server) enroll(w http.ResponseWriter, r *http.Request, se session) {
	host := strings.TrimSpace(strings.ToLower(r.PostFormValue("host")))
	d := enrollData{Host: host, IngestURL: s.IngestURL}
	again := func(status int, msg string) {
		d.Error = msg
		s.render(w, r, status, "enroll", page{Title: "Registra un server", Nav: "enroll", User: se.Email, CSRF: se.csrf(), Data: d})
	}
	if !hostPattern.MatchString(host) || host == "verifier" {
		again(http.StatusBadRequest, "Il nome può contenere lettere minuscole, cifre, punti e trattini, e deve iniziare con una lettera o una cifra.")
		return
	}
	existing, err := s.Store.Host(r.Context(), host)
	switch {
	case err == nil && r.PostFormValue("replace") != "yes":
		d.Existing = true
		again(http.StatusConflict, "Esiste già un server con questo nome, registrato il "+clock(existing.EnrolledAt, s.Now())+".")
		return
	case err != nil && !errors.Is(err, store.ErrNotFound):
		s.internal(w, r, err)
		return
	}
	now := s.Now()
	bundle, pub, err := s.CA.Enroll(host, s.IngestURL, now)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if err := s.Store.Enroll(r.Context(), host, pub, now); err != nil {
		s.internal(w, r, err)
		return
	}
	s.Log.Info("host enrolled", "host", host, "by", se.Email, "replaced", existing.ID != "")
	body, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		s.internal(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="tripwatch-`+host+`.json"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(append(body, '\n'))
}

// limiter counts failed logins per email and refuses further attempts once max is reached
// within the window.
type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	fails  map[string][]time.Time
}

func newLimiter(maxFails int, window time.Duration) *limiter {
	return &limiter{max: maxFails, window: window, fails: map[string][]time.Time{}}
}

func (l *limiter) recent(key string, now time.Time) []time.Time {
	kept := l.fails[key][:0]
	for _, t := range l.fails[key] {
		if now.Sub(t) < l.window {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.fails, key)
		return nil
	}
	l.fails[key] = kept
	return kept
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key, now)) < l.max
}

func (l *limiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Bounded memory: guessing many different emails must not grow the map without end. Each
	// failed attempt costs a bcrypt comparison, so cycling enough emails to evict a given one
	// takes far longer than the window it would buy.
	if _, ok := l.fails[key]; !ok && len(l.fails) >= 10_000 {
		for k := range l.fails {
			if l.recent(k, now) != nil {
				delete(l.fails, k)
			}
			break
		}
	}
	l.fails[key] = append(l.recent(key, now), now)
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, key)
}
