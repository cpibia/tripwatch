// Package ui serves the verifier's web interface: the traces of the enrolled hosts, the alerts
// and their handling, and the enrollment of new hosts.
package ui

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
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
	deviceCookie  = "tw_device"
)

// hostPattern is the shape accepted for a new host name: it becomes a certificate common name
// and a file name on the operator's machine.
var hostPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

// releasePattern matches the version of a published release, whose sensor packages the
// enrollment command can download; development builds offer the enrollment alone.
var releasePattern = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)$`)

const releaseDownloads = "https://github.com/cpibia/tripwatch/releases/download/"

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
	// Release is the verifier's version: the enrollment command installs the sensor of the same
	// release.
	Release string
	// Notify reports whether alerts are also sent by email.
	Notify bool
	// SecureCookies marks cookies HTTPS-only; on whenever the interface is reached over HTTPS.
	SecureCookies bool
	SilenceAfter  time.Duration
	// LoginBackoff is the first delay after repeated failed logins; zero means one second.
	LoginBackoff time.Duration
	Now          func() time.Time
	Log          *slog.Logger
}

type server struct {
	Config
	pages  map[string]*template.Template
	static http.Handler
	logins *limiter
	// checks bounds the password checks running at once to the CPUs; knownCheck is one more,
	// reserved to known browsers.
	checks     chan struct{}
	knownCheck chan struct{}
}

// New returns the web interface handler.
func New(c Config) (http.Handler, error) {
	s := &server{Config: c, pages: map[string]*template.Template{}, logins: newLimiter(time.Second, 15*time.Second),
		checks: make(chan struct{}, max(1, runtime.GOMAXPROCS(0)-1)), knownCheck: make(chan struct{}, 1)}
	if c.LoginBackoff > 0 {
		s.logins = newLimiter(c.LoginBackoff, 15*c.LoginBackoff)
	}
	for _, name := range []string{"login", "link", "overview", "servers", "host", "alerts", "alert", "enroll", "error"} {
		t, err := template.New(name).Funcs(funcs(c.Now)).Funcs(template.FuncMap{"actx": actx, "acceptable": store.Acceptable, "rowx": rowx, "groupx": groupx, "table": table, "hosttable": hostTable, "picktable": pickTable, "boardtable": boardTable, "subject": subject, "num": pct, "selecturl": selectURL, "version": func() string { return version }}).ParseFS(assets, "templates/layout.html", "templates/parts.html", "templates/"+name+".html")
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
	mux.HandleFunc("GET /login/link", s.loginLinkForm)
	mux.HandleFunc("POST /login/link", s.loginLink)
	mux.HandleFunc("POST /logout", s.authed(s.logout))
	mux.HandleFunc("POST /theme", s.authed(s.theme))
	mux.HandleFunc("GET /{$}", s.authed(s.overview))
	mux.HandleFunc("GET /hosts", s.authed(s.servers))
	mux.HandleFunc("GET /hosts/{id}", s.authed(s.host))
	mux.HandleFunc("POST /hosts/{id}/revoke", s.authed(s.revoke))
	mux.HandleFunc("POST /hosts/{id}/withdraw", s.authed(s.withdraw))
	mux.HandleFunc("GET /alerts", s.authed(s.alerts))
	mux.HandleFunc("GET /alerts/{id}", s.authed(s.alert))
	mux.HandleFunc("POST /alerts/{id}/ack", s.authed(s.ack))
	mux.HandleFunc("POST /alerts/{id}/resolve", s.authed(s.resolve))
	mux.HandleFunc("POST /alerts/{id}/accept", s.authed(s.accept))
	mux.HandleFunc("POST /bulk/{action}", s.authed(s.bulk))
	mux.HandleFunc("GET /enroll", s.authed(s.enrollForm))
	mux.HandleFunc("POST /enroll", s.authed(s.enroll))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.fail(w, r, http.StatusNotFound, "Page not found", "The address does not match any page of the console.")
	})
	return headers(mux), nil
}

// headers sets the security headers of every response. Pages carry data written by monitored
// hosts, and therefore possibly by an attacker: no inline script or style may run.
func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
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
				s.fail(w, r, http.StatusForbidden, "Session expired", "Sign in again and repeat the operation.")
				return
			}
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		if !safe {
			if !sameOrigin(r) || subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(se.csrf())) != 1 {
				s.fail(w, r, http.StatusForbidden, "Request refused", "The form does not come from this console, or it expired. Reload the page and try again.")
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
	// Alarm is set while a critical alert is open, Release is the running version.
	Alarm   bool
	Release string
	Data    any
}

func (s *server) render(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	p.Theme = themeOf(r)
	p.Notify = s.Notify
	p.Path = r.URL.RequestURI()
	p.Release = s.release()
	if p.User != "" {
		alarm, err := s.Store.Alarming(r.Context())
		if err != nil {
			s.Log.Error("alarm state", "err", err)
		}
		p.Alarm = alarm
	}
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		s.Log.Error("render page", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
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
	s.fail(w, r, http.StatusInternalServerError, "Internal error", "The request failed. The details are in the verifier's log.")
}

func (s *server) cookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	//nolint:gosec // Secure follows the deployment: on whenever the interface is served over HTTPS
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: int(maxAge / time.Second),
		HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteLaxMode})
}

func themeOf(r *http.Request) string {
	if c, err := r.Cookie(themeCookie); err == nil && (c.Value == "light" || c.Value == "system") {
		return c.Value
	}
	return "dark"
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
	s.render(w, r, http.StatusOK, "login", page{Title: "Sign in", Data: loginData{Next: localPath(r.URL.Query().Get("next"), "/")}})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	email := strings.TrimSpace(strings.ToLower(r.PostFormValue("email")))
	data := loginData{Next: localPath(r.PostFormValue("next"), "/"), Email: email}
	if !sameOrigin(r) {
		s.fail(w, r, http.StatusForbidden, "Request refused", "The sign-in form does not come from this console.")
		return
	}
	lane, err := s.loginLane(r, email)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	// The wait in line, at most one delay ceiling of 15 s plus the check, stays inside the
	// server's write timeout.
	waitCtx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	done, ok := s.logins.begin(waitCtx, lane, s.Now)
	var release func()
	if ok {
		// Password checks are bounded across all lanes, so a flood cannot starve the CPU; a
		// known browser also has a check of its own, which the flood cannot take.
		if release, ok = s.checkSlot(waitCtx, strings.HasPrefix(lane, "device:")); !ok {
			done(false)
		}
	}
	if !ok {
		data.Error = "Too many attempts in progress for this address. Try again shortly."
		s.render(w, r, http.StatusTooManyRequests, "login", page{Title: "Sign in", Data: data})
		return
	}
	token, err := s.Store.Login(r.Context(), email, r.PostFormValue("password"), s.Now())
	release()
	done(err == nil)
	if errors.Is(err, store.ErrBadCredentials) {
		s.Log.Warn("failed login", "email", email)
		data.Error = "Wrong email or password."
		s.render(w, r, http.StatusUnauthorized, "login", page{Title: "Sign in", Data: data})
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.Log.Info("login", "email", email)
	s.cookie(w, sessionCookie, token, store.SessionLifetime)
	if !strings.HasPrefix(lane, "device:") {
		if device, err := s.Store.CreateDevice(r.Context(), email, s.Now()); err == nil {
			s.cookie(w, deviceCookie, device, store.DeviceLifetime)
		}
	}
	http.Redirect(w, r, data.Next, http.StatusSeeOther) //nolint:gosec // data.Next went through localPath
}

// checkSlot waits for a turn to check a password. Every lane, users' and unknown emails' alike,
// waits for the same shared slots, so the wait tells nothing about which emails exist; known
// browsers may also take a slot reserved to them.
func (s *server) checkSlot(ctx context.Context, known bool) (func(), bool) {
	if known {
		select {
		case s.knownCheck <- struct{}{}:
			return func() { <-s.knownCheck }, true
		case s.checks <- struct{}{}:
			return func() { <-s.checks }, true
		case <-ctx.Done():
			return nil, false
		}
	}
	select {
	case s.checks <- struct{}{}:
		return func() { <-s.checks }, true
	case <-ctx.Done():
		return nil, false
	}
}

// loginLane is the line a sign-in attempt waits in, and whose failures slow it down. A browser
// the user signed in from before has a lane of its own, which guessing from anywhere else
// cannot slow: the right password from a known browser is never delayed by an attack. Every
// other attempt for an email shares one lane, whatever its source, so guessing in parallel or
// from many addresses gains nothing. Emails that are not users get a lane each too, so that
// the delays do not tell which emails exist; their lanes live in a bounded table of their own,
// where they can only push each other out.
func (s *server) loginLane(r *http.Request, email string) (string, error) {
	if c, err := r.Cookie(deviceCookie); err == nil {
		if owner, err := s.Store.DeviceEmail(r.Context(), c.Value, s.Now()); err == nil && owner == email {
			sum := sha256.Sum256([]byte(c.Value))
			return "device:" + base64.RawURLEncoding.EncodeToString(sum[:12]), nil
		}
	}
	exists, err := s.Store.UserExists(r.Context(), email)
	if err != nil {
		return "", err
	}
	if !exists {
		return "unknown:" + email, nil
	}
	return "email:" + email, nil
}

// loginLinkForm shows a button for a one-time link: opening the link must not use it, since
// link previews in chat and mail scanners open links too.
func (s *server) loginLinkForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "link", page{Title: "Sign in with a link", Data: r.URL.Query().Get("t")})
}

// loginLink signs in with a one-time link made by `tripwatch-verifier login-link`, and makes the
// browser a known one: the way in when the email's line is held by an attack.
func (s *server) loginLink(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if !sameOrigin(r) {
		s.fail(w, r, http.StatusForbidden, "Request refused", "The sign-in form does not come from this console.")
		return
	}
	email, token, err := s.Store.ConsumeLoginLink(r.Context(), r.PostFormValue("t"), s.Now())
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, http.StatusForbidden, "Invalid link", "The sign-in link was already used or has expired. Create another one from the verifier.")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.Log.Info("login with a one-time link", "email", email)
	s.cookie(w, sessionCookie, token, store.SessionLifetime)
	if device, err := s.Store.CreateDevice(r.Context(), email, s.Now()); err == nil {
		s.cookie(w, deviceCookie, device, store.DeviceLifetime)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
	// Dark is the default and needs no cookie; the button cycles dark, light, system.
	next := map[string]string{"dark": "light", "light": "system", "system": "dark"}[themeOf(r)]
	if next == "dark" {
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
	// Facts and Outdated come from the host's latest snapshot and sensor start.
	Facts    store.HostFacts
	Outdated bool
}

// More is the number of unresolved alerts besides the one shown.
func (r hostRow) More() int { return max(r.Open-1, 0) }

// summarize is the store's per-host summary for a list of one host's alerts.
func summarize(alerts []store.Alert) (store.HostSummary, bool) {
	worst := mostUrgent(alerts)
	if worst == nil {
		return store.HostSummary{}, false
	}
	n := 0
	for _, a := range alerts {
		if a.Status != store.StatusResolved {
			n++
		}
	}
	return store.HostSummary{Open: n, Worst: *worst}, true
}

func (s *server) hostRow(h store.Host, sum store.HostSummary, has bool) hostRow {
	now := s.Now()
	row := hostRow{Host: h}
	if has {
		row.Open = sum.Open
		worst := sum.Worst
		row.Worst = &worst
	}
	last := h.LastHeartbeat
	switch {
	case h.Revoked:
		row.State, row.StateText = "revoked", "revoked"
	case last.IsZero() && now.Sub(h.EnrolledAt) <= s.SilenceAfter:
		row.State, row.StateText = "waiting", "waiting for the first heartbeat"
	case last.IsZero():
		row.State, row.StateText, row.Since = "silent", "silent since enrollment", h.EnrolledAt
	case now.Sub(last) > s.SilenceAfter:
		row.State, row.StateText, row.Since = "silent", "silent", last
	case row.Worst != nil:
		row.State, row.StateText, row.Since = row.Worst.Severity, severityLabels[row.Worst.Severity], row.Worst.CreatedAt
		if row.Worst.Status == store.StatusAcked {
			row.State += " acked"
		}
	default:
		row.State, row.StateText = "ok", "healthy"
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
	Limit    int
	Focus    focus
	Base     string
	Healthy  int
	KPIs     []kpi
	Timeline timeline
	Rules    []rankRow
	Loaded   []rankRow
	Web      webAttacks
	// Revoked hosts no longer report: the overview only names them, their pages keep the record.
	Revoked []string
}

// overviewAlerts bounds the alert table of the overview; counters and host rows are computed
// over all alerts.
const overviewAlerts = 200

// overviewGroups is how many rows of open alerts the overview shows before linking to the rest.
const overviewGroups = 10

func (s *server) overview(w http.ResponseWriter, r *http.Request, se session) {
	ctx := r.Context()
	hosts, err := s.Store.Hosts(ctx)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	open, err := s.Store.Alerts(ctx, store.AlertFilter{Statuses: []string{store.StatusOpen, store.StatusAcked}, Limit: overviewAlerts, Current: true})
	if err != nil {
		s.internal(w, r, err)
		return
	}
	summaries, err := s.Store.Summaries(ctx)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	tallies, err := s.Store.Tallies(ctx)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	// The default panel is chosen among every host's worst alert, not among the listed ones,
	// which a single host could fill.
	worsts := make([]store.Alert, 0, len(summaries))
	for _, sum := range summaries {
		worsts = append(worsts, sum.Worst)
	}
	panel, err := s.picked(r, worsts, se.csrf())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	critical := &counter{Key: "critical", Label: "critical", N: tallies["critical"].N, Oldest: tallies["critical"].Oldest}
	silent := &counter{Key: "silent", Label: "silent"}
	high := &counter{Key: "high", Label: "high", N: tallies["high"].N, Oldest: tallies["high"].Oldest}
	acked := &counter{Key: "acked", Label: "acknowledged", N: tallies["acknowledged"].N, Oldest: tallies["acknowledged"].Oldest}
	now := s.Now()
	raised, err := s.Store.RaisedSince(ctx, now.Add(-7*24*time.Hour-time.Hour))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	bySeverity, err := s.Store.OpenBySeverity(ctx)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	facts, err := s.Store.Facts(ctx)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	d := overviewData{Alerts: open, Limit: overviewAlerts, Counters: []*counter{critical, silent, high, acked}, Focus: panel, Base: pageWithoutPick(r),
		Timeline: buildTimeline(raised, r.URL.Query().Get("range"), now), Rules: buildRules(raised, 8), Loaded: buildHosts(bySeverity, 8), Web: buildWeb(raised, 6)}
	for _, h := range hosts {
		if h.Revoked {
			d.Revoked = append(d.Revoked, h.ID)
			continue
		}
		sum, has := summaries[h.ID]
		row := s.hostRow(h, sum, has)
		row.Facts = facts[h.ID]
		row.Outdated = outdated(row.Facts.SensorVersion, s.release())
		switch row.State {
		case "silent":
			silent.add(row.Since)
		case "ok":
			d.Healthy++
		}
		d.Hosts = append(d.Hosts, row)
	}
	d.KPIs = buildKPIs(tallies, raised, silent, now)
	slices.SortStableFunc(d.Hosts, func(a, b hostRow) int {
		if ra, rb := a.rank(), b.rank(); ra != rb {
			return ra - rb
		}
		if !a.Since.Equal(b.Since) {
			return a.Since.Compare(b.Since)
		}
		return strings.Compare(a.ID, b.ID)
	})
	s.render(w, r, http.StatusOK, "overview", page{Title: "Overview", Nav: "overview", User: se.Email, CSRF: se.csrf(), Refresh: true, Data: d})
}

type hostData struct {
	Row          hostRow
	SilenceAfter time.Duration
	Alerts       []store.Alert
	Silences     []Gap
	Snapshots    []store.SnapshotHead
	Accepted     []store.Acceptance
	Facts        *store.HostFacts
	Outdated     bool
	Release      string
	Events       []eventRow
}

func (s *server) host(w http.ResponseWriter, r *http.Request, se session) {
	ctx := r.Context()
	h, err := s.Store.Host(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, http.StatusNotFound, "Unknown server", "No server is enrolled with this name.")
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
	accepted, err := s.Store.Acceptances(ctx, h.ID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	facts, err := s.Store.Facts(ctx)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	events, err := s.Store.HostEvents(ctx, h.ID, maxEventRows)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	sum, has := summarize(alerts)
	d := hostData{Events: eventRows(events), Accepted: accepted, Release: s.release(), Row: s.hostRow(h, sum, has), SilenceAfter: s.SilenceAfter, Alerts: alerts, Snapshots: snaps,
		Silences: silences(marks, h.EnrolledAt, now, store.ActivityRetention, s.SilenceAfter)}
	if f, ok := facts[h.ID]; ok {
		d.Facts = &f
		d.Outdated = outdated(f.SensorVersion, s.release())
	}
	if h.Revoked && len(d.Silences) > 0 && d.Silences[0].Ongoing {
		d.Silences = d.Silences[1:]
	}
	s.render(w, r, http.StatusOK, "host", page{Title: h.ID, Nav: "servers", User: se.Email, CSRF: se.csrf(), Refresh: true, Data: d})
}

func (s *server) revoke(w http.ResponseWriter, r *http.Request, se session) {
	id := r.PathValue("id")
	if r.PostFormValue("confirm") != id {
		s.fail(w, r, http.StatusBadRequest, "Revocation not confirmed", "To revoke the server, type its exact name in the confirmation field.")
		return
	}
	if err := s.Store.Revoke(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, "Unknown server", "No server is enrolled with this name.")
			return
		}
		s.internal(w, r, err)
		return
	}
	s.Log.Info("host revoked", "host", id, "by", se.Email)
	http.Redirect(w, r, "/hosts/"+url.PathEscape(id), http.StatusSeeOther)
}

// withdraw puts a finding accepted on a host back under watch.
func (s *server) withdraw(w http.ResponseWriter, r *http.Request, se session) {
	id, fp := r.PathValue("id"), r.PostFormValue("fingerprint")
	if err := s.Store.Withdraw(r.Context(), id, fp); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, r, err)
		return
	}
	s.Log.Info("acceptance withdrawn", "host", id, "fingerprint", fp, "by", se.Email)
	http.Redirect(w, r, "/hosts/"+url.PathEscape(id)+"#accepted-h", http.StatusSeeOther)
}

// Alerts.

// alertTable is what the alert table template receives: the rows, and what their action forms
// need to post and come back.
type alertTable struct {
	Alerts  []store.Alert
	CSRF    string
	Back    string
	OneHost bool
	// Select, when set, is the page whose side panel shows an alert: rows link to it with the
	// alert's id instead of to the alert's own page. Selected is the alert shown there.
	Select   string
	Selected int64
	// Picked is set when someone chose the selected alert: its group opens to show it.
	Picked bool
	// NoActions leaves the actions out of the rows: on the overview they live in the side panel
	// and on each alert's page, where there is the context to decide.
	NoActions bool
	// AcrossHosts groups one rule's alerts of all hosts together, and MaxGroups bounds how many
	// groups are shown: the overview lists what deviates at a glance, the Alerts page in full.
	AcrossHosts bool
	MaxGroups   int
}

// focus is the side panel of a page: the alert it shows and whether someone picked it.
type focus struct {
	Alert  *store.Alert
	Picked bool
	CSRF   string
	Back   string
}

// SelectURL is the address that shows alert id in the panel of page base, keeping its query.
func (t alertTable) SelectURL(id int64) string { return selectURL(t.Select, id) }

func selectURL(base string, id int64) string {
	u, err := url.Parse(base)
	if err != nil {
		return "/alerts/" + strconv.FormatInt(id, 10)
	}
	q := u.Query()
	q.Set("a", strconv.FormatInt(id, 10))
	u.RawQuery = q.Encode()
	u.Fragment = "focus"
	return u.String()
}

// picked resolves the panel of a page: the alert named by ?a= if it exists, otherwise the
// most urgent of the listed ones.
func (s *server) picked(r *http.Request, listed []store.Alert, csrf string) (focus, error) {
	f := focus{CSRF: csrf, Back: r.URL.RequestURI()}
	if id, err := strconv.ParseInt(r.URL.Query().Get("a"), 10, 64); err == nil {
		a, err := s.Store.Alert(r.Context(), id)
		switch {
		case err == nil:
			f.Alert, f.Picked = &a, true
			return f, nil
		case !errors.Is(err, store.ErrNotFound):
			return f, err
		}
	}
	f.Alert = mostUrgent(listed)
	if f.Alert == nil && len(listed) > 0 {
		f.Alert = &listed[0]
	}
	return f, nil
}

// pageWithoutPick is the current page address without the panel's selection, used as the base
// of the selection links.
func pageWithoutPick(r *http.Request) string {
	q := r.URL.Query()
	q.Del("a")
	if len(q) == 0 {
		return r.URL.Path
	}
	return r.URL.Path + "?" + q.Encode()
}

type alertAction struct {
	Alert store.Alert
	CSRF  string
	Back  string
}

func table(alerts []store.Alert, csrf, back string) alertTable {
	return alertTable{Alerts: alerts, CSRF: csrf, Back: back}
}

// pickTable is table for a page with a side panel: rows select the alert shown there.
func pickTable(alerts []store.Alert, csrf, back, base string, f focus) alertTable {
	t := alertTable{Alerts: alerts, CSRF: csrf, Back: back, Select: base}
	if f.Alert != nil {
		t.Selected, t.Picked = f.Alert.ID, f.Picked
	}
	return t
}

// boardTable is table for the overview: its rows carry no actions and open each alert's page.
func boardTable(alerts []store.Alert, csrf, back, _ string, _ focus) alertTable {
	return alertTable{Alerts: alerts, CSRF: csrf, Back: back, NoActions: true, AcrossHosts: true, MaxGroups: overviewGroups}
}

// subject is what a fingerprint names beyond its rule, such as a file's path, when the title
// does not already show it: it tells apart the rows of a group.
func subject(a store.Alert) string {
	fp, _, _ := strings.Cut(a.Fingerprint, "|")
	parts := strings.SplitN(fp, ":", 3)
	if len(parts) < 3 || parts[2] == "" || strings.Contains(a.Title, parts[2]) {
		return ""
	}
	return parts[2]
}

// hostTable is table for a page about one host, where a host column would repeat its name.
func hostTable(alerts []store.Alert, csrf, back string) alertTable {
	return alertTable{Alerts: alerts, CSRF: csrf, Back: back, OneHost: true}
}

func actx(a store.Alert, csrf, back string) alertAction { return alertAction{a, csrf, back} }

// alertRow is one row of an alert table, with the table it belongs to.
type alertRow struct {
	Alert store.Alert
	Table alertTable
}

func rowx(a store.Alert, t alertTable) alertRow { return alertRow{a, t} }

// groupRow is the head row of a group, with the table it belongs to.
type groupRow struct {
	Group alertGroup
	Table alertTable
}

func groupx(g alertGroup, t alertTable) groupRow { return groupRow{g, t} }

// alertGroup is the alerts of one host, severity and rule: one row that opens onto them. One
// finding per file or per request makes a rule raise hundreds of alerts at once, and a list of
// identical rows hides everything else.
type alertGroup struct {
	// Key names the group in the page, so it stays open across the minute refresh.
	Key    string
	Label  string
	Alerts []store.Alert
	// Lead stands for the group: the first in the table's order, the most severe and recent.
	Lead     store.Alert
	Since    time.Time
	Open     int
	Acked    int
	Resolved int
	Expanded bool
	// Hosts counts the distinct hosts of the group.
	Hosts int
	// Held is set when the store holds more alerts of the group back in an aggregate, beyond
	// its cap of open alerts per rule; CanAccept when some alert of the group can be accepted.
	Held      bool
	CanAccept bool
}

// Pending are the alerts a bulk action applies to: those not resolved yet.
func (g alertGroup) Pending() []store.Alert {
	var out []store.Alert
	for _, a := range g.Alerts {
		if a.Status != "resolved" {
			out = append(out, a)
		}
	}
	return out
}

// Groups splits the table's alerts by host, severity and rule, keeping the table's order.
func (t alertTable) Groups() []alertGroup {
	index := map[string]int{}
	var groups []alertGroup
	for _, a := range t.Alerts {
		fp := a.Fingerprint
		held := false
		if g, ok := store.Aggregate(fp); ok {
			fp, held = g, true
		}
		k := a.Severity + "\x00" + alertRule(fp)
		if !t.AcrossHosts {
			k = a.HostID + "\x00" + k
		}
		i, ok := index[k]
		if !ok {
			sum := sha256.Sum256([]byte(k))
			i = len(groups)
			index[k] = i
			groups = append(groups, alertGroup{Key: hex.EncodeToString(sum[:6]), Lead: a, Since: a.CreatedAt})
		}
		g := &groups[i]
		g.Alerts = append(g.Alerts, a)
		g.Held = g.Held || held
		g.CanAccept = g.CanAccept || store.Acceptable(a)
		if a.CreatedAt.Before(g.Since) {
			g.Since = a.CreatedAt
		}
		switch a.Status {
		case "open":
			g.Open++
		case "acknowledged":
			g.Acked++
		default:
			g.Resolved++
		}
		if t.Picked && a.ID == t.Selected {
			g.Expanded = true
		}
	}
	for i := range groups {
		named := groups[i].Alerts
		if groups[i].Held && len(named) > 1 {
			named = slices.DeleteFunc(slices.Clone(named), func(a store.Alert) bool {
				_, agg := store.Aggregate(a.Fingerprint)
				return agg
			})
		}
		groups[i].Label = commonLabel(named)
		seen := map[string]bool{}
		for _, a := range groups[i].Alerts {
			seen[a.HostID] = true
		}
		groups[i].Hosts = len(seen)
	}
	if t.MaxGroups > 0 && len(groups) > t.MaxGroups {
		groups = groups[:t.MaxGroups]
	}
	return groups
}

// HiddenGroups is how many groups MaxGroups left out.
func (t alertTable) HiddenGroups() int {
	if t.MaxGroups == 0 {
		return 0
	}
	all := t
	all.MaxGroups = 0
	return max(len(all.Groups())-t.MaxGroups, 0)
}

// alertRule is the rule part of a fingerprint: the kind and the rule, without the file, request
// or script that tells one finding from another. It follows the grouping of store.Raise, but
// also joins the per-script groups of the web log rules.
func alertRule(fingerprint string) string {
	fingerprint, _, _ = strings.Cut(fingerprint, "|")
	parts := strings.SplitN(fingerprint, ":", 3)
	if len(parts) < 3 {
		return fingerprint
	}
	return parts[0] + ":" + parts[1]
}

// commonLabel names a group by what its titles share, cut where a path or a name starts to
// differ.
func commonLabel(alerts []store.Alert) string {
	label, same := alerts[0].Title, true
	for _, a := range alerts[1:] {
		n := 0
		for n < len(label) && n < len(a.Title) && label[n] == a.Title[n] {
			n++
		}
		same = same && n == len(label) && n == len(a.Title)
		label = label[:n]
	}
	if same {
		return label
	}
	// Titles read "rule: detail"; without that shape, cut at the last word or path element.
	if i := strings.LastIndex(label, ": "); i > 0 {
		label = label[:i]
	} else if i := strings.LastIndexAny(label, " /"); i > 0 {
		label = strings.TrimRight(label[:i+1], " ")
	}
	if strings.TrimSpace(label) == "" {
		return alerts[0].Title
	}
	return label
}

var alertViews = []struct{ Key, Label string }{
	{"open", "To handle"}, {"acknowledged", "Acknowledged"}, {"resolved", "Resolved"}, {"all", "All"},
}

type alertsData struct {
	Focus  focus
	Base   string
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
	panel, err := s.picked(r, list, se.csrf())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "alerts", page{Title: "Alerts", Nav: "alerts", User: se.Email, CSRF: se.csrf(), Refresh: true,
		Data: alertsData{View: view, Views: alertViews, Host: f.HostID, Alerts: list, Limit: f.Limit, Focus: panel, Base: pageWithoutPick(r)}})
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
		s.fail(w, r, http.StatusNotFound, "Alert not found", "No alert has this number.")
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
	v := alertView{Alert: a}
	if lines, at, err := s.Store.AlertDiff(r.Context(), a.ID); err == nil && lines != "" {
		v.Diff = &alertDiff{Lines: strings.Split(lines, "\n"), At: at}
	} else if !errors.Is(err, store.ErrNotFound) {
		s.Log.Error("alert diff", "alert", a.ID, "err", err)
	}
	v.Brief = brief(a, v.Diff)
	s.render(w, r, http.StatusOK, "alert", page{Title: a.Title, Nav: "alerts", User: se.Email, CSRF: se.csrf(), Data: v})
}

// alertView is an alert with, for a policy change, the complete diff its detail cuts short.
type alertView struct {
	store.Alert
	Diff *alertDiff
	// Brief is the alert in Markdown, to paste into an AI assistant.
	Brief string
}

type alertDiff struct {
	Lines []string
	At    time.Time
}

func (s *server) ack(w http.ResponseWriter, r *http.Request, se session) {
	s.transition(w, r, se, s.Store.Ack, "alert acknowledged")
}

func (s *server) resolve(w http.ResponseWriter, r *http.Request, se session) {
	s.transition(w, r, se, s.Store.Resolve, "alert resolved")
}

func (s *server) accept(w http.ResponseWriter, r *http.Request, se session) {
	s.transition(w, r, se, s.Store.AcceptAlert, "alert accepted")
}

// maxBulk bounds the alerts one bulk action names: a table shows at most a few hundred.
const maxBulk = 1000

// bulk acknowledges or resolves the alerts of a group at once.
func (s *server) bulk(w http.ResponseWriter, r *http.Request, se session) {
	apply, msg := s.Store.Ack, "alerts acknowledged"
	switch r.PathValue("action") {
	case "ack":
	case "resolve":
		apply, msg = s.Store.Resolve, "alerts resolved"
	case "accept":
		apply, msg = s.Store.AcceptAlert, "alerts accepted"
	default:
		http.NotFound(w, r)
		return
	}
	ids := r.PostForm["id"]
	if len(ids) > maxBulk {
		http.Error(w, "too many alerts", http.StatusRequestEntityTooLarge)
		return
	}
	now, done := s.Now(), 0
	for _, raw := range ids {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			continue
		}
		// As for a single alert, one changed meanwhile by a colleague is not an error.
		if err := apply(r.Context(), id, se.Email, now); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internal(w, r, err)
			return
		}
		done++
	}
	s.Log.Info(msg, "count", done, "by", se.Email)
	http.Redirect(w, r, localPath(r.PostFormValue("back"), "/alerts"), http.StatusSeeOther) //nolint:gosec // localPath accepts only paths on this site
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
	Mode      string
	Error     string
	Existing  bool
	IngestURL string
	// System is "deb" or "rpm" when the command also installs the sensor package of Release,
	// "installed" when it only enrolls.
	System  string
	Release string
	// Token, Command and Expires are set once a token was made: it is shown on this page only.
	Token   string
	Command string
	Expires time.Time
}

// release is the published release this verifier runs, or "" for a development build.
func (s *server) release() string {
	if m := releasePattern.FindStringSubmatch(s.Release); m != nil {
		return m[1]
	}
	return ""
}

// enrollSystem reads the chosen system, falling back to enrollment alone when there is no
// release to install from.
func enrollSystem(choice, release string) string {
	switch {
	case release == "":
		return "installed"
	case choice == "rpm" || choice == "installed":
		return choice
	}
	return "deb"
}

// enrollCommand is the single command to run on the host. On deb and rpm systems it first
// installs the sensor package of the release for the host's own architecture, and removes the
// downloaded file.
func enrollCommand(system, release, token string) string {
	enroll := "echo '" + token + "' | sudo tripwatch-sensor enroll -token-file - && sudo systemctl enable --now tripwatch-sensor"
	base := releaseDownloads + "v" + release + "/"
	switch system {
	case "deb":
		return "cd /tmp && f=tripwatch-sensor_" + release + "_$(dpkg --print-architecture).deb && curl -fsSLO " + base + "$f" +
			" && sudo apt-get install -y ./$f && rm -f $f && " + enroll
	case "rpm":
		return "sudo $(command -v dnf || command -v yum) install -y " + base + "tripwatch-sensor-" + release + "-1.$(uname -m).rpm && " + enroll
	}
	return enroll
}

func (s *server) enrollForm(w http.ResponseWriter, r *http.Request, se session) {
	release := s.release()
	s.render(w, r, http.StatusOK, "enroll", page{Title: "Enroll a server", Nav: "enroll", User: se.Email, CSRF: se.csrf(),
		Data: enrollData{IngestURL: s.IngestURL, Mode: "token", Release: release, System: enrollSystem("", release)}})
}

// enroll makes a one-time token for the host, or, in bundle mode, issues its certificate and
// keys and hands them over as a download. Neither is kept: a lost token or bundle means
// enrolling again, which invalidates the previous keys once used.
func (s *server) enroll(w http.ResponseWriter, r *http.Request, se session) {
	host := strings.TrimSpace(strings.ToLower(r.PostFormValue("host")))
	mode := "token"
	if r.PostFormValue("mode") == "bundle" {
		mode = "bundle"
	}
	release := s.release()
	d := enrollData{Host: host, Mode: mode, IngestURL: s.IngestURL, Release: release, System: enrollSystem(r.PostFormValue("system"), release)}
	again := func(status int, msg string) {
		d.Error = msg
		s.render(w, r, status, "enroll", page{Title: "Enroll a server", Nav: "enroll", User: se.Email, CSRF: se.csrf(), Data: d})
	}
	if !hostPattern.MatchString(host) || host == "verifier" {
		again(http.StatusBadRequest, "The name may contain lowercase letters, digits, dots and hyphens, and must start with a letter or a digit.")
		return
	}
	existing, err := s.Store.Host(r.Context(), host)
	switch {
	case err == nil && r.PostFormValue("replace") != "yes":
		d.Existing = true
		again(http.StatusConflict, "A server with this name already exists, enrolled "+clock(existing.EnrolledAt, s.Now())+".")
		return
	case err != nil && !errors.Is(err, store.ErrNotFound):
		s.internal(w, r, err)
		return
	}
	now := s.Now()
	if mode == "token" {
		secret, expires, err := s.Store.CreateEnrollToken(r.Context(), host, se.Email, now)
		if err != nil {
			s.internal(w, r, err)
			return
		}
		s.Log.Info("enrollment token made", "host", host, "by", se.Email, "replaces", existing.ID != "")
		d.Token = pki.EnrollToken{URL: s.IngestURL, Secret: secret, CA: s.CA.Fingerprint()}.String()
		d.Command = enrollCommand(d.System, release, d.Token)
		d.Expires = expires
		s.render(w, r, http.StatusOK, "enroll", page{Title: "Enroll a server", Nav: "enroll", User: se.Email, CSRF: se.csrf(), Data: d})
		return
	}
	bundle, pub, err := s.CA.Enroll(host, s.IngestURL, now)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	serial, err := pki.Serial([]byte(bundle.Cert))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if err := s.Store.EnrollWithCertificate(r.Context(), host, pub, serial, now); err != nil {
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

// limiter slows down guessing without ever locking a user out: the attempts of one lane (see
// loginLane) run one at a time, and after a few failures each waits longer, up to a ceiling.
type limiter struct {
	mu      sync.Mutex
	free    int           // failures allowed before delays start
	base    time.Duration // first delay
	ceiling time.Duration
	window  time.Duration        // failures older than this are forgotten
	entries map[string]*attempts // users and their known browsers
	// unknown holds the lanes of emails that are not users: a fixed set chosen by a keyed hash
	// of the email, so there is nothing to scan or evict, no lock shared with the users' lanes,
	// and an attacker cannot aim two emails at one lane.
	unknown [unknownLanes]*attempts
	key     [32]byte
}

const unknownLanes = 1 << 14

type attempts struct {
	turn  chan struct{} // one-slot semaphore: whose turn it is, given up when the request ends
	fails int
	last  time.Time
}

func newAttempts() *attempts { return &attempts{turn: make(chan struct{}, 1)} }

// evictStale drops idle lanes whose failures are past the window from a full table.
func (l *limiter) evictStale(now func() time.Time) {
	for k, e := range l.entries {
		select {
		case e.turn <- struct{}{}:
			stale := now().Sub(e.last) > l.window
			<-e.turn
			if stale {
				delete(l.entries, k)
			}
		default:
		}
	}
}

const maxLimiterEntries = 10_000

// A lane gets freeFailures failures before the delays start, and forgets failures older than
// failureWindow.
const (
	freeFailures  = 5
	failureWindow = time.Hour
)

func newLimiter(base, ceiling time.Duration) *limiter {
	l := &limiter{free: freeFailures, base: base, ceiling: ceiling, window: failureWindow, entries: map[string]*attempts{}}
	_, _ = rand.Read(l.key[:])
	for i := range l.unknown {
		l.unknown[i] = newAttempts()
	}
	return l
}

// lane picks the lane of an email that is not a user.
func (l *limiter) lane(email string) int {
	mac := hmac.New(sha256.New, l.key[:])
	mac.Write([]byte(email))
	return int(binary.BigEndian.Uint32(mac.Sum(nil)) % unknownLanes)
}

// begin waits for the turn of key and the delay its failures earned. The caller calls done with
// the outcome. It returns false if ctx ended while waiting.
func (l *limiter) begin(ctx context.Context, key string, now func() time.Time) (done func(ok bool), started bool) {
	var a *attempts
	if email, ok := strings.CutPrefix(key, "unknown:"); ok {
		a = l.unknown[l.lane(email)]
	} else {
		l.mu.Lock()
		var found bool
		if a, found = l.entries[key]; !found {
			// Lanes exist only for real users and their known browsers, so the table stays
			// small; stale ones are still dropped now and then.
			if len(l.entries) >= maxLimiterEntries {
				l.evictStale(now)
			}
			a = newAttempts()
			l.entries[key] = a
		}
		l.mu.Unlock()
	}

	select {
	case a.turn <- struct{}{}:
	case <-ctx.Done():
		return nil, false
	}
	if now().Sub(a.last) > l.window {
		a.fails = 0
	}
	if extra := a.fails - l.free; extra >= 0 {
		delay := l.ceiling
		if extra < 16 && l.base<<extra < l.ceiling {
			delay = l.base << extra
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			<-a.turn
			return nil, false
		}
	}
	return func(ok bool) {
		if ok {
			a.fails = 0
		} else {
			a.fails++
			a.last = now()
		}
		<-a.turn
	}, true
}

// serversData is the fleet page: every enrolled host with its system and sensor, then the
// revoked ones.
type serversData struct {
	Hosts    []hostRow
	Revoked  []hostRow
	Release  string
	Outdated int
}

func (s *server) servers(w http.ResponseWriter, r *http.Request, se session) {
	ctx := r.Context()
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
	d := serversData{Release: s.release()}
	for _, h := range hosts {
		sum, has := summaries[h.ID]
		row := s.hostRow(h, sum, has)
		row.Facts = facts[h.ID]
		row.Outdated = !h.Revoked && outdated(row.Facts.SensorVersion, d.Release)
		if h.Revoked {
			d.Revoked = append(d.Revoked, row)
			continue
		}
		if row.Outdated {
			d.Outdated++
		}
		d.Hosts = append(d.Hosts, row)
	}
	slices.SortStableFunc(d.Hosts, func(a, b hostRow) int { return strings.Compare(a.ID, b.ID) })
	s.render(w, r, http.StatusOK, "servers", page{Title: "Servers", Nav: "servers", User: se.Email, CSRF: se.csrf(), Refresh: true, Data: d})
}

// outdated reports whether a sensor runs an older release than the verifier: the verifier is
// updated first, so its version is the one sensors should reach. Development builds compare
// with nothing.
func outdated(sensor, verifier string) bool {
	a, okA := semver(sensor)
	b, okB := semver(verifier)
	return okA && okB && slices.Compare(a, b) < 0
}

func semver(v string) ([]int, bool) {
	m := releasePattern.FindStringSubmatch(v)
	if m == nil {
		return nil, false
	}
	var out []int
	for _, p := range strings.Split(m[1], ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}
