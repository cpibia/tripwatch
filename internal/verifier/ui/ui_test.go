package ui

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/verifier/pki"
	"github.com/cpibia/tripwatch/internal/verifier/store"
)

var now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

const (
	email    = "ops@example.net"
	password = "correct-horse-battery"
)

type harness struct {
	t     *testing.T
	store *store.Store
	srv   *httptest.Server
	http  *http.Client
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.LoadOrCreate(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SetUser(context.Background(), email, password, now); err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{Store: st, CA: ca, IngestURL: "https://verifier.example.net:8443/v1/envelopes", SilenceAfter: 3 * time.Minute, LoginBackoff: 10 * time.Millisecond,
		Now: func() time.Time { return now }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &harness{t: t, store: st, srv: srv, http: client}
}

// reply is a response read in full.
type reply struct {
	StatusCode int
	Header     http.Header
}

func (h *harness) do(method, path, site string, form url.Values) (reply, string) {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(h.t.Context(), method, h.srv.URL+path, strings.NewReader(form.Encode()))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", site)
	}
	res, err := h.http.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	return reply{res.StatusCode, res.Header}, string(body)
}

func (h *harness) get(path string) (reply, string) { return h.do(http.MethodGet, path, "", nil) }

func (h *harness) post(path string, form url.Values) (reply, string) {
	return h.do(http.MethodPost, path, "same-origin", form)
}

var csrfField = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// login signs in and returns the CSRF token of the session.
func (h *harness) login() string {
	h.t.Helper()
	res, _ := h.post("/login", url.Values{"email": {email}, "password": {password}, "next": {"/"}})
	if res.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("login: status %d", res.StatusCode)
	}
	_, body := h.get("/")
	m := csrfField.FindStringSubmatch(body)
	if m == nil {
		h.t.Fatal("no CSRF token on the overview")
	}
	return m[1]
}

func TestPagesRequireLogin(t *testing.T) {
	h := newHarness(t)
	res, _ := h.get("/alerts?view=all")
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/login?next=%2Falerts%3Fview%3Dall" {
		t.Fatalf("got %d to %q, want a redirect to the login keeping the page", res.StatusCode, res.Header.Get("Location"))
	}
	res, _ = h.post("/enroll", url.Values{"host": {"web-01"}})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("enroll without session: status %d", res.StatusCode)
	}
}

func TestLogin(t *testing.T) {
	h := newHarness(t)
	res, body := h.post("/login", url.Values{"email": {email}, "password": {"wrong-password-here"}})
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "non corretti") {
		t.Fatalf("wrong password: status %d", res.StatusCode)
	}
	res, _ = h.post("/login", url.Values{"email": {email}, "password": {password}, "next": {"//evil.example/"}})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Fatalf("open redirect: got %q", res.Header.Get("Location"))
	}
	if !strings.Contains(res.Header.Get("Set-Cookie"), "HttpOnly") {
		t.Fatalf("session cookie not HttpOnly: %q", res.Header.Get("Set-Cookie"))
	}
}

func TestLoginLimiterSlowsDownWithoutLockingOut(t *testing.T) {
	h := newHarness(t)
	// Parallel guesses run one at a time and, past the free failures, each waits longer.
	var wg sync.WaitGroup
	start := time.Now()
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.post("/login", url.Values{"email": {email}, "password": {"wrong-password-here"}})
		}()
	}
	wg.Wait()
	// Failures 6, 7 and 8 wait 10, 20 and 40 ms in the test configuration.
	if took := time.Since(start); took < 70*time.Millisecond {
		t.Fatalf("eight parallel failures took %v: not serialised or not delayed", took)
	}
	// The right password still gets in.
	res, _ := h.post("/login", url.Values{"email": {email}, "password": {password}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("the user is locked out: status %d", res.StatusCode)
	}
}

func TestCrossSiteFormsRejected(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	res, _ := h.post("/enroll", url.Values{"host": {"web-01"}, "csrf": {"forged"}})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong token: status %d", res.StatusCode)
	}
	res, _ = h.do(http.MethodPost, "/enroll", "cross-site", url.Values{"host": {"web-01"}, "csrf": {csrf}})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site form: status %d", res.StatusCode)
	}
	if _, err := h.store.Host(context.Background(), "web-01"); err == nil {
		t.Fatal("a rejected form enrolled the host")
	}
}

func TestEnrollDownloadsBundleOnce(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	res, body := h.post("/enroll", url.Values{"host": {"web-01"}, "csrf": {csrf}, "mode": {"bundle"}})
	if res.StatusCode != http.StatusOK || !strings.Contains(res.Header.Get("Content-Disposition"), `filename="tripwatch-web-01.json"`) {
		t.Fatalf("enroll: status %d, disposition %q", res.StatusCode, res.Header.Get("Content-Disposition"))
	}
	var b pki.Bundle
	if err := json.Unmarshal([]byte(body), &b); err != nil || b.HostID != "web-01" || b.SigningKey == "" {
		t.Fatalf("bundle: %v %+v", err, b)
	}

	res, body = h.post("/enroll", url.Values{"host": {"web-01"}, "csrf": {csrf}, "mode": {"bundle"}})
	if res.StatusCode != http.StatusConflict || !strings.Contains(body, `name="replace"`) {
		t.Fatalf("enrolling an existing host without confirmation: status %d", res.StatusCode)
	}
	res, _ = h.post("/enroll", url.Values{"host": {"web-01"}, "csrf": {csrf}, "replace": {"yes"}, "mode": {"bundle"}})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("confirmed re-enrollment: status %d", res.StatusCode)
	}
	for _, bad := range []string{"../etc", "Web 01", "verifier", strings.Repeat("a", 64)} {
		if res, _ := h.post("/enroll", url.Values{"host": {bad}, "csrf": {csrf}}); res.StatusCode != http.StatusBadRequest {
			t.Errorf("host %q: status %d, want 400", bad, res.StatusCode)
		}
	}
}

func TestEnrollTokenShownOnce(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	res, body := h.post("/enroll", url.Values{"host": {"web-07"}, "csrf": {csrf}})
	m := regexp.MustCompile(`echo '(tw1\.[A-Za-z0-9_-]+)' \| sudo tripwatch-sensor enroll -token-file -`).FindStringSubmatch(html.UnescapeString(body))
	if res.StatusCode != http.StatusOK || m == nil {
		t.Fatalf("token page: status %d", res.StatusCode)
	}
	token, err := pki.ParseEnrollToken(m[1])
	if err != nil || token.URL != "https://verifier.example.net:8443/v1/envelopes" || token.CA == "" {
		t.Fatalf("token = %+v, %v", token, err)
	}
	host, by, err := h.store.ConsumeEnrollToken(context.Background(), token.Secret, now)
	if err != nil || host != "web-07" || by != email {
		t.Fatalf("token not usable: %q %q %v", host, by, err)
	}
	if _, err := h.store.Host(context.Background(), "web-07"); err == nil {
		t.Fatal("making a token enrolled the host before the token was used")
	}
	if _, body := h.get("/enroll"); strings.Contains(body, m[1]) {
		t.Fatal("the token is shown again")
	}
}

func TestAlertTextIsEscapedAndHandled(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.store.Enroll(ctx, "web-01", make([]byte, 32), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Raise(ctx, store.Alert{HostID: "web-01", Fingerprint: "web:x", Severity: "high", Kind: "web",
		Title: "Modified file", Detail: `GET /<script>alert(1)</script> "ua"`}, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	csrf := h.login()
	alerts, _ := h.store.Alerts(ctx, store.AlertFilter{})
	id := alerts[0].ID
	path := "/alerts/" + itoa(id)

	_, body := h.get(path)
	if strings.Contains(body, "<script>alert") || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("alert detail not escaped")
	}
	if res, _ := h.post(path+"/ack", url.Values{"csrf": {csrf}, "back": {"https://evil.example/"}}); res.Header.Get("Location") != path {
		t.Fatalf("ack redirected to %q", res.Header.Get("Location"))
	}
	if a, _ := h.store.Alert(ctx, id); a.Status != store.StatusAcked || a.AckedBy != email {
		t.Fatalf("after ack: %+v", a)
	}
	h.post(path+"/resolve", url.Values{"csrf": {csrf}})
	if a, _ := h.store.Alert(ctx, id); a.Status != store.StatusResolved {
		t.Fatalf("after resolve: %s", a.Status)
	}
	if res, _ := h.get("/alerts/999"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("missing alert: status %d", res.StatusCode)
	}
}

func TestOverviewShowsSilentHostFirst(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, id := range []string{"a-quiet", "b-alive"} {
		if err := h.store.Enroll(ctx, id, make([]byte, 32), now.Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	deliver := func(host string, at time.Time) {
		hs, _ := h.store.Host(ctx, host)
		e := protocol.Envelope{HostID: host, Kind: protocol.KindHeartbeat, Sequence: hs.Chain.Sequence + 1, SentAt: at}
		if err := h.store.Accept(ctx, e, hs.Chain, protocol.ChainState{Sequence: e.Sequence}, at); err != nil {
			t.Fatal(err)
		}
	}
	deliver("a-quiet", now.Add(-time.Hour))
	deliver("b-alive", now.Add(-time.Minute))
	h.login()
	_, body := h.get("/")
	quiet, alive := strings.Index(body, `href="/hosts/a-quiet"`), strings.Index(body, `href="/hosts/b-alive"`)
	if quiet < 0 || alive < 0 || quiet > alive {
		t.Fatal("the silent host is not listed before the responding one")
	}
	if !regexp.MustCompile(`c-silent on">\s*<dt><svg[^>]*>.*?</svg>muti</dt>\s*<dd><span class="n">1</span>`).MatchString(body) {
		t.Fatal("the counters do not count the silent host")
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t)
	res, _ := h.get("/login")
	csp := res.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP %q", csp)
	}
}

func TestSilences(t *testing.T) {
	until := now
	enrolled := until.Add(-3 * time.Hour)
	var marks []store.Mark
	beat := func(from, to time.Time) {
		for m := from; m.Before(to); m = m.Add(time.Minute) {
			marks = append(marks, store.Mark{At: m, Kind: protocol.KindHeartbeat})
		}
	}
	// Beats for an hour, a 20-minute gap, beats again, a 2-minute hiccup, then nothing.
	beat(enrolled, enrolled.Add(time.Hour))
	beat(enrolled.Add(80*time.Minute), enrolled.Add(100*time.Minute))
	beat(enrolled.Add(102*time.Minute), enrolled.Add(120*time.Minute))
	marks = append(marks, store.Mark{At: enrolled.Add(30 * time.Minute), Kind: protocol.KindSnapshot})

	got := silences(marks, enrolled, until, 24*time.Hour, 3*time.Minute)
	if len(got) != 2 {
		t.Fatalf("silences = %+v, want the ongoing one and the 21-minute gap", got)
	}
	if !got[0].Ongoing || got[0].Duration() != 61*time.Minute {
		t.Errorf("ongoing silence = %+v", got[0])
	}
	if got[1].Ongoing || got[1].Duration() != 21*time.Minute {
		t.Errorf("past silence = %+v", got[1])
	}
}

func TestMostUrgent(t *testing.T) {
	alerts := []store.Alert{
		{ID: 1, Severity: "critical", Status: store.StatusAcked, CreatedAt: now.Add(-5 * time.Hour)},
		{ID: 2, Severity: "high", Status: store.StatusOpen, CreatedAt: now.Add(-3 * time.Hour)},
		{ID: 3, Severity: "critical", Status: store.StatusResolved, CreatedAt: now.Add(-9 * time.Hour)},
		{ID: 4, Severity: "high", Status: store.StatusOpen, CreatedAt: now.Add(-4 * time.Hour)},
	}
	if a := mostUrgent(alerts); a == nil || a.ID != 4 {
		t.Fatalf("most urgent = %+v, want the oldest untaken high alert over a critical one already taken", a)
	}
	if a := mostUrgent(alerts[:1]); a == nil || a.ID != 1 {
		t.Fatalf("with only a taken alert: %+v", a)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestHostPageAndRevoke(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.store.Enroll(ctx, "web-01", make([]byte, 32), now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	csrf := h.login()
	res, body := h.get("/hosts/web-01")
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "muto dalla registrazione") || !strings.Contains(body, "in corso") {
		t.Fatalf("host page: status %d", res.StatusCode)
	}
	if res, _ := h.get("/hosts/nope"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown host: status %d", res.StatusCode)
	}

	if res, _ := h.post("/hosts/web-01/revoke", url.Values{"csrf": {csrf}, "confirm": {"web-02"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("revoke with the wrong name: status %d", res.StatusCode)
	}
	if res, _ := h.post("/hosts/web-01/revoke", url.Values{"csrf": {csrf}, "confirm": {"web-01"}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke: status %d", res.StatusCode)
	}
	if hs, _ := h.store.Host(ctx, "web-01"); !hs.Revoked {
		t.Fatal("host not revoked")
	}
	if _, body := h.get("/hosts/web-01"); strings.Contains(body, `action="/hosts/web-01/revoke"`) || !strings.Contains(body, "revocato") {
		t.Fatal("revoked host still offers revocation or hides its state")
	}
}

func TestAlertViews(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for i, st := range []string{"open", "acked", "resolved"} {
		if _, err := h.store.Raise(ctx, store.Alert{HostID: "web-01", Fingerprint: "fp:" + st, Severity: "medium", Kind: "web", Title: "alert " + st}, now.Add(-time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := h.store.Alerts(ctx, store.AlertFilter{})
	for _, a := range all {
		switch a.Fingerprint {
		case "fp:acked":
			_ = h.store.Ack(ctx, a.ID, email, now)
		case "fp:resolved":
			_ = h.store.Resolve(ctx, a.ID, email, now)
		}
	}
	h.login()
	for view, want := range map[string][]string{
		"open":         {"alert open", "alert acked"},
		"acknowledged": {"alert acked"},
		"resolved":     {"alert resolved"},
		"all":          {"alert open", "alert acked", "alert resolved"},
	} {
		_, body := h.get("/alerts?view=" + view)
		if n := strings.Count(body, `<td class="what">`); n != len(want) {
			t.Errorf("view %s: %d rows, want %d", view, n, len(want))
		}
		for _, w := range want {
			if !strings.Contains(body, w) {
				t.Errorf("view %s misses %q", view, w)
			}
		}
	}
	if _, body := h.get("/alerts?view=all&host=web-02"); strings.Contains(body, `<td class="what">`) {
		t.Error("host filter ignored")
	}
}

func TestLogoutAndTheme(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	themes := []string{}
	for range 3 {
		res, _ := h.post("/theme", url.Values{"csrf": {csrf}, "back": {"/alerts"}})
		if res.Header.Get("Location") != "/alerts" {
			t.Fatalf("theme redirected to %q", res.Header.Get("Location"))
		}
		_, body := h.get("/")
		m := regexp.MustCompile(`Tema: ([a-z ]+)<`).FindStringSubmatch(body)
		themes = append(themes, m[1])
	}
	if strings.Join(themes, ",") != "chiaro,scuro,di sistema" {
		t.Fatalf("theme cycle = %v", themes)
	}

	if res, _ := h.post("/logout", url.Values{"csrf": {csrf}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: status %d", res.StatusCode)
	}
	if res, _ := h.get("/"); res.StatusCode != http.StatusSeeOther {
		t.Fatal("still signed in after logout")
	}
}

func TestFormatting(t *testing.T) {
	for d, want := range map[time.Duration]string{30 * time.Second: "1 min", 59 * time.Minute: "59 min", 2 * time.Hour: "2 h", 125 * time.Minute: "2 h 5 min", 50 * time.Hour: "2 g 2 h"} {
		if got := duration(d); got != want {
			t.Errorf("duration(%v) = %q, want %q", d, got, want)
		}
	}
	for n, want := range map[int]string{512: "512 B", 2048: "2 KB", 3 << 20: "3.0 MB"} {
		if got := size(n); got != want {
			t.Errorf("size(%d) = %q, want %q", n, got, want)
		}
	}
	if shape("unknown", "") != "" || !strings.Contains(string(shape("high", "acknowledged")), "acked") {
		t.Error("shape")
	}
}

func TestPanelFollowsTheSelectedAlert(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, a := range []store.Alert{
		{HostID: "web-01", Fingerprint: "a", Severity: "critical", Kind: "accounts", Title: "Root account", Detail: "first detail"},
		{HostID: "web-01", Fingerprint: "b", Severity: "medium", Kind: "web", Title: "Scan in the logs", Detail: "second detail"},
	} {
		if _, err := h.store.Raise(ctx, a, now); err != nil {
			t.Fatal(err)
		}
	}
	alerts, _ := h.store.Alerts(ctx, store.AlertFilter{})
	medium := alerts[1].ID
	h.login()

	_, body := h.get("/")
	if !strings.Contains(body, "Da guardare per primo") || !strings.Contains(body, "first detail") {
		t.Fatal("without a selection the panel does not show the most urgent alert")
	}
	link := "/?a=" + itoa(medium) + "#focus"
	if !strings.Contains(body, `href="`+link+`"`) {
		t.Fatalf("rows do not link to their selection (%s)", link)
	}

	for _, page := range []string{"/?a=", "/alerts?view=open&a="} {
		_, body = h.get(page + itoa(medium))
		if !strings.Contains(body, "Allarme selezionato") || !strings.Contains(body, "second detail") || strings.Contains(body, "first detail") {
			t.Errorf("%s: the panel does not show the selected alert", page)
		}
		if !strings.Contains(body, `href="/alerts/`+itoa(medium)+`">Apri il dettaglio`) {
			t.Errorf("%s: no way into the selected alert", page)
		}
	}
	if _, body = h.get("/?a=999"); !strings.Contains(body, "Da guardare per primo") {
		t.Error("an unknown selection does not fall back to the most urgent alert")
	}
}

// A browser the user signed in from keeps its own lane: guessing from anywhere else, in
// parallel and from any number of addresses, does not slow it down.
func TestKnownBrowserIsNeverSlowed(t *testing.T) {
	h := newHarness(t)
	begin := time.Now()
	h.login() // the harness client becomes a known browser
	// A plain sign-in on this machine, password check included: the race detector and a slow
	// CI make an absolute bound meaningless.
	plain := time.Since(begin)
	attacker := func() {
		form := url.Values{"email": {email}, "password": {"wrong-password-here"}}
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, h.srv.URL+"/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = res.Body.Close()
		}
	}
	var wg sync.WaitGroup
	start := time.Now()
	for range 10 {
		wg.Add(1)
		go func() { defer wg.Done(); attacker() }()
	}
	wg.Wait()
	// The unknown attempts share the email's lane: failures 6 to 10 wait 10 to 160 ms in turn.
	if took := time.Since(start); took < 250*time.Millisecond {
		t.Fatalf("parallel guesses were not serialised and delayed: %v", took)
	}
	start = time.Now()
	res, _ := h.post("/login", url.Values{"email": {email}, "password": {password}})
	if took := time.Since(start); res.StatusCode != http.StatusSeeOther || took > 3*plain+200*time.Millisecond {
		t.Fatalf("the known browser: status %d after %v (a plain sign-in takes %v)", res.StatusCode, took, plain)
	}
}

// A one-time link lets the user in from a new browser, makes it a known one, and works once.
func TestLoginLink(t *testing.T) {
	h := newHarness(t)
	token, err := h.store.CreateLoginLink(context.Background(), email, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CreateLoginLink(context.Background(), "nobody@example.net", now); err == nil {
		t.Fatal("a link was made for an email that is not a user")
	}
	res, _ := h.post("/login/link", url.Values{"t": {token}})
	if res.StatusCode != http.StatusSeeOther || !strings.Contains(strings.Join(res.Header.Values("Set-Cookie"), ";"), deviceCookie+"=") {
		t.Fatalf("link: status %d, cookies %v", res.StatusCode, res.Header.Values("Set-Cookie"))
	}
	if res, _ := h.get("/"); res.StatusCode != http.StatusOK {
		t.Fatalf("not signed in after the link: %d", res.StatusCode)
	}
	if res, _ := h.post("/login/link", url.Values{"t": {token}}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("the link worked twice: %d", res.StatusCode)
	}
}

// An email that is not a user is slowed down like one that is: the delays do not tell them apart.
func TestUnknownEmailsHaveTheirOwnLane(t *testing.T) {
	h := newHarness(t)
	took := func(addr string) time.Duration {
		for range 6 {
			h.post("/login", url.Values{"email": {addr}, "password": {"wrong-password-here"}})
		}
		start := time.Now()
		h.post("/login", url.Values{"email": {addr}, "password": {"wrong-password-here"}})
		return time.Since(start)
	}
	known, unknown := took(email), took("nobody@example.net")
	if unknown < known/2 || unknown > known*2+100*time.Millisecond {
		t.Fatalf("delays tell users apart: user %v, unknown %v", known, unknown)
	}
	if other := took("someone-else@example.net"); other > known*2+100*time.Millisecond {
		t.Fatalf("unknown emails share a lane: %v", other)
	}
}

// Opening a sign-in link shows a button; only submitting it uses the link.
func TestLoginLinkNeedsAClick(t *testing.T) {
	h := newHarness(t)
	token, _ := h.store.CreateLoginLink(context.Background(), email, now)
	res, body := h.get("/login/link?t=" + token)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `name="t" value="`+token+`"`) || len(res.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("opening the link: status %d, cookies %v", res.StatusCode, res.Header.Values("Set-Cookie"))
	}
	if res, _ := h.post("/login/link", url.Values{"t": {token}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("submitting the link: %d", res.StatusCode)
	}
	if res, _ := h.post("/login/link", url.Values{"t": {token}}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("the link worked twice: %d", res.StatusCode)
	}
}

func TestPasswordResetCancelsLinksAndDevicesAreBounded(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token, _ := h.store.CreateLoginLink(ctx, email, now)
	if err := h.store.SetUser(ctx, email, password, now); err != nil {
		t.Fatal(err)
	}
	if res, _ := h.post("/login/link", url.Values{"t": {token}}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("a link made before the reset still works: %d", res.StatusCode)
	}
	var first string
	for i := range store.MaxDevices + 5 {
		d, err := h.store.CreateDevice(ctx, email, now.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = d
		}
	}
	if _, err := h.store.DeviceEmail(ctx, first, now); err == nil {
		t.Fatal("the oldest browser is still known past the bound")
	}
	if n, err := h.store.RevokeDevices(ctx, email); err != nil || n != store.MaxDevices {
		t.Fatalf("revoked %d browsers, %v", n, err)
	}
}

// Unknown emails use fixed lanes: however many arrive, the users' table does not grow and the
// same email always lands in the same lane.
func TestUnknownLanesAreFixed(t *testing.T) {
	l := newLimiter(time.Millisecond, 15*time.Millisecond)
	clock := func() time.Time { return now }
	for i := range 5000 {
		done, ok := l.begin(t.Context(), "unknown:x"+strconv.Itoa(i)+"@example.net", clock)
		if !ok {
			t.Fatal("unknown lane not taken")
		}
		done(false)
	}
	if len(l.entries) != 0 {
		t.Fatalf("unknown emails grew the users' table to %d", len(l.entries))
	}
	first, again := l.lane("a@example.net"), l.lane("a@example.net")
	if first != again || newLimiter(time.Millisecond, time.Millisecond).lane("a@example.net") == first && l.lane("b@example.net") == first {
		t.Fatal("lanes are not stable per process, or not keyed")
	}
}

// With every shared password check taken by a flood, a known browser still gets one.
func TestKnownBrowserHasAReservedCheck(t *testing.T) {
	s := &server{checks: make(chan struct{}, 1), knownCheck: make(chan struct{}, 1)}
	s.checks <- struct{}{} // the flood holds the shared check
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, ok := s.checkSlot(ctx, false); ok {
		t.Fatal("an unknown browser got past a full set of checks")
	}
	release, ok := s.checkSlot(t.Context(), true)
	if !ok {
		t.Fatal("the known browser has no check of its own")
	}
	release()
}

// The page of a policy alert shows the whole diff kept with it, which the detail cuts short.
func TestPolicyAlertShowsCompleteDiff(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.store.Enroll(ctx, "web-01", make([]byte, 32), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Raise(ctx, store.Alert{HostID: "web-01", Fingerprint: "persistence-change:policy:/etc/sudoers.d/x|1", Severity: "high",
		Kind: "persistence-change", Title: "Politica sudo cambiata"}, now); err != nil {
		t.Fatal(err)
	}
	id, _ := h.store.AlertID(ctx, "web-01", "persistence-change:policy:/etc/sudoers.d/x|1")
	if err := h.store.SetAlertDiff(ctx, id, "+ b ALL=(ALL) NOPASSWD: ALL\n+ <script>", now); err != nil {
		t.Fatal(err)
	}
	h.login()
	_, body := h.get("/alerts/" + itoa(id))
	if !strings.Contains(body, "Confronto completo") || !strings.Contains(body, "&#43; b ALL=(ALL) NOPASSWD: ALL") || strings.Contains(body, "<script>") {
		t.Fatalf("complete diff not shown:\n%s", body)
	}
}

func TestEnrollCommandInstallsTheSameRelease(t *testing.T) {
	for _, tc := range []struct{ choice, release, want string }{
		{"", "0.1.1", "deb"},
		{"rpm", "0.1.1", "rpm"},
		{"installed", "0.1.1", "installed"},
		{"anything", "0.1.1", "deb"},
		{"deb", "", "installed"},
	} {
		if got := enrollSystem(tc.choice, tc.release); got != tc.want {
			t.Errorf("enrollSystem(%q, %q) = %q, want %q", tc.choice, tc.release, got, tc.want)
		}
	}
	for v, want := range map[string]string{"0.1.1": "0.1.1", "v0.2.0": "0.2.0", "dev": "", "v0.1.0-3-g1a2b3c4": "", "0.0.1-dev": ""} {
		if got := (&server{Config: Config{Release: v}}).release(); got != want {
			t.Errorf("release of %q = %q, want %q", v, got, want)
		}
	}
	enroll := "echo 'tw1.x' | sudo tripwatch-sensor enroll -token-file - && sudo systemctl enable --now tripwatch-sensor"
	deb := enrollCommand("deb", "0.1.1", "tw1.x")
	if !strings.Contains(deb, "/download/v0.1.1/$f") || !strings.Contains(deb, "f=tripwatch-sensor_0.1.1_$(dpkg --print-architecture).deb") ||
		!strings.Contains(deb, "sudo apt-get install -y ./$f && rm -f $f && ") || !strings.HasSuffix(deb, enroll) {
		t.Errorf("deb command = %s", deb)
	}
	rpm := enrollCommand("rpm", "0.1.1", "tw1.x")
	if !strings.Contains(rpm, "/download/v0.1.1/tripwatch-sensor-0.1.1-1.$(uname -m).rpm && ") || !strings.HasSuffix(rpm, enroll) {
		t.Errorf("rpm command = %s", rpm)
	}
	if got := enrollCommand("installed", "0.1.1", "tw1.x"); got != enroll {
		t.Errorf("enrollment alone = %s", got)
	}
}

// Alerts of one rule on one host are one row that opens onto them, and a group is resolved at
// once; a rule with a single alert keeps its plain row.
func TestAlertsOfOneRuleAreGrouped(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.store.Enroll(ctx, "web-01", make([]byte, 32), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	raise := func(fp, severity, title string) int64 {
		t.Helper()
		if _, err := h.store.Raise(ctx, store.Alert{HostID: "web-01", Fingerprint: fp, Severity: severity, Kind: "packages", Title: title}, now); err != nil {
			t.Fatal(err)
		}
		id, err := h.store.AlertID(ctx, "web-01", fp)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	var hidden []int64
	for _, p := range []string{"/usr/lib/.a", "/usr/lib/.b", "/usr/share/.c"} {
		hidden = append(hidden, raise("packages:hidden:"+p, "high", "Elemento nascosto in /usr: "+p))
	}
	single := raise("packages:unowned:/usr/bin/x", "high", "Eseguibile senza pacchetto: /usr/bin/x")

	csrf := h.login()
	_, body := h.get("/hosts/web-01")
	heads := regexp.MustCompile(`<button type="button" class="disclose"[^>]*aria-controls="(rows-[0-9a-f]+)"[^>]*><span class="label">([^<]*)</span><span class="tally-n">(\d+)</span>`).FindAllStringSubmatch(body, -1)
	if len(heads) != 1 || heads[0][2] != "Elemento nascosto in /usr" || heads[0][3] != "3" {
		t.Fatalf("group heads = %q", heads)
	}
	if !strings.Contains(body, `id="`+heads[0][1]+`" hidden>`) {
		t.Error("the rows of a group are not closed at first")
	}
	if !strings.Contains(body, `href="/alerts/`+itoa(single)+`"`) {
		t.Error("an alert alone in its rule lost its own row")
	}

	form := url.Values{"csrf": {csrf}, "back": {"/hosts/web-01"}}
	for _, id := range hidden {
		form.Add("id", itoa(id))
	}
	if res, _ := h.post("/bulk/resolve", form); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("bulk resolve: status %d", res.StatusCode)
	}
	for _, id := range append(hidden, single) {
		a, err := h.store.Alert(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if want := id != single; (a.Status == "resolved") != want {
			t.Errorf("alert %d: status %q", id, a.Status)
		}
	}
	if res, _ := h.post("/bulk/delete", form); res.StatusCode != http.StatusNotFound {
		t.Errorf("unknown bulk action: status %d", res.StatusCode)
	}
}

func TestGroupLabel(t *testing.T) {
	titles := func(ts ...string) []store.Alert {
		var out []store.Alert
		for _, t := range ts {
			out = append(out, store.Alert{Title: t})
		}
		return out
	}
	for _, tc := range []struct {
		alerts []store.Alert
		want   string
	}{
		{titles("Script nelle cartelle di upload", "Script nelle cartelle di upload"), "Script nelle cartelle di upload"},
		{titles("Elemento nascosto in /usr: /usr/src/a/.x", "Elemento nascosto in /usr: /usr/src/b/.y"), "Elemento nascosto in /usr"},
		{titles("Impostazione da sviluppo in /srv/app/one", "Impostazione da sviluppo in /srv/app/two"), "Impostazione da sviluppo in /srv/app/"},
		{titles("Alpha", "Beta"), "Alpha"},
	} {
		if got := commonLabel(tc.alerts); got != tc.want {
			t.Errorf("commonLabel = %q, want %q", got, tc.want)
		}
	}
	if alertRule("weblog:upload_script:/up/a.php|1") != "weblog:upload_script" || alertRule("chain:broken") != "chain:broken" {
		t.Error("alertRule does not keep the kind and rule only")
	}
}
