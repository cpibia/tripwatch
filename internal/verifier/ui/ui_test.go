package ui

import (
	"context"
	"encoding/json"
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
	h, err := New(Config{Store: st, CA: ca, IngestURL: "https://verifier.example.net:8443/v1/envelopes", SilenceAfter: 3 * time.Minute,
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

func TestLoginLimiter(t *testing.T) {
	h := newHarness(t)
	for range 10 {
		h.post("/login", url.Values{"email": {email}, "password": {"wrong-password-here"}})
	}
	res, _ := h.post("/login", url.Values{"email": {email}, "password": {password}})
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("after 10 failures the right password got status %d, want 429", res.StatusCode)
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
	res, body := h.post("/enroll", url.Values{"host": {"web-01"}, "csrf": {csrf}})
	if res.StatusCode != http.StatusOK || !strings.Contains(res.Header.Get("Content-Disposition"), `filename="tripwatch-web-01.json"`) {
		t.Fatalf("enroll: status %d, disposition %q", res.StatusCode, res.Header.Get("Content-Disposition"))
	}
	var b pki.Bundle
	if err := json.Unmarshal([]byte(body), &b); err != nil || b.HostID != "web-01" || b.SigningKey == "" {
		t.Fatalf("bundle: %v %+v", err, b)
	}

	res, body = h.post("/enroll", url.Values{"host": {"web-01"}, "csrf": {csrf}})
	if res.StatusCode != http.StatusConflict || !strings.Contains(body, `name="replace"`) {
		t.Fatalf("enrolling an existing host without confirmation: status %d", res.StatusCode)
	}
	res, _ = h.post("/enroll", url.Values{"host": {"web-01"}, "csrf": {csrf}, "replace": {"yes"}})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("confirmed re-enrollment: status %d", res.StatusCode)
	}
	for _, bad := range []string{"../etc", "Web 01", "verifier", strings.Repeat("a", 64)} {
		if res, _ := h.post("/enroll", url.Values{"host": {bad}, "csrf": {csrf}}); res.StatusCode != http.StatusBadRequest {
			t.Errorf("host %q: status %d, want 400", bad, res.StatusCode)
		}
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
	if !regexp.MustCompile(`c-silent on">\s*<dt>muti</dt>\s*<dd><span class="n">1</span>`).MatchString(body) {
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
