package ui

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	wt "github.com/cpibia/tripwatch/internal/verifier/webauthn/webauthntest"
)

const consoleHost = "console.example.com"

var (
	challengeAttr = regexp.MustCompile(`data-webauthn="(create|get)" data-challenge="([A-Za-z0-9_-]+)"`)
	recoveryCode  = regexp.MustCompile(`[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}`)
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// prompt returns the challenge of a page's security key form of a kind.
func prompt(t *testing.T, body, kind string) []byte {
	t.Helper()
	for _, m := range challengeAttr.FindAllStringSubmatch(body, -1) {
		if m[1] == kind {
			c, err := base64.RawURLEncoding.DecodeString(m[2])
			if err != nil {
				t.Fatal(err)
			}
			return c
		}
	}
	t.Fatalf("no %q key prompt on the page", kind)
	return nil
}

// assertion is a key's answer to a page's sign-in prompt, as webauthn.js posts it.
func assertion(t *testing.T, a *wt.Authenticator, body string, form url.Values) url.Values {
	t.Helper()
	cd, ad, sig := a.Assert(consoleHost, "https://"+consoleHost, prompt(t, body, "get"))
	form.Set("credential", b64(a.ID))
	form.Set("clientData", b64(cd))
	form.Set("authenticatorData", b64(ad))
	form.Set("signature", b64(sig))
	return form
}

// addKey registers a key from the account page and returns the page that answers.
func (h *harness) addKey(csrf, name string, a *wt.Authenticator) (reply, string) {
	h.t.Helper()
	_, body := h.get("/account")
	cd, att := a.Register(consoleHost, "https://"+consoleHost, prompt(h.t, body, "create"))
	return h.post("/account/key-add", url.Values{"csrf": {csrf}, "name": {name}, "transports": {"usb"},
		"clientData": {b64(cd)}, "attestation": {b64(att)}})
}

// halfLogin gives the password and returns the second step's page.
func (h *harness) halfLogin() string {
	h.t.Helper()
	res, _ := h.post("/login", url.Values{"email": {email}, "password": {password}, "next": {"/alerts"}})
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "/login/2fa") {
		h.t.Fatalf("after the password: %q", loc)
	}
	_, body := h.get("/login/2fa?next=/alerts")
	return body
}

func (h *harness) audited(action string) string {
	h.t.Helper()
	entries, err := h.store.AuditLog(context.Background(), 1000)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, e := range entries {
		if e.Action == action {
			return e.Detail
		}
	}
	h.t.Fatalf("no %q in the audit log", action)
	return ""
}

// A key added from the account page is a second factor by itself: it brings the recovery codes,
// signing in then waits for it, a stranger's key is refused, and the page loads the script only
// where a key is asked.
func TestSecurityKeySignIn(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	if _, body := h.get("/alerts"); strings.Contains(body, "webauthn.js") {
		t.Error("the key script loads on every page")
	}
	_, body := h.get("/account")
	if !strings.Contains(body, "/static/webauthn.js") {
		t.Fatal("no key script on the account page")
	}
	a := wt.New(wt.ES256)
	res, body := h.addKey(csrf, "Desk key", a)
	if res.StatusCode != http.StatusOK || len(recoveryCode.FindAllString(body, -1)) != 10 {
		t.Fatalf("first key: %d, %d codes", res.StatusCode, len(recoveryCode.FindAllString(body, -1)))
	}
	if d := h.audited("security key added"); d != "Desk key" {
		t.Errorf("audit detail %q", d)
	}
	if res, _ := h.addKey(csrf, "Again", a); res.StatusCode != http.StatusBadRequest {
		t.Errorf("same key twice: %d", res.StatusCode)
	}
	h.post("/logout", url.Values{"csrf": {csrf}})

	body = h.halfLogin()
	if !strings.Contains(body, b64(a.ID)) || !strings.Contains(body, "Recovery code") {
		t.Fatal("the sign-in page offers neither the key nor a recovery code")
	}
	if res, _ := h.post("/login/2fa", assertion(t, wt.New(wt.ES256), body, url.Values{"next": {"/alerts"}})); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a stranger's key: %d", res.StatusCode)
	}
	h.audited("security key refused")
	_, body = h.get("/login/2fa?next=/alerts")
	if res, _ := h.post("/login/2fa", assertion(t, a, body, url.Values{"next": {"/alerts"}})); res.Header.Get("Location") != "/alerts" {
		t.Fatalf("the right key: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if res, _ := h.get("/alerts"); res.StatusCode != http.StatusOK {
		t.Fatalf("after the key: %d", res.StatusCode)
	}
	if d := h.audited("second factor given"); d != "with the security key Desk key" {
		t.Errorf("audit detail %q", d)
	}

	// A copy of the key gives itself away when its counter falls behind the original's.
	h.post("/logout", url.Values{"csrf": {csrfOf(t, h)}})
	body = h.halfLogin()
	a.Count--
	if res, _ := h.post("/login/2fa", assertion(t, a, body, url.Values{"next": {"/alerts"}})); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("counter gone back: %d", res.StatusCode)
	}
	if d := h.audited("possible cloned security key"); !strings.HasPrefix(d, "Desk key") {
		t.Errorf("audit detail %q", d)
	}
}

func csrfOf(t *testing.T, h *harness) string {
	t.Helper()
	_, body := h.get("/account")
	m := csrfField.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no CSRF token on the account page")
	}
	return m[1]
}

// A session signed in again does not change the second factors until it confirms one: with a
// key or a code. Once confirmed it adds the app next to the key, turns it off without a code,
// and removes the key.
func TestChangingFactorsTakesConfirmation(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	a := wt.New(wt.EdDSA)
	h.addKey(csrf, "Pocket key", a)
	h.post("/logout", url.Values{"csrf": {csrf}})
	body := h.halfLogin()
	h.post("/login/2fa", assertion(t, a, body, url.Values{"next": {"/alerts"}}))
	csrf = csrfOf(t, h)

	for _, action := range []string{"key-add", "key-remove", "2fa-begin"} {
		if res, _ := h.post("/account/"+action, url.Values{"csrf": {csrf}}); res.StatusCode != http.StatusForbidden {
			t.Errorf("%s before confirming: %d", action, res.StatusCode)
		}
	}
	if res, _ := h.post("/account/confirm", url.Values{"csrf": {csrf}, "code": {"000000"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong code confirmed: %d", res.StatusCode)
	}
	_, body = h.get("/account")
	if strings.Contains(body, "/account/key-remove") {
		t.Error("remove offered before confirming")
	}
	if res, _ := h.post("/account/confirm", assertion(t, a, body, url.Values{"csrf": {csrf}})); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirm with the key: %d", res.StatusCode)
	}
	h.audited("second factor confirmed")

	_, body = h.post("/account/2fa-begin", url.Values{"csrf": {csrf}})
	m := regexp.MustCompile(`<pre class="datum mono">([A-Z2-7]+)</pre>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no secret shown")
	}
	res, body := h.post("/account/2fa-confirm", url.Values{"csrf": {csrf}, "code": {totpCode(t, m[1])}})
	if res.StatusCode != http.StatusOK || recoveryCode.MatchString(body) {
		t.Fatalf("app next to a key: %d, codes shown again", res.StatusCode)
	}
	if _, body := h.post("/account/2fa-off", url.Values{"csrf": {csrf}}); !strings.Contains(body, "security keys still guard") {
		t.Fatal("app not turned off by a confirmed session")
	}

	if res, _ := h.post("/account/key-remove", url.Values{"csrf": {csrf}, "id": {b64(a.ID)}}); res.StatusCode != http.StatusOK {
		t.Fatalf("remove: %d", res.StatusCode)
	}
	if d := h.audited("security key removed"); d != "Pocket key" {
		t.Errorf("audit detail %q", d)
	}
	if on, _ := h.store.SecondFactorEnabled(context.Background(), email); on {
		t.Fatal("second factor still on")
	}
	if _, body = h.get("/account"); !strings.Contains(body, "password only") {
		t.Error("account page still shows a second factor")
	}
}
