package ui

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP, as the verifier computes it
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func totpCode(t *testing.T, secret string) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha1.New, key)
	_ = binary.Write(mac, binary.BigEndian, now.Unix()/30)
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1000000)
}

// A user sets up the second factor from their account; signing in then asks the code, refuses a
// wrong one and opens nothing until it is given; a recovery code works once.
func TestSecondFactorSignIn(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	_, body := h.post("/account/2fa-begin", url.Values{"csrf": {csrf}})
	m := regexp.MustCompile(`<pre class="datum mono">([A-Z2-7]+)</pre>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no secret shown")
	}
	if res, _ := h.get("/account/2fa/qr.png"); res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("qr: %d", res.StatusCode)
	}
	if res, _ := h.post("/account/2fa-confirm", url.Values{"csrf": {csrf}, "code": {"000000"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("wrong confirmation accepted")
	}
	_, body = h.post("/account/2fa-confirm", url.Values{"csrf": {csrf}, "code": {totpCode(t, m[1])}})
	codes := regexp.MustCompile(`[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}`).FindAllString(body, -1)
	if len(codes) != 10 {
		t.Fatalf("%d recovery codes shown", len(codes))
	}
	if res, _ := h.post("/account/2fa-begin", url.Values{"csrf": {csrf}}); res.StatusCode != http.StatusConflict {
		t.Fatalf("second factor replaced without a code: %d", res.StatusCode)
	}
	h.post("/logout", url.Values{"csrf": {csrf}})

	res, _ := h.post("/login", url.Values{"email": {email}, "password": {password}, "next": {"/alerts"}})
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "/login/2fa") {
		t.Fatalf("after the password: %q", loc)
	}
	for _, c := range res.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, deviceCookie+"=") {
			t.Fatal("the password alone made the browser a known one")
		}
	}
	if res, _ := h.get("/alerts"); res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(res.Header.Get("Location"), "/login/2fa") {
		t.Fatalf("a page before the code: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if res, _ := h.post("/login/2fa", url.Values{"code": {"123456"}, "next": {"/alerts"}}); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", res.StatusCode)
	}
	if res, _ := h.post("/login/2fa", url.Values{"code": {codes[0]}, "next": {"/alerts"}}); res.Header.Get("Location") != "/alerts" {
		t.Fatalf("recovery code: %q", res.Header.Get("Location"))
	}
	if res, _ := h.get("/alerts"); res.StatusCode != http.StatusOK {
		t.Fatalf("after the code: %d", res.StatusCode)
	}
	_, body = h.get("/account")
	if !strings.Contains(body, "9 recovery codes left") || !strings.Contains(body, "this one") {
		t.Error("account page does not show the codes left or the session")
	}
	if on, _ := h.store.TOTPEnabled(context.Background(), email); !on {
		t.Fatal("second factor off")
	}
}

// Ending sessions that do not exist leaves no trace in the audit log: a user signed in cannot
// push an administrator's entries out with made-up IDs. Ending a real one is recorded.
func TestEndSessionAuditsOnlyRealSessions(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	ctx := context.Background()
	before, err := h.store.AuditLog(ctx, 10000)
	if err != nil {
		t.Fatal(err)
	}
	for range 50 {
		h.post("/account/end-session", url.Values{"csrf": {csrf}, "id": {"00"}})
	}
	after, _ := h.store.AuditLog(ctx, 10000)
	if len(after) != len(before) {
		t.Fatalf("%d audit entries from sessions that do not exist", len(after)-len(before))
	}
	token, err := h.store.Login(ctx, email, password, now)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(token))
	h.post("/account/end-session", url.Values{"csrf": {csrf}, "id": {hex.EncodeToString(sum[:])}})
	if after, _ := h.store.AuditLog(ctx, 10000); len(after) != len(before)+1 {
		t.Errorf("ending a real session: %d entries, want %d", len(after), len(before)+1)
	}
}
