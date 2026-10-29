package ui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

func (h *harness) api(method, path, token string) (int, string) {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := h.http.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

// Programs read with a token as its owner; only a write token changes alerts; a browser's
// session is no token; a revoked token, or one whose owner sees fewer servers, gets no more.
func TestAPI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, id := range []string{"web-01", "db-01"} {
		if err := h.store.Enroll(ctx, id, make([]byte, 32), now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := h.store.Raise(ctx, store.Alert{HostID: id, Fingerprint: "f", Severity: "high", Kind: "web", Title: "on " + id}, now); err != nil {
			t.Fatal(err)
		}
	}
	csrf := h.login()
	if code, _ := h.api("GET", "/api/v1/alerts", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token, with a session cookie: %d", code)
	}
	mint := func(write bool) string {
		form := url.Values{"csrf": {csrf}, "name": {"siem"}, "days": {"30"}}
		if write {
			form.Set("write", "on")
		}
		_, body := h.post("/settings/api", form)
		m := regexp.MustCompile(`twk_[A-Za-z0-9_-]+`).FindString(body)
		if m == "" {
			t.Fatal("no token shown")
		}
		return m
	}
	read, write := mint(false), mint(true)

	code, body := h.api("GET", "/api/v1/alerts?status=open&severity=high", read)
	var list struct {
		Alerts []struct {
			ID   int64  `json:"id"`
			Host string `json:"host"`
		} `json:"alerts"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(body), &list) != nil || len(list.Alerts) != 2 {
		t.Fatalf("list: %d %s", code, body)
	}
	id := itoa(list.Alerts[0].ID)
	if code, _ := h.api("POST", "/api/v1/alerts/"+id+"/ack", read); code != http.StatusForbidden {
		t.Fatalf("read token acked: %d", code)
	}
	if code, _ := h.api("POST", "/api/v1/alerts/"+id+"/delete", write); code != http.StatusNotFound {
		t.Fatalf("unknown action: %d", code)
	}
	if code, body := h.api("POST", "/api/v1/alerts/"+id+"/ack", write); code != http.StatusOK || !strings.Contains(body, `"status":"acknowledged"`) {
		t.Fatalf("write token ack: %d %s", code, body)
	}
	if log, _ := h.store.AuditLog(ctx, 5); !strings.Contains(log[0].Actor, "api:siem") {
		t.Errorf("audit actor %q", log[0].Actor)
	}

	if err := h.store.SetHostDetails(ctx, "web-01", "", []string{"team=web"}, ""); err != nil {
		t.Fatal(err)
	}
	token, _, _ := h.store.CreateInvite(ctx, "web@example.net", store.RoleViewer, email, now)
	if _, _, err := h.store.AcceptInvite(ctx, token, "a long new password", now); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetScope(ctx, "web@example.net", "team=web"); err != nil {
		t.Fatal(err)
	}
	scoped, err := h.store.CreateAPIToken(ctx, "web view", "web@example.net", false, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, body := h.api("GET", "/api/v1/hosts", scoped); strings.Contains(body, "db-01") || !strings.Contains(body, "web-01") {
		t.Errorf("scoped token sees %s", body)
	}

	tokens, _ := h.store.APITokens(ctx)
	for _, tk := range tokens {
		h.post("/settings/api/"+itoa(tk.ID)+"/revoke", url.Values{"csrf": {csrf}})
	}
	if code, _ := h.api("GET", "/api/v1/hosts", read); code != http.StatusUnauthorized {
		t.Errorf("revoked token: %d", code)
	}
}
