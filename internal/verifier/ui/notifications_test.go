package ui

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A channel is added from its form, refused with the reason when a setting has the wrong shape
// (its secret not sent back), tested, turned off and removed; the menu warning goes away while
// one is on.
func TestNotificationChannels(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	if _, body := h.get("/"); !strings.Contains(body, `Notifications <span class="long">not set up`) {
		t.Fatal("no warning without channels")
	}
	res, body := h.post("/notifications", url.Values{"csrf": {csrf}, "kind": {"telegram"}, "name": {"ops"}, "min": {"high"}, "bot_token": {"not-a-token"}, "chat_id": {"-100123"}})
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "bot token has the form") || strings.Contains(body, "not-a-token") || !strings.Contains(body, `value="-100123"`) {
		t.Fatalf("bad token: %d", res.StatusCode)
	}
	res, _ = h.post("/notifications", url.Values{"csrf": {csrf}, "kind": {"telegram"}, "name": {"broken chat"}, "min": {"critical"}, "bot_token": {"123456:" + strings.Repeat("A", 35)}, "chat_id": {"-100123"}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("add: %d", res.StatusCode)
	}
	if res, _ := h.post("/notifications", url.Values{"csrf": {csrf}, "kind": {"webhook"}, "name": {"siem"}, "min": {"medium"}, "url": {"http://plain.example.net"}, "secret": {strings.Repeat("s", 16)}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("plain http webhook accepted")
	}
	channels, _ := h.store.Channels(context.Background())
	if len(channels) != 1 || channels[0].MinSeverity != "critical" {
		t.Fatalf("channels %+v", channels)
	}
	id := channels[0].ID
	_, body = h.get("/notifications")
	if !strings.Contains(body, "broken chat") || !strings.Contains(body, "chat -100123") || strings.Contains(body, strings.Repeat("A", 35)) {
		t.Fatal("channel not listed, or its token shown")
	}
	if _, body := h.get("/"); strings.Contains(body, "not set up") {
		t.Error("warning shown with a channel on")
	}

	res, _ = h.post("/notifications/"+itoa(id)+"/test", url.Values{"csrf": {csrf}})
	if loc := res.Header.Get("Location"); loc != "/notifications?tested=failed" {
		t.Fatalf("test redirected to %q", loc)
	}
	if _, body := h.get("/notifications?tested=failed"); !strings.Contains(body, "refused by the server") {
		t.Error("test failure not shown")
	}
	h.post("/notifications/"+itoa(id)+"/disable", url.Values{"csrf": {csrf}})
	if c, _ := h.store.Channel(context.Background(), id); c.Enabled {
		t.Error("still on")
	}
	h.post("/notifications/"+itoa(id)+"/delete", url.Values{"csrf": {csrf}})
	if channels, _ := h.store.Channels(context.Background()); len(channels) != 0 {
		t.Error("not removed")
	}
	if res, _ := h.post("/notifications/"+itoa(id)+"/test", url.Values{"csrf": {csrf}}); res.StatusCode != http.StatusNotFound {
		t.Errorf("removed channel: %d", res.StatusCode)
	}
}
