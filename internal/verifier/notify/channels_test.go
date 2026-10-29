package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// Each channel gets the alerts at or above its severity raised after it was set up; the webhook
// payload is signed; a failing channel raises its own alert and the others are not repeated.
func TestChannels(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	t0 := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	if _, err := st.Raise(ctx, store.Alert{HostID: "web-01", Fingerprint: "old", Severity: "critical", Kind: "web", Title: "before the channels"}, t0.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	tg, _ := st.AddChannel(ctx, store.Channel{Kind: store.ChannelTelegram, Name: "ops chat", MinSeverity: "critical", Settings: store.ChannelSettings{BotToken: "123:secret", ChatID: "-100"}}, t0)
	if _, err := st.AddChannel(ctx, store.Channel{Kind: store.ChannelWebhook, Name: "siem", MinSeverity: "medium", Settings: store.ChannelSettings{URL: "https://hooks.example.net/tw", Secret: "s3"}}, t0); err != nil {
		t.Fatal(err)
	}
	for _, a := range []store.Alert{
		{HostID: "web-01", Fingerprint: "c", Severity: "critical", Kind: "web", Title: "webshell"},
		{HostID: "web-01", Fingerprint: "m", Severity: "medium", Kind: "ssh", Title: "password login"},
		{HostID: "web-01", Fingerprint: "l", Severity: "low", Kind: "apps", Title: "debug on"},
	} {
		if _, err := st.Raise(ctx, a, t0.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}

	posts := map[string][]byte{}
	var signature string
	failTelegram := true
	n := &Notifier{Store: st, Now: func() time.Time { return t0.Add(2 * time.Minute) }, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		post: func(_ context.Context, url string, body []byte, header http.Header) error {
			if strings.Contains(url, "telegram") && failTelegram {
				return errors.New("https://api.telegram.org: connection refused")
			}
			posts[url] = body
			signature = header.Get(SignatureHeader)
			return nil
		}}
	n.Round(ctx)

	hook := posts["https://hooks.example.net/tw"]
	var payload struct {
		Alerts []struct{ Title string } `json:"alerts"`
	}
	if err := json.Unmarshal(hook, &payload); err != nil || len(payload.Alerts) != 2 || payload.Alerts[0].Title != "webshell" || payload.Alerts[1].Title != "password login" {
		t.Fatalf("webhook got %s", hook)
	}
	mac := hmac.New(sha256.New, []byte("s3"))
	mac.Write(hook)
	if signature != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Errorf("signature %q", signature)
	}
	open, _ := st.Alerts(ctx, store.AlertFilter{HostID: "verifier", Statuses: []string{store.StatusOpen}})
	if len(open) != 1 || !strings.Contains(open[0].Title, "ops chat") || strings.Contains(open[0].Detail, "123:secret") {
		t.Fatalf("failing channel raised %+v", open)
	}
	c, _ := st.Channel(ctx, tg)
	if c.LastError == "" || !c.LastOK.IsZero() {
		t.Errorf("telegram result %+v", c)
	}

	// Delivered through the webhook, so not sent again: the next round carries only the alert
	// about the failing channel, which the webhook wants too. The telegram channel recovers on
	// the next alerts.
	posts = map[string][]byte{}
	failTelegram = false
	n.Round(ctx)
	if again := string(posts["https://hooks.example.net/tw"]); strings.Contains(again, "webshell") || !strings.Contains(again, "not being sent: ops chat") {
		t.Fatalf("second round sent %s", again)
	}
	if _, err := st.Raise(ctx, store.Alert{HostID: "web-02", Fingerprint: "c2", Severity: "critical", Kind: "web", Title: "another"}, t0.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	n.Round(ctx)
	var sent map[string]any
	for url, body := range posts {
		if strings.Contains(url, "telegram") {
			_ = json.Unmarshal(body, &sent)
		}
	}
	if sent == nil || sent["chat_id"] != "-100" || !strings.Contains(sent["text"].(string), "another") || strings.Contains(sent["text"].(string), "before the channels") {
		t.Fatalf("telegram got %v", sent)
	}
	if open, _ := st.Alerts(ctx, store.AlertFilter{HostID: "verifier", Statuses: []string{store.StatusOpen}}); len(open) != 0 {
		t.Errorf("channel alert still open: %+v", open)
	}
}
