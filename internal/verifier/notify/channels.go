package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// SignatureHeader carries the webhook payload's HMAC-SHA256 under the channel's secret, as
// "sha256=<hex>": the receiver checks it before trusting the payload.
const SignatureHeader = "X-Tripwatch-Signature"

// telegramLimit is the length Telegram accepts for one message, less room for the cut mark.
const telegramLimit = 4000

// httpTimeout bounds one HTTP send: notifications run on the same loop as the silence checks.
const httpTimeout = 20 * time.Second

// webhookAlert is an alert as a webhook receives it.
type webhookAlert struct {
	ID       int64     `json:"id"`
	Host     string    `json:"host"`
	Severity string    `json:"severity"`
	Kind     string    `json:"kind"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
	Raised   time.Time `json:"raised_at"`
	URL      string    `json:"url,omitempty"`
}

// deliver sends one message through a channel.
func (n *Notifier) deliver(ctx context.Context, c store.Channel, subject, body string, alerts []store.Alert) error {
	switch c.Kind {
	case store.ChannelEmail:
		send := n.send
		if send == nil {
			send = sendSMTP
		}
		m := Mailer{Host: c.Settings.SMTPHost, Port: c.Settings.SMTPPort, User: c.Settings.SMTPUser, Password: c.Settings.Password, From: c.Settings.From, To: c.Settings.To}
		if m.Port == "" {
			m.Port = "587"
		}
		return send(m, subject, body)
	case store.ChannelTelegram:
		text := subject + "\n\n" + body
		if len(text) > telegramLimit {
			text = strings.ToValidUTF8(text[:telegramLimit], "") + "\n[...]"
		}
		payload, err := json.Marshal(map[string]any{"chat_id": c.Settings.ChatID, "text": text, "disable_web_page_preview": true})
		if err != nil {
			return err
		}
		endpoint := "https://" + telegramHost + "/bot" + url.PathEscape(c.Settings.BotToken) + "/sendMessage"
		return n.postJSON(ctx, endpoint, payload, nil)
	case store.ChannelWebhook:
		list := make([]webhookAlert, 0, len(alerts))
		for _, a := range alerts {
			w := webhookAlert{ID: a.ID, Host: a.HostID, Severity: a.Severity, Kind: a.Kind, Title: a.Title, Detail: a.Detail, Raised: a.CreatedAt}
			if n.Mailer.BaseURL != "" {
				w.URL = fmt.Sprintf("%s/alerts/%d", strings.TrimSuffix(n.Mailer.BaseURL, "/"), a.ID)
			}
			list = append(list, w)
		}
		// "text" is what chat tools (Slack, Mattermost, Discord through their webhook bridges)
		// show; "alerts" is for programs.
		payload, err := json.Marshal(map[string]any{"text": subject + "\n\n" + body, "alerts": list})
		if err != nil {
			return err
		}
		mac := hmac.New(sha256.New, []byte(c.Settings.Secret))
		mac.Write(payload)
		header := http.Header{SignatureHeader: {"sha256=" + hex.EncodeToString(mac.Sum(nil))}}
		return n.postJSON(ctx, c.Settings.URL, payload, header)
	}
	return fmt.Errorf("unknown channel kind %q", c.Kind)
}

func (n *Notifier) postJSON(ctx context.Context, endpoint string, body []byte, header http.Header) error {
	if n.post != nil {
		return n.post(ctx, endpoint, body, header)
	}
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header[k] = v
	}
	// No redirects: a webhook answering with one would send the alerts somewhere else.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		// The Telegram address carries the bot token: keep it out of what is shown and stored.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			return fmt.Errorf("%s: %w", redactURL(endpoint), uerr.Err)
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		// Only Telegram's own answer is quoted, it says what to fix ("chat not found"). A webhook
		// may point inside the verifier's network, and its error page must not be read back
		// through the notifications page and the alerts.
		if req.URL.Host != telegramHost {
			return fmt.Errorf("%s answered %s", redactURL(endpoint), resp.Status)
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s answered %s: %s", redactURL(endpoint), resp.Status, bytes.TrimSpace(msg))
	}
	return nil
}

// telegramHost is the Bot API's address.
const telegramHost = "api.telegram.org"

// redactURL keeps the host of an address: paths and queries may hold tokens.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "the endpoint"
	}
	return u.Scheme + "://" + u.Host
}
