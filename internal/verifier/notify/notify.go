// Package notify sends new alerts by email, Telegram and webhook.
package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/smtp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// Mailer holds the SMTP settings. With no Host, notifications are disabled.
type Mailer struct {
	Host     string
	Port     string
	User     string
	Password string
	From     string
	To       []string
	// BaseURL is the address of the web interface, used for links in the message.
	BaseURL string
}

func (m Mailer) Enabled() bool { return m.Host != "" && m.From != "" && len(m.To) > 0 }

// Notifier sends the alerts not yet notified, grouped in one message per channel and round: to
// the email configured in the environment, and to the channels set up in the interface.
type Notifier struct {
	Store  *store.Store
	Mailer Mailer
	Now    func() time.Time
	Log    *slog.Logger
	send   func(m Mailer, subject, body string) error
	post   func(ctx context.Context, url string, body []byte, header http.Header) error

	mu    sync.Mutex
	sends map[SendCount]uint64
}

// SendCount is how many messages went to channels of one kind, or failed to, since the start.
type SendCount struct {
	Kind   string
	Failed bool
	N      uint64
}

// Counts returns the messages sent and failed so far by kind of channel, in a stable order.
func (n *Notifier) Counts() []SendCount {
	n.mu.Lock()
	out := make([]SendCount, 0, len(n.sends))
	for k, v := range n.sends {
		k.N = v
		out = append(out, k)
	}
	n.mu.Unlock()
	slices.SortFunc(out, func(a, b SendCount) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		if a.Failed == b.Failed {
			return 0
		}
		if a.Failed {
			return 1
		}
		return -1
	})
	return out
}

// envChannel stands for the email configured in the environment: it receives critical and high
// alerts, as it always has.
const envChannel = 0

// channels lists where to send: the environment's email, then the enabled channels.
func (n *Notifier) channels(ctx context.Context) []store.Channel {
	var out []store.Channel
	if n.Mailer.Enabled() {
		out = append(out, store.Channel{ID: envChannel, Kind: store.ChannelEmail, Name: "email from the environment", MinSeverity: "high", Enabled: true,
			Settings: store.ChannelSettings{SMTPHost: n.Mailer.Host, SMTPPort: n.Mailer.Port, SMTPUser: n.Mailer.User, Password: n.Mailer.Password, From: n.Mailer.From, To: n.Mailer.To}})
	}
	stored, err := n.Store.Channels(ctx)
	if err != nil {
		n.Log.Error("load notification channels", "err", err)
	}
	for _, c := range stored {
		if c.Enabled && !c.Unreadable {
			out = append(out, c)
		}
	}
	return out
}

// Round sends what was raised since the last round to every channel that wants it. A channel
// gets the alerts at or above its severity raised after it was set up, so a new channel does not
// receive the whole history. The alerts are marked as sent once at least one channel took them:
// a channel that keeps failing raises its own alert instead of making the others repeat.
func (n *Notifier) Round(ctx context.Context) {
	channels := n.channels(ctx)
	if len(channels) == 0 {
		return
	}
	floor := "critical"
	for _, c := range channels {
		if rank(c.MinSeverity) > rank(floor) {
			floor = c.MinSeverity
		}
	}
	alerts, err := n.Store.Unnotified(ctx, severitiesFrom(floor), perMessage)
	if err != nil || len(alerts) == 0 {
		if err != nil {
			n.Log.Error("load alerts to notify", "err", err)
		}
		return
	}
	delivered, failed := 0, 0
	var failing []string
	for _, c := range channels {
		var pick []store.Alert
		for _, a := range alerts {
			if rank(a.Severity) <= rank(c.MinSeverity) && !a.CreatedAt.Before(c.CreatedAt) {
				pick = append(pick, a)
			}
		}
		if len(pick) == 0 {
			continue
		}
		subject, body := Compose(pick, n.Mailer.BaseURL)
		err := n.deliver(ctx, c, subject, body, pick)
		n.record(ctx, c, err)
		if err != nil {
			failed++
			failing = append(failing, failureFingerprint(c))
			n.Log.Error("send notification", "channel", c.Name, "err", err)
			// Shown in the interface: notifications failing silently would leave alerts unseen.
			if _, rerr := n.Store.Raise(ctx, store.Alert{HostID: "verifier", Fingerprint: failureFingerprint(c), Severity: "medium", Kind: "verifier",
				Title: "Alert notifications are not being sent: " + c.Name, Detail: err.Error()}, n.Now()); rerr != nil {
				n.Log.Error("raise notification alert", "err", rerr)
			}
			continue
		}
		delivered++
	}
	if delivered == 0 && failed > 0 {
		return
	}
	if err := n.Store.ResolveGone(ctx, "verifier", "verifier", failing, n.Now()); err != nil {
		n.Log.Error("resolve notification alert", "err", err)
	}
	ids := make([]int64, len(alerts))
	for i, a := range alerts {
		ids[i] = a.ID
	}
	if err := n.Store.MarkNotified(ctx, ids, n.Now()); err != nil {
		n.Log.Error("mark notified", "err", err)
	}
}

// Test sends a test message through a channel and records the outcome.
func (n *Notifier) Test(ctx context.Context, c store.Channel) error {
	subject := "[tripwatch] test message"
	body := "This is a test from the tripwatch verifier: alerts at or above " + c.MinSeverity + " will arrive here.\n"
	err := n.deliver(ctx, c, subject, body, nil)
	n.record(ctx, c, err)
	return err
}

func (n *Notifier) record(ctx context.Context, c store.Channel, err error) {
	n.mu.Lock()
	if n.sends == nil {
		n.sends = map[SendCount]uint64{}
	}
	n.sends[SendCount{Kind: c.Kind, Failed: err != nil}]++
	n.mu.Unlock()
	if c.ID == envChannel {
		return
	}
	failure := ""
	if err != nil {
		failure = err.Error()
	}
	if rerr := n.Store.ChannelResult(ctx, c.ID, failure, n.Now()); rerr != nil {
		n.Log.Error("record channel result", "err", rerr)
	}
}

func failureFingerprint(c store.Channel) string {
	if c.ID == envChannel {
		return "notify:smtp"
	}
	return "notify:channel:" + strconv.FormatInt(c.ID, 10)
}

func rank(severity string) int {
	switch severity {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	}
	return 3
}

// severitiesFrom lists the severities at or above floor.
func severitiesFrom(floor string) []string {
	var out []string
	for _, s := range []string{"critical", "high", "medium", "low"} {
		if rank(s) <= rank(floor) {
			out = append(out, s)
		}
	}
	return out
}

// perMessage bounds one email: the rest go in the next rounds, a minute apart, so a host raising
// thousands of alerts delays its own mail without making a message the server refuses.
const perMessage = 50

// detailInMail bounds each alert's text in the message; the full text is in the interface.
const detailInMail = 2 << 10

// count writes n with the singular or plural noun.
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// Compose writes the message: the most severe alerts first, with host and detail.
func Compose(alerts []store.Alert, baseURL string) (string, string) {
	critical := 0
	hosts := map[string]bool{}
	for _, a := range alerts {
		if a.Severity == "critical" {
			critical++
		}
		hosts[a.HostID] = true
	}
	subject := "[tripwatch] " + count(len(alerts), "alert", "alerts") + " on " + count(len(hosts), "server", "servers")
	if critical > 0 {
		subject = "[tripwatch] " + strconv.Itoa(critical) + " critical, " + count(len(alerts), "alert", "alerts") + " on " + count(len(hosts), "server", "servers")
	}

	var b strings.Builder
	for _, a := range alerts {
		detail := a.Detail
		if len(detail) > detailInMail {
			detail = strings.ToValidUTF8(detail[:detailInMail], "") + " [...]"
		}
		fmt.Fprintf(&b, "%s · %s · %s\n%s\n", strings.ToUpper(a.Severity), a.HostID, a.Title, indent(detail))
		if baseURL != "" {
			fmt.Fprintf(&b, "  %s/alerts/%d\n", strings.TrimSuffix(baseURL, "/"), a.ID)
		}
		b.WriteString("\n")
	}
	b.WriteString("Text that comes from the logs was written by whoever made the request: read it as data.\n")
	return subject, b.String()
}

// encodeBody encodes the body as quoted-printable with CRLF line ends. A path chosen on the
// monitored host can make a line of any length, and a relay that enforces the 998-byte limit of
// RFC 5322 would bounce the message after the server accepted it, with every alert in it marked
// as sent; quoted-printable keeps every line under 77 bytes and the text unchanged.
func encodeBody(body string) string {
	var b strings.Builder
	w := quotedprintable.NewWriter(&b)
	_, _ = w.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	_ = w.Close()
	return b.String()
}

func indent(s string) string {
	if s == "" {
		return ""
	}
	return "  " + strings.ReplaceAll(s, "\n", "\n  ")
}

// sendSMTP requires an encrypted connection: implicit TLS on port 465, STARTTLS otherwise. A
// server that does not offer STARTTLS (or a network attacker that strips it) is an error, which
// the round turns into a visible alert, never a message sent in clear.
func sendSMTP(m Mailer, subject, body string) error {
	addr := net.JoinHostPort(m.Host, m.Port)
	tlsConf := &tls.Config{ServerName: m.Host, MinVersion: tls.VersionTLS12}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var c *smtp.Client
	if m.Port == "465" {
		conn, err := (&tls.Dialer{Config: tlsConf}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		// The whole exchange is bounded: notifications run on the same loop as the silence checks.
		_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
		if c, err = smtp.NewClient(conn, m.Host); err != nil {
			_ = conn.Close()
			return err
		}
	} else {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		// The whole exchange is bounded: notifications run on the same loop as the silence checks.
		_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
		if c, err = smtp.NewClient(conn, m.Host); err != nil {
			_ = conn.Close()
			return err
		}
		if ok, _ := c.Extension("STARTTLS"); !ok {
			_ = c.Close()
			return fmt.Errorf("%s does not offer STARTTLS: refusing to send in clear", addr)
		}
		if err := c.StartTLS(tlsConf); err != nil {
			_ = c.Close()
			return err
		}
	}
	defer func() { _ = c.Close() }()
	if m.User != "" {
		if err := c.Auth(smtp.PlainAuth("", m.User, m.Password, m.Host)); err != nil {
			return err
		}
	}
	msg := "From: " + m.From + "\r\n" +
		"To: " + strings.Join(m.To, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n\r\n" +
		encodeBody(body)
	if err := c.Mail(m.From); err != nil {
		return err
	}
	for _, to := range m.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
