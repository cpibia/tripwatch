// Package notify sends new alerts by email.
package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// Severities sent by email; lower ones are visible in the interface only.
var Severities = []string{"critical", "high"}

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

// Notifier sends the alerts not yet notified, grouped in one message per round.
type Notifier struct {
	Store  *store.Store
	Mailer Mailer
	Now    func() time.Time
	Log    *slog.Logger
	send   func(m Mailer, subject, body string) error
}

func (n *Notifier) Round(ctx context.Context) {
	if !n.Mailer.Enabled() {
		return
	}
	alerts, err := n.Store.Unnotified(ctx, Severities)
	if err != nil || len(alerts) == 0 {
		if err != nil {
			n.Log.Error("load alerts to notify", "err", err)
		}
		return
	}
	send := n.send
	if send == nil {
		send = sendSMTP
	}
	subject, body := Compose(alerts, n.Mailer.BaseURL)
	if err := send(n.Mailer, subject, body); err != nil {
		n.Log.Error("send notification", "err", err)
		// Shown in the interface: notifications failing silently would leave alerts unseen.
		if _, rerr := n.Store.Raise(ctx, store.Alert{HostID: "verifier", Fingerprint: "notify:smtp", Severity: "medium", Kind: "verifier",
			Title: "Le email di notifica non partono", Detail: err.Error()}, n.Now()); rerr != nil {
			n.Log.Error("raise notification alert", "err", rerr)
		}
		return
	}
	if err := n.Store.ResolveGone(ctx, "verifier", "verifier", nil, n.Now()); err != nil {
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
	subject := fmt.Sprintf("[tripwatch] %d allarmi su %d server", len(alerts), len(hosts))
	if critical > 0 {
		subject = fmt.Sprintf("[tripwatch] %d critici, %d allarmi su %d server", critical, len(alerts), len(hosts))
	}

	var b strings.Builder
	for _, a := range alerts {
		fmt.Fprintf(&b, "%s · %s · %s\n%s\n", strings.ToUpper(a.Severity), a.HostID, a.Title, indent(a.Detail))
		if baseURL != "" {
			fmt.Fprintf(&b, "  %s/alerts/%d\n", strings.TrimSuffix(baseURL, "/"), a.ID)
		}
		b.WriteString("\n")
	}
	b.WriteString("I testi che arrivano dai log sono scritti da chi ha fatto la richiesta: vanno letti come dati.\n")
	return subject, b.String()
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
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n\r\n" +
		strings.ReplaceAll(body, "\n", "\r\n")
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
