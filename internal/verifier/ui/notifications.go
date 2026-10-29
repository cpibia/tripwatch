package ui

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// channelSeverities are the floors a channel can be set to, most selective first.
var channelSeverities = []string{"critical", "high", "medium"}

// Shapes accepted for a channel's settings: they reach SMTP commands and request addresses.
var (
	smtpHostPattern = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
	portPattern     = regexp.MustCompile(`^[0-9]{1,5}$`)
	botTokenPattern = regexp.MustCompile(`^[0-9]{1,20}:[A-Za-z0-9_-]{20,100}$`)
	chatIDPattern   = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$`)
)

type notificationsData struct {
	Channels   []store.Channel
	Env        bool
	Severities []string
	Error      string
	// Form keeps what was typed when the channel was refused, secrets excepted.
	Form   url.Values
	Tested string
}

// minsev is what the severity choice of an add form needs: the floors, and the one selected,
// kept from a refused form of the same kind, critical and high otherwise.
type minsev struct {
	Severities []string
	Selected   string
}

func minsevx(d notificationsData, kind string) minsev {
	m := minsev{Severities: d.Severities, Selected: "high"}
	if d.Form.Get("kind") == kind && slices.Contains(d.Severities, d.Form.Get("min")) {
		m.Selected = d.Form.Get("min")
	}
	return m
}

// anyChannel reports whether a notification channel is enabled.
func (s *server) anyChannel(ctx context.Context) bool {
	channels, err := s.Store.Channels(ctx)
	if err != nil {
		return false
	}
	for _, c := range channels {
		if c.Enabled && !c.Unreadable {
			return true
		}
	}
	return false
}

func (s *server) notifications(w http.ResponseWriter, r *http.Request, se session) {
	s.renderNotifications(w, r, se, http.StatusOK, notificationsData{Tested: r.URL.Query().Get("tested")})
}

func (s *server) renderNotifications(w http.ResponseWriter, r *http.Request, se session, status int, d notificationsData) {
	channels, err := s.Store.Channels(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	d.Channels, d.Env, d.Severities = channels, s.Notify, channelSeverities
	s.render(w, r, status, "notifications", page{Title: "Notifications", Nav: "notifications", User: se.Email, CSRF: se.csrf(), Data: d})
}

// addChannel records a channel from its form. Settings are checked for their shape here; whether
// they work is what the test button shows.
func (s *server) addChannel(w http.ResponseWriter, r *http.Request, se session) {
	c, problem := channelFromForm(r)
	if problem != "" {
		form := url.Values{}
		for k, v := range r.PostForm {
			if k != "password" && k != "bot_token" && k != "secret" && k != "csrf" {
				form[k] = v
			}
		}
		s.renderNotifications(w, r, se, http.StatusBadRequest, notificationsData{Error: problem, Form: form})
		return
	}
	if _, err := s.Store.AddChannel(r.Context(), c, s.Now()); err != nil {
		if errors.Is(err, store.ErrTooManyChannels) {
			s.renderNotifications(w, r, se, http.StatusBadRequest, notificationsData{Error: "There are already as many channels as the verifier keeps: remove one first."})
			return
		}
		s.internal(w, r, err)
		return
	}
	s.Log.Info("notification channel added", "kind", c.Kind, "name", c.Name, "by", se.Email)
	s.audit(r, se, "channel added", c.Name, c.Kind+", "+c.MinSeverity+" and above")
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

// channelFromForm reads a channel from its form; the second value, when not empty, says to the
// operator what to fix.
func channelFromForm(r *http.Request) (store.Channel, string) {
	field := func(name string) string { return strings.TrimSpace(r.PostFormValue(name)) }
	c := store.Channel{Kind: field("kind"), Name: field("name"), MinSeverity: field("min")}
	if c.Name == "" || len(c.Name) > 80 {
		return c, "Give the channel a name of up to 80 characters."
	}
	if !slices.Contains(channelSeverities, c.MinSeverity) {
		return c, "Choose which alerts the channel receives."
	}
	switch c.Kind {
	case store.ChannelEmail:
		c.Settings = store.ChannelSettings{SMTPHost: field("smtp_host"), SMTPPort: field("smtp_port"), SMTPUser: field("smtp_user"), Password: r.PostFormValue("password"), From: field("from")}
		if c.Settings.SMTPPort == "" {
			c.Settings.SMTPPort = "587"
		}
		if !smtpHostPattern.MatchString(c.Settings.SMTPHost) || !portPattern.MatchString(c.Settings.SMTPPort) {
			return c, "The SMTP server needs a host name and a port number."
		}
		if _, err := mail.ParseAddress(c.Settings.From); err != nil || strings.ContainsAny(c.Settings.From, "\r\n") {
			return c, "The sender is not a valid email address."
		}
		for _, to := range strings.FieldsFunc(field("to"), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
			if _, err := mail.ParseAddress(to); err != nil || strings.ContainsAny(to, "\r\n") {
				return c, "A recipient is not a valid email address: " + to
			}
			c.Settings.To = append(c.Settings.To, to)
		}
		if len(c.Settings.To) == 0 || len(c.Settings.To) > 20 {
			return c, "Give between 1 and 20 recipients."
		}
	case store.ChannelTelegram:
		c.Settings = store.ChannelSettings{BotToken: strings.TrimSpace(r.PostFormValue("bot_token")), ChatID: field("chat_id")}
		if !botTokenPattern.MatchString(c.Settings.BotToken) {
			return c, "The bot token has the form 123456789:ABC..., as BotFather gives it."
		}
		if !chatIDPattern.MatchString(c.Settings.ChatID) {
			return c, "The chat is a number (a group's starts with -) or a @channel name."
		}
	case store.ChannelWebhook:
		c.Settings = store.ChannelSettings{URL: field("url"), Secret: r.PostFormValue("secret")}
		u, err := url.Parse(c.Settings.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(c.Settings.URL) > 2048 {
			return c, "The webhook address must be an https:// address."
		}
		if len(c.Settings.Secret) < 16 {
			return c, "The secret signs each payload: give at least 16 characters."
		}
	default:
		return c, "Unknown kind of channel."
	}
	return c, ""
}

// channelAction tests, enables, disables or removes a channel.
func (s *server) channelAction(w http.ResponseWriter, r *http.Request, se session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "Unknown channel", "No notification channel has this number.")
		return
	}
	ctx := r.Context()
	c, err := s.Store.Channel(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, http.StatusNotFound, "Unknown channel", "No notification channel has this number.")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	back := "/notifications"
	switch r.PathValue("action") {
	case "test":
		if s.TestChannel == nil {
			s.fail(w, r, http.StatusConflict, "Test unavailable", "This verifier cannot send test messages.")
			return
		}
		result := "ok"
		if c.Unreadable {
			result = "failed"
		} else if err := s.TestChannel(ctx, c); err != nil {
			result = "failed"
		}
		back += "?tested=" + result
	case "enable", "disable":
		err = s.Store.SetChannelEnabled(ctx, id, r.PathValue("action") == "enable")
	case "delete":
		err = s.Store.DeleteChannel(ctx, id)
	default:
		s.fail(w, r, http.StatusNotFound, "Unknown action", "This action does not exist.")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.Log.Info("notification channel "+r.PathValue("action"), "channel", c.Name, "by", se.Email)
	s.audit(r, se, "channel "+r.PathValue("action"), c.Name, "")
	http.Redirect(w, r, back, http.StatusSeeOther)
}
