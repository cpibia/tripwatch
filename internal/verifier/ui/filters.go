package ui

import (
	"net/url"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// category is what an operator calls a family of alert kinds: the kind names the collector or
// rule behind an alert, which says little to someone sorting a hundred servers' alerts.
type category struct {
	Key, Label string
	kinds      []string
}

// categories lists every category in the order the filter offers them. A change of a collector's
// state has the kind of the collector with "-change" after it.
var categories = []category{
	{"web-request", "Web request", []string{"weblog"}},
	{"web-files", "Web files", []string{"web"}},
	{"realtime", "Real-time", []string{"realtime"}},
	{"access", "Access", []string{"accounts", "sudoers", "ssh"}},
	{"persistence", "Persistence", []string{"persistence", "scheduled", "services", "hooks"}},
	{"processes", "Processes", []string{"processes", "kernel"}},
	{"network", "Network", []string{"network", "sockets"}},
	{"privileges", "Privileges", []string{"privileged", "containers"}},
	{"packages", "Packages", []string{"packages"}},
	{"apps", "Applications", []string{"apps"}},
	{"sensor", "Sensor", []string{"sensor", "sensor-event", "chain", "verifier", "silence"}},
}

// categoryOf names the category of a kind; a kind no category lists is shown as it is.
func categoryOf(kind string) category {
	base := strings.TrimSuffix(kind, "-change")
	for _, c := range categories {
		if slices.Contains(c.kinds, base) {
			return c
		}
	}
	return category{Key: kind, Label: strings.ReplaceAll(base, "-", " ")}
}

// kindsOf lists the kinds of a category, with their changes, for the store's filter.
func kindsOf(key string) []string {
	for _, c := range categories {
		if c.Key == key {
			var kinds []string
			for _, k := range c.kinds {
				kinds = append(kinds, k, k+"-change")
			}
			return kinds
		}
	}
	return nil
}

// headline is an alert's title without the prefix that names its category, which the page
// shows as a tag: emails keep it, a list does not need it twice.
func headline(title string) string {
	for _, prefix := range []string{"Web request: ", "Log: "} {
		if rest, ok := strings.CutPrefix(title, prefix); ok && rest != "" {
			return strings.ToUpper(rest[:1]) + rest[1:]
		}
	}
	return title
}

// alertQuery is what the Alerts page shows, read from and written back to its address so a
// view can be kept and shared.
type alertQuery struct {
	View     string
	Text     string
	Severity []string
	Host     string
	Category string
	Sort     string
}

var allSeverities = []string{"critical", "high", "medium", "low"}

// defaultSeverities leaves the low alerts out: they are notes on a server's health and its
// sensor's life, kept and shown on its page, not alerts to handle.
var defaultSeverities = []string{"critical", "high", "medium"}

var alertSorts = []struct{ Key, Label string }{
	{"", "Most severe"}, {store.SortNewest, "Newest"}, {store.SortOldest, "Oldest"}, {store.SortOccurrences, "Most repeated"}, {store.SortHost, "Server"},
}

func readAlertQuery(v url.Values) alertQuery {
	q := alertQuery{View: v.Get("view"), Text: strings.TrimSpace(v.Get("q")), Host: v.Get("host"), Category: v.Get("cat"), Sort: v.Get("sort")}
	for _, s := range v["sev"] {
		if slices.Contains(allSeverities, s) && !slices.Contains(q.Severity, s) {
			q.Severity = append(q.Severity, s)
		}
	}
	if len(q.Severity) == 0 {
		q.Severity = defaultSeverities
	}
	if !slices.ContainsFunc(alertSorts, func(s struct{ Key, Label string }) bool { return s.Key == q.Sort }) {
		q.Sort = ""
	}
	if kindsOf(q.Category) == nil {
		q.Category = ""
	}
	return q
}

// values writes the query back, leaving out what is the default.
func (q alertQuery) values() url.Values {
	v := url.Values{}
	if q.View != "" && q.View != "open" {
		v.Set("view", q.View)
	}
	if q.Text != "" {
		v.Set("q", q.Text)
	}
	if !slices.Equal(q.Severity, defaultSeverities) {
		v["sev"] = q.Severity
	}
	if q.Host != "" {
		v.Set("host", q.Host)
	}
	if q.Category != "" {
		v.Set("cat", q.Category)
	}
	if q.Sort != "" {
		v.Set("sort", q.Sort)
	}
	return v
}

// With returns the address of the same query in another status view.
func (q alertQuery) With(view string) string {
	q.View = view
	return link(q)
}

// Without returns the address of the query with one of its filters cleared.
func (q alertQuery) Without(filter string) string {
	switch filter {
	case "q":
		q.Text = ""
	case "sev":
		q.Severity = defaultSeverities
	case "host":
		q.Host = ""
	case "cat":
		q.Category = ""
	case "all":
		q = alertQuery{View: q.View, Severity: defaultSeverities}
	}
	return link(q)
}

// Shows reports whether a severity is in the query.
func (q alertQuery) Shows(sev string) bool { return slices.Contains(q.Severity, sev) }

// Filtered reports whether anything narrows the list beyond the defaults.
func (q alertQuery) Filtered() bool {
	return q.Text != "" || q.Host != "" || q.Category != "" || !slices.Equal(q.Severity, defaultSeverities)
}

// LowHidden reports whether the low alerts are left out.
func (q alertQuery) LowHidden() bool { return !q.Shows("low") }

func link(q alertQuery) string {
	if v := q.values().Encode(); v != "" {
		return "/alerts?" + v
	}
	return "/alerts"
}

// serverQuery is what the Servers page shows.
type serverQuery struct {
	Text  string
	State string
	Sort  string
}

var serverStates = []struct{ Key, Label string }{
	{"", "every server"}, {"alerts", "with alerts"}, {"silent", "silent"}, {"outdated", "sensor to update"},
}

var serverSorts = []struct{ Key, Label string }{
	{"", "Name"}, {"severity", "Most severe"}, {"alerts", "Most alerts"}, {"heartbeat", "Quietest"},
}

func readServerQuery(v url.Values) serverQuery {
	q := serverQuery{Text: strings.TrimSpace(v.Get("q")), State: v.Get("state"), Sort: v.Get("sort")}
	if len(q.Text) > maxServerQuery {
		q.Text = strings.ToValidUTF8(q.Text[:maxServerQuery], "")
	}
	if !slices.ContainsFunc(serverStates, func(s struct{ Key, Label string }) bool { return s.Key == q.State }) {
		q.State = ""
	}
	if !slices.ContainsFunc(serverSorts, func(s struct{ Key, Label string }) bool { return s.Key == q.Sort }) {
		q.Sort = ""
	}
	return q
}

// maxServerQuery bounds the text searched among servers.
const maxServerQuery = 200

// Filtered reports whether anything narrows the list.
func (q serverQuery) Filtered() bool { return q.Text != "" || q.State != "" }

// matches reports whether a server answers the query: its name, system, addresses, sensor
// version, the technologies it runs and the domains it serves are searched.
func (q serverQuery) matches(r hostRow) bool {
	switch q.State {
	case "alerts":
		if r.Open == 0 {
			return false
		}
	case "silent":
		if r.State != "silent" {
			return false
		}
	case "outdated":
		if !r.Outdated {
			return false
		}
	}
	if q.Text == "" {
		return true
	}
	text := strings.ToLower(q.Text)
	f := r.Facts
	fields := []string{r.ID, r.Name, r.Note, r.PeerAddr, f.Hostname, f.OS, f.Kernel, f.Arch, f.Environment, f.SensorVersion, f.PackageManager}
	fields = append(fields, r.Labels...)
	fields = append(fields, f.Addresses...)
	fields = append(fields, f.ContainerRuntimes...)
	for _, a := range f.Apps {
		fields = append(fields, a.Framework, a.Framework+" "+a.Version, a.Path)
		fields = append(fields, a.Sites...)
	}
	return slices.ContainsFunc(fields, func(s string) bool { return strings.Contains(strings.ToLower(s), text) })
}

// order sorts servers as the query asks; equal ones stay by name.
func (q serverQuery) order(rows []hostRow) {
	worst := func(r hostRow) int {
		if r.State == "silent" {
			return -1
		}
		if r.Worst == nil {
			return 4
		}
		return severityRank(r.Worst.Severity)
	}
	slices.SortStableFunc(rows, func(a, b hostRow) int {
		switch q.Sort {
		case "severity":
			if c := worst(a) - worst(b); c != 0 {
				return c
			}
		case "alerts":
			if c := b.Open - a.Open; c != 0 {
				return c
			}
		case "heartbeat":
			if c := a.LastHeartbeat.Compare(b.LastHeartbeat); c != 0 {
				return c
			}
		}
		return strings.Compare(a.ID, b.ID)
	})
}
