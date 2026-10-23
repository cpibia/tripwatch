package ui

import (
	"fmt"
	"html/template"
	"strings"
	"time"
)

var months = [...]string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

var severityLabels = map[string]string{"critical": "critical", "high": "high", "medium": "medium", "low": "low"}

var statusLabels = map[string]string{"open": "open", "acknowledged": "acknowledged", "resolved": "resolved"}

func funcs(now func() time.Time) template.FuncMap {
	return template.FuncMap{
		"clock":   func(t time.Time) string { return clock(t, now()) },
		"updated": func() string { return now().In(time.Local).Format("15:04") },
		"stamp": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			return t.In(time.Local).Format("2006-01-02 15:04:05 MST")
		},
		"iso": func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
		"ago": func(t time.Time) string { return ago(t, now()) },
		"since": func(t time.Time) string {
			if s := ago(t, now()); s != "just now" {
				return strings.TrimSuffix(s, " ago")
			}
			return "under a minute"
		},
		"sev": func(s string) string {
			if l, ok := severityLabels[s]; ok {
				return l
			}
			return s
		},
		"status": func(s string) string {
			if l, ok := statusLabels[s]; ok {
				return l
			}
			return s
		},
		"size": size,
		"plural": func(n int, one, many string) string {
			if n == 1 {
				return one
			}
			return many
		},
		"dur":   duration,
		"shape": shape,
	}
}

// clock writes a time briefly: the hour alone today, the day and hour otherwise.
func clock(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	l, n := t.In(time.Local), now.In(time.Local)
	if l.Year() == n.Year() && l.YearDay() == n.YearDay() {
		return l.Format("15:04")
	}
	if l.Year() == n.Year() {
		return fmt.Sprintf("%d %s %s", l.Day(), months[l.Month()-1], l.Format("15:04"))
	}
	return fmt.Sprintf("%d %s %d", l.Day(), months[l.Month()-1], l.Year())
}

// ago writes the time elapsed since t in the largest unit that fits.
func ago(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d/time.Hour))
	}
	return fmt.Sprintf("%d d ago", int(d/(24*time.Hour)))
}

func size(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}

// duration writes a span in minutes, hours and days, at most two units.
func duration(d time.Duration) string {
	m := int(d / time.Minute)
	switch {
	case m < 60:
		return fmt.Sprintf("%d min", max(m, 1))
	case m < 24*60:
		if m%60 == 0 {
			return fmt.Sprintf("%d h", m/60)
		}
		return fmt.Sprintf("%d h %d min", m/60, m%60)
	}
	return fmt.Sprintf("%d d %d h", m/(24*60), m%(24*60)/60)
}

// shapes gives every state its own form, so that severity never rests on colour alone.
var shapes = map[string]string{
	"silent":   `<path d="M6 0.8L11.2 6L6 11.2L0.8 6Z"/>`,
	"critical": `<path d="M6 0.8L11.4 10.8H0.6Z"/>`,
	"high":     `<path d="M1.5 1.5H10.5V10.5H1.5Z"/>`,
	"medium":   `<circle cx="6" cy="6" r="4.6"/>`,
	"low":      `<circle cx="6" cy="6" r="4.2"/>`,
}

// shape returns the mark of a state; acknowledged marks are drawn desaturated.
func shape(kind, status string) template.HTML {
	body, ok := shapes[kind]
	if !ok {
		return ""
	}
	class := "mark mark-" + kind
	if status == "acknowledged" {
		class += " acked"
	}
	if status == "resolved" {
		class += " done"
	}
	return template.HTML(`<svg class="` + class + `" viewBox="0 0 12 12" aria-hidden="true">` + body + `</svg>`) //nolint:gosec // constant markup chosen from a fixed table
}
