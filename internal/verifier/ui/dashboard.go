package ui

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// The overview's charts are computed here and drawn by the templates as plain SVG: no script,
// and every figure comes from the alerts and hosts the verifier holds.

// stackOrder is the order of severities in a stacked bar, from the base up: the most severe
// sits on the common baseline, where lengths compare best.
var stackOrder = []string{"critical", "high", "medium", "low"}

// kpi is one figure of the strip at the top of the overview.
type kpi struct {
	Key    string
	Label  string
	N      int
	Oldest time.Time
	// New is how many were raised in the last 24 hours.
	New int
	// Spark is the polyline of the last 7 days, one point a day, in a 70 by 20 box.
	Spark string
}

// segment is one severity's part of a bar, in the coordinates of its SVG.
type segment struct {
	Severity string
	X, Y     float64
	W, H     float64
	N        int
}

type columnBar struct {
	Label    string
	Title    string
	Segments []segment
}

// timeline is "alerts over time": a column per hour or per day, stacked by severity.
type timeline struct {
	Range   string
	Columns []columnBar
	Max     int
	Total   int
	Width   float64
	Height  float64
	// Ticks label a few columns under the chart.
	Ticks []string
}

// rankRow is one row of a ranking drawn as a horizontal bar, stacked by severity when it has
// more than one.
type rankRow struct {
	Label    string
	Sub      string
	Href     string
	N        int
	Severity string
	Segments []segment
}

type webAttacks struct {
	Sources []rankRow
	Targets []rankRow
	Total   int
}

const (
	timelineHeight = 140.0
	columnGap      = 0.18
)

// buildKPIs counts the open alerts of each severity, with their age, what arrived in the last
// day, and the shape of the last week.
func buildKPIs(tallies map[string]store.Tally, raised []store.Raised, silent *counter, now time.Time) []kpi {
	days := dayStarts(now, 7)
	perDay := map[string][]int{}
	newToday := map[string]int{}
	for _, r := range raised {
		key := r.Severity
		if r.Kind == "silence" {
			key = "silent"
		}
		if perDay[key] == nil {
			perDay[key] = make([]int, len(days))
		}
		if i := bucket(days, r.CreatedAt); i >= 0 {
			perDay[key][i]++
		}
		if now.Sub(r.CreatedAt) <= 24*time.Hour {
			newToday[key]++
		}
	}
	out := []kpi{}
	for _, k := range []struct{ key, label string }{{"critical", "Critical"}, {"high", "High"}, {"medium", "Medium"}, {"low", "Low"}} {
		t := tallies[k.key]
		out = append(out, kpi{Key: k.key, Label: k.label, N: t.N, Oldest: t.Oldest, New: newToday[k.key], Spark: spark(perDay[k.key])})
	}
	out = append(out, kpi{Key: "silent", Label: "Silent sensors", N: silent.N, Oldest: silent.Oldest, New: newToday["silent"], Spark: spark(perDay["silent"])})
	return out
}

// spark draws counts as a polyline in a 70 by 20 box; an empty series is a flat baseline.
func spark(counts []int) string {
	if len(counts) == 0 {
		counts = make([]int, 7)
	}
	top := slices.Max(counts)
	var b strings.Builder
	for i, n := range counts {
		x := 70 * float64(i) / float64(max(len(counts)-1, 1))
		y := 19.0
		if top > 0 {
			y = 19 - 17*float64(n)/float64(top)
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y)
	}
	return b.String()
}

// buildTimeline stacks the alerts raised per hour over the last day, or per day over the last
// week.
func buildTimeline(raised []store.Raised, rng string, now time.Time) timeline {
	var starts []time.Time
	var label func(time.Time) string
	if rng == "7d" {
		starts = dayStarts(now, 7)
		label = func(t time.Time) string { return t.Format("Mon 2") }
	} else {
		rng = "24h"
		end := now.In(time.Local).Truncate(time.Hour)
		for i := 23; i >= 0; i-- {
			starts = append(starts, end.Add(-time.Duration(i)*time.Hour))
		}
		label = func(t time.Time) string { return t.Format("15:04") }
	}
	counts := make([]map[string]int, len(starts))
	for i := range counts {
		counts[i] = map[string]int{}
	}
	t := timeline{Range: rng, Width: float64(len(starts)) * 10, Height: timelineHeight}
	for _, r := range raised {
		if i := bucket(starts, r.CreatedAt); i >= 0 {
			counts[i][r.Severity]++
			t.Total++
		}
	}
	for _, c := range counts {
		n := 0
		for _, v := range c {
			n += v
		}
		t.Max = max(t.Max, n)
	}
	scale := 0.0
	if t.Max > 0 {
		scale = (timelineHeight - 2) / float64(t.Max)
	}
	for i, start := range starts {
		col := columnBar{Label: label(start)}
		y := timelineHeight
		var parts []string
		for _, sev := range stackOrder {
			n := counts[i][sev]
			if n == 0 {
				continue
			}
			h := float64(n) * scale
			y -= h
			col.Segments = append(col.Segments, segment{Severity: sev, X: float64(i)*10 + columnGap*5, Y: y, W: 10 * (1 - columnGap), H: h, N: n})
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
		col.Title = col.Label + ": " + strings.Join(parts, ", ")
		if len(parts) == 0 {
			col.Title = col.Label + ": none"
		}
		t.Columns = append(t.Columns, col)
	}
	step := 6
	if rng == "7d" {
		step = 1
	}
	for i := range starts {
		if i%step == 0 {
			t.Ticks = append(t.Ticks, label(starts[i]))
		}
	}
	return t
}

// buildRules ranks the rules that raised most alerts in the period: a rule that suddenly raises
// many is often a legitimate activity to accept or a rule to tune.
func buildRules(raised []store.Raised, limit int) []rankRow {
	type agg struct {
		titles []store.Alert
		n      int
		worst  string
	}
	by := map[string]*agg{}
	var order []string
	for _, r := range raised {
		if r.Kind == "verifier" || r.Kind == "sensor-event" {
			continue
		}
		k := alertRule(r.Fingerprint)
		a := by[k]
		if a == nil {
			a = &agg{worst: r.Severity}
			by[k] = a
			order = append(order, k)
		}
		a.n++
		if len(a.titles) < 50 {
			a.titles = append(a.titles, store.Alert{Title: r.Title})
		}
		if severityRank(r.Severity) < severityRank(a.worst) {
			a.worst = r.Severity
		}
	}
	slices.SortStableFunc(order, func(x, y string) int { return by[y].n - by[x].n })
	if len(order) > limit {
		order = order[:limit]
	}
	var rows []rankRow
	for _, k := range order {
		a := by[k]
		rows = append(rows, rankRow{Label: commonLabel(a.titles), Sub: k, N: a.n, Severity: a.worst})
	}
	return scaleRows(rows, nil)
}

// buildHosts ranks the hosts by unresolved alerts, stacked by severity.
func buildHosts(open map[string]map[string]int, limit int) []rankRow {
	var rows []rankRow
	parts := map[string]map[string]int{}
	for host, bySev := range open {
		n := 0
		for _, v := range bySev {
			n += v
		}
		rows = append(rows, rankRow{Label: host, Href: "/hosts/" + host, N: n})
		parts[host] = bySev
	}
	slices.SortFunc(rows, func(a, b rankRow) int {
		if a.N != b.N {
			return b.N - a.N
		}
		return strings.Compare(a.Label, b.Label)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return scaleRows(rows, parts)
}

// firstAddress takes the first source address out of a web log alert's detail.
var firstAddress = regexp.MustCompile(`\(first ([0-9a-fA-F:.]+)\)`)

// buildWeb ranks the sources and the targeted scripts of the attacks seen in the web logs, by
// requests.
func buildWeb(raised []store.Raised, limit int) webAttacks {
	sources, targets := map[string]int{}, map[string]int{}
	var w webAttacks
	for _, r := range raised {
		if r.Kind != "weblog" {
			continue
		}
		n := max(r.Occurrences, 1)
		w.Total += n
		if m := firstAddress.FindStringSubmatch(r.Detail); m != nil {
			sources[m[1]] += n
		}
		fp, _, _ := strings.Cut(r.Fingerprint, "|")
		if parts := strings.SplitN(fp, ":", 3); len(parts) == 3 && parts[2] != "" {
			targets[parts[2]] += n
		}
	}
	w.Sources = scaleRows(topRows(sources, limit), nil)
	w.Targets = scaleRows(topRows(targets, limit), nil)
	return w
}

func topRows(counts map[string]int, limit int) []rankRow {
	var rows []rankRow
	for k, n := range counts {
		rows = append(rows, rankRow{Label: k, N: n})
	}
	slices.SortFunc(rows, func(a, b rankRow) int {
		if a.N != b.N {
			return b.N - a.N
		}
		return strings.Compare(a.Label, b.Label)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// scaleRows lays the rows' bars out in a 100 by 10 box, relative to the longest; with parts, a
// bar is split by severity in stack order.
func scaleRows(rows []rankRow, parts map[string]map[string]int) []rankRow {
	top := 0
	for _, r := range rows {
		top = max(top, r.N)
	}
	for i := range rows {
		r := &rows[i]
		if top == 0 {
			continue
		}
		if parts == nil {
			r.Segments = []segment{{Severity: r.Severity, W: 100 * float64(r.N) / float64(top), H: 10, N: r.N}}
			continue
		}
		x := 0.0
		for _, sev := range stackOrder {
			n := parts[r.Label][sev]
			if n == 0 {
				continue
			}
			w := 100 * float64(n) / float64(top)
			r.Segments = append(r.Segments, segment{Severity: sev, X: x, W: w, H: 10, N: n})
			x += w
		}
	}
	return rows
}

// dayStarts returns the starts of the last n local days, oldest first, today last.
func dayStarts(now time.Time, n int) []time.Time {
	l := now.In(time.Local)
	today := time.Date(l.Year(), l.Month(), l.Day(), 0, 0, 0, 0, time.Local)
	out := make([]time.Time, n)
	for i := range n {
		out[i] = today.AddDate(0, 0, i-n+1)
	}
	return out
}

// bucket finds the period a time falls in, given the periods' starts in order; the last runs
// to now. It is -1 before the first.
func bucket(starts []time.Time, t time.Time) int {
	for i := len(starts) - 1; i >= 0; i-- {
		if !t.Before(starts[i]) {
			return i
		}
	}
	return -1
}

func pct(f float64) string { return strconv.FormatFloat(f, 'f', 2, 64) }
