package ui

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxExportAlerts bounds an export: past it, narrower filters are the way to the rest, and the
// file says so in its last row.
const maxExportAlerts = 10_000

// exportAlerts writes the alerts a list query selects, every page of it, as CSV or JSON, in the
// list's order. It reads what the user may see, as the list does, and is recorded in the audit
// log: a copy of the alerts leaves the console.
func (s *server) exportAlerts(w http.ResponseWriter, r *http.Request, se session) {
	q := readAlertQuery(r.URL.Query())
	format := r.URL.Query().Get("format")
	if format != "csv" && format != "json" {
		s.fail(w, r, http.StatusBadRequest, "Unknown format", "Alerts are exported as csv or json.")
		return
	}
	f := q.filter()
	f.Limit = maxExportAlerts + 1
	list, err := s.Store.Alerts(r.Context(), f)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	cut := len(list) > maxExportAlerts
	list = list[:min(len(list), maxExportAlerts)]
	s.audit(r, se, "alerts exported", "", strconv.Itoa(len(list))+" alerts as "+format+", "+orDash(q.values().Encode()))

	name := "tripwatch-alerts-" + s.Now().UTC().Format("20060102-150405") + "." + format
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	if format == "json" {
		out := make([]apiAlert, 0, len(list))
		for _, a := range list {
			out = append(out, toAPIAlert(a))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"alerts": out, "truncated": cut})
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	c := csv.NewWriter(w)
	_ = c.Write([]string{"id", "host", "severity", "status", "kind", "title", "detail", "created_at", "updated_at", "occurrences"})
	for _, a := range list {
		_ = c.Write([]string{strconv.FormatInt(a.ID, 10), cell(a.HostID), a.Severity, a.Status, cell(a.Kind), cell(a.Title), cell(a.Detail),
			a.CreatedAt.UTC().Format(time.RFC3339), a.UpdatedAt.UTC().Format(time.RFC3339), strconv.Itoa(a.Occurrences)})
	}
	if cut {
		_ = c.Write([]string{"", "", "", "", "", "Only the first " + strconv.Itoa(maxExportAlerts) + " alerts: narrow the filters for the rest."})
	}
	c.Flush()
}

// cell keeps a spreadsheet from reading text as a formula. Titles and details carry what the
// monitored host wrote, file names among it, and a cell starting with =, +, - or @ (or a tab or
// carriage return before one) is run by the spreadsheet that opens the file.
func cell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
