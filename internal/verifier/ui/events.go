package ui

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
	"github.com/cpibia/tripwatch/internal/watch"
)

// maxEventRows bounds the events shown on a host's page.
const maxEventRows = 100

// eventRow is one real-time event as the host page lists it. Every field but the labels comes
// from the host.
type eventRow struct {
	At             time.Time
	Class          string
	What           string
	Subject        string
	Detail         string
	PackageManager bool
}

var classLabels = map[string]string{
	watch.ClassAccounts: "Accounts", watch.ClassSSH: "SSH", watch.ClassPrivilege: "Privilege", watch.ClassSchedule: "Schedule",
	watch.ClassService: "Service", watch.ClassHook: "Start-up", watch.ClassUpload: "Upload", watch.ClassExec: "Process",
}

var opLabels = map[string]string{
	watch.OpCreate: "created", watch.OpWrite: "written", watch.OpDelete: "removed", watch.OpAttrib: "attributes changed",
	watch.ReasonWebShell: "started by the web server's user", watch.ReasonDeleted: "runs from a deleted file",
	watch.ReasonUnusualPath: "started from an unusual place", watch.ReasonPrivilege: "became root",
}

func eventRows(events []store.Event) []eventRow {
	out := make([]eventRow, 0, len(events))
	for _, e := range events {
		var ev watch.Event
		_ = json.Unmarshal(e.Data, &ev)
		row := eventRow{At: e.At, Class: label(classLabels, e.Class), What: label(opLabels, e.Op), Subject: e.Path, PackageManager: e.PackageManager}
		var parts []string
		if e.Class == watch.ClassExec {
			row.What = label(opLabels, ev.Reason)
			if ev.Cmdline != "" {
				parts = append(parts, ev.Cmdline)
			}
			if ev.Parent != "" {
				parts = append(parts, "parent "+ev.Parent)
			}
			if ev.User != nil {
				parts = append(parts, "uid "+strconv.Itoa(*ev.User))
			}
		} else {
			if ev.Dir {
				parts = append(parts, "directory")
			}
			if ev.SHA256 != "" {
				parts = append(parts, fmt.Sprintf("%s, SHA-256 %.12s", size(int(ev.Size)), ev.SHA256))
			}
			if ev.UID != nil {
				parts = append(parts, "uid "+strconv.FormatUint(uint64(*ev.UID), 10))
			}
			if ev.Mode != "" {
				parts = append(parts, ev.Mode)
			}
		}
		row.Detail = strings.Join(parts, " · ")
		out = append(out, row)
	}
	return out
}

func label(labels map[string]string, key string) string {
	if l, ok := labels[key]; ok {
		return l
	}
	return key
}
