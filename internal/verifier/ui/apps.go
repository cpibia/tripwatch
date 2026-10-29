package ui

import (
	"path"
	"slices"
	"strings"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// hostApp is a web application of a server as its page lists it: the site first, since that is
// what an operator recognises, then what runs it and where it lives, and the alerts still open
// on its files.
type hostApp struct {
	store.AppFact
	// Site is the first site it serves; Others the number of the rest.
	Site   string
	Others int
	// Dir and Base split the path, so the part that tells applications apart stands out.
	Dir, Base string
	// Open counts the unresolved alerts about its files, Worst is the most severe of them.
	Open  int
	Worst string
}

// hostApps lists a server's applications, those with open alerts first, then those a site
// serves. An alert belongs to the application whose directory holds the path it names: the
// deepest one, when applications are nested.
func hostApps(f store.HostFacts, alerts []store.Alert) []hostApp {
	out := make([]hostApp, 0, len(f.Apps))
	for _, a := range f.Apps {
		app := hostApp{AppFact: a, Dir: strings.TrimSuffix(path.Dir(a.Path), "/") + "/", Base: path.Base(a.Path)}
		for _, s := range a.Sites {
			if s == "" || s == "_" {
				continue
			}
			if app.Site == "" {
				app.Site = s
			} else {
				app.Others++
			}
		}
		out = append(out, app)
	}
	for _, al := range alerts {
		if al.Status == store.StatusResolved {
			continue
		}
		best := -1
		for i, app := range out {
			if (strings.Contains(al.Detail, app.Path+"/") || strings.Contains(al.Fingerprint, app.Path+"/")) &&
				(best < 0 || len(app.Path) > len(out[best].Path)) {
				best = i
			}
		}
		if best >= 0 {
			out[best].Open++
			if out[best].Worst == "" || severityRank(al.Severity) < severityRank(out[best].Worst) {
				out[best].Worst = al.Severity
			}
		}
	}
	slices.SortStableFunc(out, func(a, b hostApp) int {
		switch {
		case (a.Open > 0) != (b.Open > 0):
			return before(a.Open > 0)
		case a.Open > 0 && a.Worst != b.Worst:
			return severityRank(a.Worst) - severityRank(b.Worst)
		case (a.Site != "") != (b.Site != ""):
			return before(a.Site != "")
		}
		return strings.Compare(a.Path, b.Path)
	})
	return out
}

// before orders first what has a property the other lacks.
func before(has bool) int {
	if has {
		return -1
	}
	return 1
}
