package store

import (
	"cmp"
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"time"
)

// HostFacts is what the fleet page shows of a host: its system as the sensor read it, and what
// the latest snapshot found on it. All of it comes from the host, so it is data, never markup.
type HostFacts struct {
	OS                string        `json:"os,omitempty"`
	OSID              string        `json:"os_id,omitempty"`
	OSVersion         string        `json:"os_version,omitempty"`
	Kernel            string        `json:"kernel,omitempty"`
	Arch              string        `json:"arch,omitempty"`
	Hostname          string        `json:"hostname,omitempty"`
	BootedAt          time.Time     `json:"booted_at,omitzero"`
	CPUs              int           `json:"cpus,omitempty"`
	MemoryBytes       uint64        `json:"memory_bytes,omitempty"`
	Addresses         []string      `json:"addresses,omitempty"`
	SensorVersion     string        `json:"sensor_version,omitempty"`
	Environment       string        `json:"environment,omitempty"`
	ContainerRuntimes []string      `json:"container_runtimes,omitempty"`
	PackageManager    string        `json:"package_manager,omitempty"`
	Packages          int           `json:"packages,omitempty"`
	Apps              []AppFact     `json:"apps,omitempty"`
	Listening         int           `json:"listening,omitempty"`
	Realtime          *RealtimeFact `json:"realtime,omitempty"`
	SeenAt            time.Time     `json:"seen_at"`
}

// RealtimeFact says whether the sensor's real-time watchers run, and why not when they do not.
type RealtimeFact struct {
	Files     bool     `json:"files"`
	Processes bool     `json:"processes"`
	Watches   int      `json:"watches,omitempty"`
	Issues    []string `json:"issues,omitempty"`
}

// AppFact is one web application found on a host, with the names of the sites that serve it:
// none for one only found on disk (an old release, a project in a home directory).
type AppFact struct {
	Path      string   `json:"path"`
	Framework string   `json:"framework"`
	Version   string   `json:"version,omitempty"`
	Sites     []string `json:"sites,omitempty"`
}

// AppGroup is the applications of one framework and version on a host.
type AppGroup struct {
	Framework string
	Version   string
	Count     int
}

// genericFrameworks name directories recognised by a file any project has (index.html,
// package.json), not by a stack.
var genericFrameworks = []string{"static", "php", "node", "python", "go", "rust", "java", "unknown"}

// AppGroups are the host's applications grouped by framework and version, stacks first, then
// the most numerous: what runs on a host in one line, however many releases or copies it keeps.
func (f HostFacts) AppGroups() []AppGroup {
	var out []AppGroup
	for _, a := range f.Apps {
		i := slices.IndexFunc(out, func(g AppGroup) bool { return g.Framework == a.Framework && g.Version == a.Version })
		if i < 0 {
			out = append(out, AppGroup{Framework: a.Framework, Version: a.Version})
			i = len(out) - 1
		}
		out[i].Count++
	}
	generic := func(g AppGroup) int {
		if slices.Contains(genericFrameworks, g.Framework) {
			return 1
		}
		return 0
	}
	slices.SortStableFunc(out, func(a, b AppGroup) int { return cmp.Or(generic(a)-generic(b), b.Count-a.Count) })
	return out
}

// SortedApps are the host's applications, those a site serves first.
func (f HostFacts) SortedApps() []AppFact {
	out := slices.Clone(f.Apps)
	slices.SortStableFunc(out, func(a, b AppFact) int { return min(len(b.Sites), 1) - min(len(a.Sites), 1) })
	return out
}

// SetFacts keeps the facts of a host's latest analysed snapshot.
func (s *Store) SetFacts(ctx context.Context, host string, f HostFacts) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO host_facts (host_id, facts, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (host_id) DO UPDATE SET facts = excluded.facts, updated_at = excluded.updated_at`, host, string(b), f.SeenAt.Unix())
	return err
}

// startedVersion reads the version out of a "Sensor started" alert; those raised before the
// interface was in English say "versione".
var startedVersion = regexp.MustCompile(`\(versione? ([0-9A-Za-z.+~-]+),`)

// Facts returns the facts of every host. A host whose sensor predates the system block still
// gets its version, from the signed event of its latest start.
func (s *Store) Facts(ctx context.Context) (map[string]HostFacts, error) {
	out := map[string]HostFacts{}
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, facts FROM host_facts`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var host, raw string
		if err := rows.Scan(&host, &raw); err != nil {
			_ = rows.Close()
			return nil, err
		}
		var f HostFacts
		if json.Unmarshal([]byte(raw), &f) == nil {
			out[host] = f
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	events, err := s.db.QueryContext(ctx, `SELECT host_id, detail FROM alerts WHERE kind = 'sensor-event' AND fingerprint LIKE 'sensor:started:%' ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = events.Close() }()
	started := map[string]string{}
	for events.Next() {
		var host, detail string
		if err := events.Scan(&host, &detail); err != nil {
			return nil, err
		}
		if m := startedVersion.FindStringSubmatch(detail); m != nil {
			started[host] = m[1]
		}
	}
	for host, v := range started {
		f := out[host]
		if f.SensorVersion == "" {
			f.SensorVersion = v
			out[host] = f
		}
	}
	return out, events.Err()
}
