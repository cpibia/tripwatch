// Package system collects the operating system state attackers change to keep access:
// accounts, SSH, sudo, scheduled jobs, services, startup hooks and privileged files.
package system

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

// Password states. The hash itself is never collected.
const (
	PasswordSet     = "set"
	PasswordLocked  = "locked"
	PasswordEmpty   = "empty"
	PasswordUnknown = "unknown"
)

type Account struct {
	Name     string `json:"name"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	Home     string `json:"home"`
	Shell    string `json:"shell"`
	Password string `json:"password"`
}

type Group struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members,omitempty"`
	// From etc/gshadow, which newgrp and sg read instead of etc/group: its own member list,
	// the group's administrators and the state of the group password (never its hash).
	ShadowMembers []string `json:"shadow_members,omitempty"`
	Admins        []string `json:"admins,omitempty"`
	Password      string   `json:"password,omitempty"`
}

type AccountsResult struct {
	Accounts []Account        `json:"accounts"`
	Groups   []Group          `json:"groups"`
	Files    []collector.File `json:"files"`
	Issues   collector.Issues `json:"issues,omitempty"`
}

// Accounts collects users and groups from the local databases.
type Accounts struct{}

func (Accounts) Name() string { return "accounts" }

func (Accounts) Collect(_ context.Context, src collector.Source) (any, error) {
	var res AccountsResult

	accounts, err := readAccounts(src, &res.Issues)
	if err != nil {
		return nil, err
	}
	res.Accounts = accounts

	groups, err := collector.ReadLines(src.FS, "etc/group")
	res.Issues.Add(err)
	for _, line := range groups {
		fields := strings.Split(line, ":")
		if len(fields) < 4 || strings.HasPrefix(line, "#") {
			continue
		}
		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			res.Issues = append(res.Issues, fmt.Sprintf("etc/group: malformed entry for %q", fields[0]))
			continue
		}
		g := Group{Name: fields[0], GID: gid}
		if fields[3] != "" {
			g.Members = strings.Split(fields[3], ",")
		}
		res.Groups = append(res.Groups, g)
	}
	gshadow, err := collector.ReadLines(src.FS, "etc/gshadow")
	if err == nil {
		byName := map[string]int{}
		for i, g := range res.Groups {
			byName[g.Name] = i
		}
		states := shadowStates(gshadow)
		for _, line := range gshadow {
			fields := strings.Split(line, ":")
			i, ok := byName[fields[0]]
			if len(fields) < 4 || !ok {
				continue
			}
			res.Groups[i].Password = states[fields[0]]
			if fields[2] != "" {
				res.Groups[i].Admins = strings.Split(fields[2], ",")
			}
			if fields[3] != "" {
				res.Groups[i].ShadowMembers = strings.Split(fields[3], ",")
			}
		}
	}

	for _, name := range []string{"etc/passwd", "etc/shadow", "etc/group", "etc/gshadow"} {
		res.Files = appendDescribed(res.Files, &res.Issues, src, name)
	}
	return res, nil
}

// readAccounts parses etc/passwd, with the password state taken from etc/shadow.
func readAccounts(src collector.Source, issues *collector.Issues) ([]Account, error) {
	passwd, err := collector.ReadLines(src.FS, "etc/passwd")
	if err != nil {
		return nil, err
	}
	shadow, err := collector.ReadLines(src.FS, "etc/shadow")
	issues.Add(err)
	passwords := shadowStates(shadow)

	var accounts []Account
	for _, line := range passwd {
		fields := strings.Split(line, ":")
		if len(fields) < 7 || strings.HasPrefix(line, "#") {
			continue
		}
		uid, uidErr := strconv.Atoi(fields[2])
		gid, gidErr := strconv.Atoi(fields[3])
		if uidErr != nil || gidErr != nil {
			*issues = append(*issues, fmt.Sprintf("etc/passwd: malformed entry for %q", fields[0]))
			continue
		}
		state, ok := passwords[fields[0]]
		if !ok {
			state = PasswordUnknown
		}
		accounts = append(accounts, Account{
			Name: fields[0], UID: uid, GID: gid, Home: fields[5], Shell: fields[6], Password: state,
		})
	}
	return accounts, nil
}

func shadowStates(lines []string) map[string]string {
	states := map[string]string{}
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		switch hash := fields[1]; {
		case hash == "":
			states[fields[0]] = PasswordEmpty
		case strings.HasPrefix(hash, "!") || strings.HasPrefix(hash, "*"):
			states[fields[0]] = PasswordLocked
		default:
			states[fields[0]] = PasswordSet
		}
	}
	return states
}

// homes returns the distinct home directories of the accounts, as Source paths.
func homes(accounts []Account) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range accounts {
		if a.Home == "" || a.Home == "/" || a.Home == "/nonexistent" {
			continue
		}
		h := collector.Rel(a.Home)
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}
