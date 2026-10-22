package system

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

const deletedSuffix = " (deleted)"

// Process is a running process as seen in /proc. Exe is where the binary was loaded from;
// ExeDeleted means it was removed from disk after starting, a common way to leave no file
// behind. ExeSHA256 is computed through /proc, so it is available even then.
type Process struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	UID        int    `json:"uid"`
	EUID       int    `json:"euid"`
	Comm       string `json:"comm"`
	Cmdline    string `json:"cmdline"`
	Exe        string `json:"exe,omitempty"`
	ExeDeleted bool   `json:"exe_deleted,omitempty"`
	ExeSHA256  string `json:"exe_sha256,omitempty"`
	Cwd        string `json:"cwd,omitempty"`
	Preload    string `json:"ld_preload,omitempty"`
	NetNS      string `json:"netns,omitempty"`
}

type ProcessesResult struct {
	Processes     []Process        `json:"processes"`
	KernelThreads int              `json:"kernel_threads"`
	Issues        collector.Issues `json:"issues,omitempty"`
}

// Processes collects every user-space process from /proc. Kernel threads are only counted;
// a process that names itself like one ([kworker/0:1]) still has an executable and is listed.
type Processes struct{}

func (Processes) Name() string { return "processes" }

func (Processes) Collect(ctx context.Context, src collector.Source) (any, error) {
	var res ProcessesResult
	hashes := map[string]string{}

	for _, pid := range pids(src.FS) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p, ok := readProcess(src.FS, pid)
		if !ok {
			continue
		}
		if p.Exe == "" && p.Cmdline == "" {
			res.KernelThreads++
			continue
		}
		if p.Exe != "" {
			key := p.Exe + strconv.FormatBool(p.ExeDeleted)
			sum, seen := hashes[key]
			if !seen {
				f, err := collector.Describe(src, fmt.Sprintf("proc/%d/exe", pid))
				res.Issues.Add(err)
				sum = f.SHA256
				hashes[key] = sum
			}
			p.ExeSHA256 = sum
		}
		res.Processes = append(res.Processes, p)
	}
	return res, nil
}

// pids lists the numeric entries of /proc, in ascending order.
func pids(fsys fs.FS) []int {
	entries, err := fs.ReadDir(fsys, "proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && e.IsDir() {
			out = append(out, pid)
		}
	}
	slices.Sort(out)
	return out
}

// readProcess returns false when the process exited while being read.
func readProcess(fsys fs.FS, pid int) (Process, bool) {
	dir := fmt.Sprintf("proc/%d/", pid)
	status, err := fs.ReadFile(fsys, dir+"status")
	if err != nil {
		return Process{}, false
	}

	p := Process{PID: pid}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, _ := strings.Cut(line, ":")
		fields := strings.Fields(value)
		switch {
		case key == "PPid" && len(fields) > 0:
			p.PPID, _ = strconv.Atoi(fields[0])
		case key == "Uid" && len(fields) > 1:
			p.UID, _ = strconv.Atoi(fields[0])
			p.EUID, _ = strconv.Atoi(fields[1])
		}
	}

	comm, _ := fs.ReadFile(fsys, dir+"comm")
	p.Comm = strings.TrimSpace(string(comm))

	cmdline, _ := fs.ReadFile(fsys, dir+"cmdline")
	p.Cmdline = strings.TrimSpace(string(bytes.ReplaceAll(cmdline, []byte{0}, []byte{' '})))

	if exe, err := fs.ReadLink(fsys, dir+"exe"); err == nil {
		p.Exe, p.ExeDeleted = strings.CutSuffix(exe, deletedSuffix)
	}
	p.Cwd, _ = fs.ReadLink(fsys, dir+"cwd")
	p.NetNS, _ = fs.ReadLink(fsys, dir+"ns/net")

	if environ, err := fs.ReadFile(fsys, dir+"environ"); err == nil {
		for _, kv := range bytes.Split(environ, []byte{0}) {
			if v, ok := bytes.CutPrefix(kv, []byte("LD_PRELOAD=")); ok {
				p.Preload = string(v)
			}
		}
	}
	return p, true
}
