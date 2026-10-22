package system

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cpibia/tripwatch/internal/collector"
)

// TCP states from include/net/tcp_states.h that matter for detection: listeners, open
// connections, and outbound attempts that never completed (SYN_SENT is what a blocked
// egress looks like).
var tcpStates = map[string]string{
	"01": "established",
	"02": "syn_sent",
	"03": "syn_recv",
	"0A": "listen",
}

type Socket struct {
	Proto   string `json:"proto"`
	Local   string `json:"local"`
	Remote  string `json:"remote,omitempty"`
	State   string `json:"state"`
	UID     int    `json:"uid"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
	NetNS   string `json:"netns,omitempty"`
}

type SocketsResult struct {
	Sockets    []Socket         `json:"sockets"`
	Namespaces int              `json:"namespaces"`
	Issues     collector.Issues `json:"issues,omitempty"`
}

// Sockets collects listening sockets and connections from every network namespace, so the
// sockets of containers are seen from the host.
type Sockets struct{}

func (Sockets) Name() string { return "sockets" }

func (Sockets) Collect(ctx context.Context, src collector.Source) (any, error) {
	var res SocketsResult

	owners := map[string]int{}
	comms := map[int]string{}
	namespaces := map[string]int{}
	var nsOrder []string

	for _, pid := range pids(src.FS) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dir := fmt.Sprintf("proc/%d/", pid)
		if ns, err := fs.ReadLink(src.FS, dir+"ns/net"); err == nil {
			if _, seen := namespaces[ns]; !seen {
				namespaces[ns] = pid
				nsOrder = append(nsOrder, ns)
			}
		}
		fds, err := fs.ReadDir(src.FS, dir+"fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := fs.ReadLink(src.FS, dir+"fd/"+fd.Name())
			if inode, ok := strings.CutPrefix(target, "socket:["); ok && err == nil {
				owners[strings.TrimSuffix(inode, "]")] = pid
			}
		}
		comm, _ := fs.ReadFile(src.FS, dir+"comm")
		comms[pid] = strings.TrimSpace(string(comm))
	}

	tables := map[string]string{}
	if len(nsOrder) == 0 {
		// Namespaces unreadable (no permission or no per-process /proc): fall back to the
		// tables of the sensor's own namespace.
		tables[""] = "proc/net/"
	}
	for _, ns := range nsOrder {
		tables[ns] = fmt.Sprintf("proc/%d/net/", namespaces[ns])
	}
	res.Namespaces = len(tables)

	for _, ns := range append([]string{""}, nsOrder...) {
		dir, ok := tables[ns]
		if !ok {
			continue
		}
		for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
			lines, err := collector.ReadLines(src.FS, dir+proto)
			res.Issues.Add(err)
			for _, line := range lines {
				s, inode, ok := parseSocketLine(proto, line)
				if !ok {
					continue
				}
				s.NetNS = ns
				if pid, found := owners[inode]; found {
					s.PID, s.Process = pid, comms[pid]
				}
				res.Sockets = append(res.Sockets, s)
			}
		}
	}
	return res, nil
}

// parseSocketLine parses one row of /proc/net/{tcp,udp}[6] and returns the socket inode.
// TCP sockets in states that carry no signal (TIME_WAIT, CLOSE, ...) are skipped.
func parseSocketLine(proto, line string) (Socket, string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 10 || fields[0] == "sl" {
		return Socket{}, "", false
	}

	state := "unconnected"
	if strings.HasPrefix(proto, "tcp") {
		var ok bool
		if state, ok = tcpStates[fields[3]]; !ok {
			return Socket{}, "", false
		}
	} else if fields[3] == "01" {
		state = "established"
	}

	local, err := parseSocketAddr(fields[1])
	if err != nil {
		return Socket{}, "", false
	}
	remote, err := parseSocketAddr(fields[2])
	if err != nil {
		return Socket{}, "", false
	}
	uid, _ := strconv.Atoi(fields[7])

	s := Socket{Proto: proto, Local: local.String(), State: state, UID: uid}
	if remote.Port() != 0 || !remote.Addr().IsUnspecified() {
		s.Remote = remote.String()
	}
	return s, fields[9], true
}

// parseSocketAddr decodes the kernel's ADDR:PORT hex format. The address is stored as
// 32-bit words in host byte order (little-endian on amd64 and arm64), the port big-endian.
func parseSocketAddr(s string) (netip.AddrPort, error) {
	addrHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("malformed address %q", s)
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("malformed address %q", s)
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("malformed port %q", s)
	}

	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	addr, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}
