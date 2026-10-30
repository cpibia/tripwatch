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

// Bounds on reading the kernel's socket tables: a row is about 150 bytes, and a million rows,
// past what one account's descriptors reach by default, take a few seconds to parse.
const (
	maxSocketLine  = 512
	maxSocketLines = 1 << 20
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
	// Exe is recorded for packet and raw sockets only: they see traffic no port shows, which is
	// how backdoors that open no port wait for their trigger, and a process name is free to fake.
	Exe string `json:"exe,omitempty"`
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

// MaxSockets bounds the sockets one result reports. Any user can open tens of thousands of
// sockets, and a result past the verifier's budget is refused whole, taking the listening,
// raw and packet sockets its rules read with it. Over the bound those come first, and what is
// left out is counted by owner.
const MaxSockets = 20_000

// socketRank orders sockets by what they tell: raw and packet sockets, which only privileged
// processes open, then root's sockets, then any listener, then the rest.
func socketRank(s Socket) int {
	switch {
	case s.Proto == "packet" || strings.HasPrefix(s.Proto, "raw"):
		return 0
	case s.UID == 0:
		return 1
	case s.State == "listen":
		return 2
	}
	return 3
}

// socketBound keeps at most MaxSockets of each rank as they are read, so memory stays bounded
// whatever the number of sockets, and counts the ones dropped by owner.
type socketBound struct {
	ranks   [4][]Socket
	total   int
	dropped map[int]int
	order   []int
}

func (b *socketBound) add(s Socket) {
	r := socketRank(s)
	if len(b.ranks[r]) < MaxSockets {
		b.ranks[r] = append(b.ranks[r], s)
		b.order = append(b.order, r)
		b.total++
		return
	}
	b.drop(s.UID)
}

// maxDroppedOwners bounds the owners named in an issue; the others are summed.
const maxDroppedOwners = 32

func (b *socketBound) drop(uid int) {
	if b.dropped == nil {
		b.dropped = map[int]int{}
	}
	b.dropped[uid]++
}

// result returns the sockets in the order they were read when they fit, the most telling ones
// first when they do not, and an issue naming who opened the ones left out.
func (b *socketBound) result(res *SocketsResult) {
	switch {
	case b.total == 0:
	case b.total <= MaxSockets:
		next := [4]int{}
		res.Sockets = make([]Socket, 0, b.total)
		for _, r := range b.order {
			res.Sockets = append(res.Sockets, b.ranks[r][next[r]])
			next[r]++
		}
	default:
		res.Sockets = make([]Socket, 0, MaxSockets)
		for _, rank := range b.ranks {
			room := MaxSockets - len(res.Sockets)
			res.Sockets = append(res.Sockets, rank[:min(len(rank), room)]...)
			for _, s := range rank[min(len(rank), room):] {
				b.drop(s.UID)
			}
		}
	}
	if len(b.dropped) == 0 {
		return
	}
	sum := 0
	for _, n := range b.dropped {
		sum += n
	}
	res.Issues = append(res.Issues, fmt.Sprintf("%d sockets left out over the limit of %d: %s", sum, MaxSockets, byOwner(b.dropped)))
}

func (Sockets) Collect(ctx context.Context, src collector.Source) (any, error) {
	var res SocketsResult
	var bound socketBound

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
		// Read as streams: anyone can open sockets until a table outgrows what is read at
		// once, and the bound keeps root's and the listeners first.
		for _, proto := range []string{"tcp", "tcp6", "udp", "udp6", "raw", "raw6"} {
			cut, err := collector.EachLine(src.FS, dir+proto, maxSocketLine, maxSocketLines, func(line string) {
				s, inode, ok := parseSocketLine(proto, line)
				if !ok {
					return
				}
				s.NetNS = ns
				if pid, found := owners[inode]; found {
					s.PID, s.Process = pid, comms[pid]
					if strings.HasPrefix(proto, "raw") {
						s.Exe = exeOf(src.FS, pid)
					}
				}
				bound.add(s)
			})
			res.Issues.Add(err)
			if cut {
				res.Issues.Add(fmt.Errorf("%s%s: more than %d lines, the rest not read", dir, proto, maxSocketLines))
			}
		}
		cut, err := collector.EachLine(src.FS, dir+"packet", maxSocketLine, maxSocketLines, func(line string) {
			s, inode, ok := parsePacketLine(line)
			if !ok {
				return
			}
			s.NetNS = ns
			if pid, found := owners[inode]; found {
				s.PID, s.Process, s.Exe = pid, comms[pid], exeOf(src.FS, pid)
			}
			bound.add(s)
		})
		res.Issues.Add(err)
		if cut {
			res.Issues.Add(fmt.Errorf("%spacket: more than %d lines, the rest not read", dir, maxSocketLines))
		}
	}
	bound.result(&res)
	return res, nil
}

// parsePacketLine parses one row of /proc/net/packet (sk RefCnt Type Proto Iface R Rmem User
// Inode) into a socket whose local address names the ethertype and the interface index.
func parsePacketLine(line string) (Socket, string, bool) {
	f := strings.Fields(line)
	if len(f) < 9 || f[0] == "sk" {
		return Socket{}, "", false
	}
	kind := map[string]string{"1": "stream", "2": "dgram", "3": "raw"}[f[2]]
	if kind == "" {
		kind = "type " + f[2]
	}
	uid, _ := strconv.Atoi(f[7])
	return Socket{Proto: "packet", Local: fmt.Sprintf("ethertype 0x%s, interface %s", f[3], f[4]), State: kind, UID: uid}, f[8], true
}

func exeOf(fsys fs.FS, pid int) string {
	exe, _ := fs.ReadLink(fsys, fmt.Sprintf("proc/%d/exe", pid))
	return exe
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
