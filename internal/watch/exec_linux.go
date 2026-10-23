//go:build linux

package watch

import (
	"context"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/system"
)

// Proc connector constants from include/uapi/linux/connector.h and cn_proc.h.
const (
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1
	procEventExec     = 0x00000002
	procEventUID      = 0x00000004
	nlmsgHdrLen       = 16
	cnMsgLen          = 20
	procEventHdrLen   = 16
)

// MaxInspections bounds how many new processes are looked at each second: a fork bomb or a busy
// build must not turn the sensor into one.
const MaxInspections = 200

// Execs listens to the kernel's process connector and reports the process starts that matter.
type Execs struct {
	src      collector.Source
	out      chan<- Event
	now      func() time.Time
	fd       int
	mu       sync.Mutex
	webUsers map[int]bool
	homes    map[int]string
	uploads  []string
	// Dropped counts events lost because the consumer did not keep up; Skipped, processes not
	// inspected because more started than MaxInspections in a second.
	Dropped atomic.Int64
	Skipped atomic.Int64
	// CapDropErr says why CAP_NET_ADMIN could not be given up after subscribing, if it could not.
	CapDropErr error
}

// NewExecs subscribes to process events. It needs CAP_NET_ADMIN and the initial network
// namespace.
func NewExecs(src collector.Source, out chan<- Event) (*Execs, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())}); err != nil { //nolint:gosec // a process ID is never negative
		_ = unix.Close(fd)
		return nil, err
	}
	msg := make([]byte, nlmsgHdrLen+cnMsgLen+4)
	binary.NativeEndian.PutUint32(msg[0:], nlmsgHdrLen+cnMsgLen+4)
	binary.NativeEndian.PutUint16(msg[4:], unix.NLMSG_DONE)
	binary.NativeEndian.PutUint32(msg[12:], uint32(os.Getpid())) //nolint:gosec // a process ID is never negative
	binary.NativeEndian.PutUint32(msg[16:], cnIdxProc)
	binary.NativeEndian.PutUint32(msg[20:], cnValProc)
	binary.NativeEndian.PutUint16(msg[32:], 4)
	binary.NativeEndian.PutUint32(msg[36:], procCnMcastListen)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	x := &Execs{src: src, out: out, now: time.Now, fd: fd, webUsers: map[int]bool{}}
	x.CapDropErr = dropNetAdmin()
	return x, nil
}

// dropNetAdmin gives up CAP_NET_ADMIN once the subscription exists: receiving needs no
// capability, and a sensor reading hostile input should not keep the power to reconfigure the
// network. Capabilities are per thread, so the change is applied to every thread of the process.
func dropNetAdmin() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return err
	}
	const bit = uint32(1) << unix.CAP_NET_ADMIN
	if data[0].Effective&bit == 0 && data[0].Permitted&bit == 0 {
		return nil
	}
	data[0].Effective &^= bit
	data[0].Permitted &^= bit
	data[0].Inheritable &^= bit
	//nolint:gosec // capset takes pointers to the header and the two data words
	if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return errno
	}
	return nil
}

// Close stops the subscription.
func (x *Execs) Close() error { return unix.Close(x.fd) }

// SetUploads replaces the upload directories, where no account's job is exempted.
func (x *Execs) SetUploads(dirs []string) {
	x.mu.Lock()
	x.uploads = dirs
	x.mu.Unlock()
}

// SetHomes replaces the home directories of the accounts, by UID.
func (x *Execs) SetHomes(homes map[int]string) {
	x.mu.Lock()
	x.homes = homes
	x.mu.Unlock()
}

// SetWebUsers replaces the UIDs taken for the web server's.
func (x *Execs) SetWebUsers(uids []int) {
	m := make(map[int]bool, len(uids))
	for _, u := range uids {
		m[u] = true
	}
	x.mu.Lock()
	x.webUsers = m
	x.mu.Unlock()
}

// Run reads process events until ctx ends.
func (x *Execs) Run(ctx context.Context) error {
	buf := make([]byte, 16<<10)
	fds := []unix.PollFd{{Fd: int32(x.fd), Events: unix.POLLIN}} //nolint:gosec // a file descriptor fits in the int32 poll takes
	second, budget := time.Now(), MaxInspections
	for ctx.Err() == nil {
		n, err := unix.Poll(fds, 500)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if n <= 0 {
			continue
		}
		read, _, err := unix.Recvfrom(x.fd, buf, 0)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ENOBUFS) {
			// The kernel dropped events because they came faster than they were read.
			x.Dropped.Add(1)
			continue
		}
		if err != nil {
			return err
		}
		for b := buf[:read]; len(b) >= nlmsgHdrLen; {
			size := int(binary.NativeEndian.Uint32(b[0:]))
			if size < nlmsgHdrLen || size > len(b) {
				break
			}
			if now := time.Now(); now.Sub(second) >= time.Second {
				second, budget = now, MaxInspections
			}
			if budget > 0 {
				if x.message(b[nlmsgHdrLen:size]) {
					budget--
				}
			} else {
				x.Skipped.Add(1)
			}
			next := (size + 3) &^ 3
			if next > len(b) {
				break
			}
			b = b[next:]
		}
	}
	return nil
}

// message handles one connector message, and reports whether it inspected a process.
func (x *Execs) message(m []byte) bool {
	if len(m) < cnMsgLen+procEventHdrLen+8 {
		return false
	}
	if binary.NativeEndian.Uint32(m[0:]) != cnIdxProc {
		return false
	}
	ev := m[cnMsgLen:]
	what := binary.NativeEndian.Uint32(ev[0:])
	data := ev[procEventHdrLen:]
	pid := int(int32(binary.NativeEndian.Uint32(data[0:])))  //nolint:gosec // the kernel writes a pid_t here
	tgid := int(int32(binary.NativeEndian.Uint32(data[4:]))) //nolint:gosec // the kernel writes a pid_t here
	switch what {
	case procEventExec:
		if pid != tgid {
			return false
		}
		p, ok := system.ReadProcess(x.src.FS, pid)
		if !ok {
			return true
		}
		x.mu.Lock()
		reason, script := classifyExec(p, execContext{webUsers: x.webUsers, homes: x.homes, uploads: x.uploads, fromCron: x.fromCron, owner: x.owner})
		x.mu.Unlock()
		if reason != "" {
			e := x.event(reason, p)
			e.Script = clipText(script)
			x.send(e)
		}
		return true
	case procEventUID:
		if len(data) < 16 {
			return false
		}
		ruid := int(binary.NativeEndian.Uint32(data[8:]))
		euid := int(binary.NativeEndian.Uint32(data[12:]))
		if euid != 0 || ruid == 0 {
			return false
		}
		p, ok := system.ReadProcess(x.src.FS, tgid)
		if ok && privileged(p, ruid, euid) {
			e := x.event(ReasonPrivilege, p)
			e.User, e.EUser = &ruid, &euid
			x.send(e)
		}
		return true
	}
	return false
}

// cronNames are the executable names of cron daemons.
var cronNames = []string{"cron", "crond", "anacron", "fcron"}

// fromCron walks up to four ancestors of a process looking for a cron daemon, known by the
// executable it runs from the system's directories and by running as root: a process name is
// free to set (/proc/self/comm), an executable path and a UID are not.
func (x *Execs) fromCron(p system.Process) bool {
	ppid := p.PPID
	for range 4 {
		if ppid <= 1 {
			return false
		}
		parent, ok := system.ReadProcess(x.src.FS, ppid)
		if !ok {
			return false
		}
		if parent.UID == 0 && !parent.ExeDeleted && slices.Contains(cronNames, path.Base(parent.Exe)) &&
			slices.ContainsFunc(systemBinDirs, func(d string) bool { return strings.HasPrefix(parent.Exe, d) }) {
			return true
		}
		ppid = parent.PPID
	}
	return false
}

// owner returns the owner of a file, without following a final link.
func (x *Execs) owner(p string) (int, bool) {
	info, err := fs.Lstat(x.src.FS, collector.Rel(p))
	if err != nil {
		return 0, false
	}
	uid, ok := collector.Owner(info)
	return int(uid), ok
}

func (x *Execs) event(reason string, p system.Process) Event {
	uid, euid := p.UID, p.EUID
	e := Event{At: x.now().UTC(), Class: ClassExec, Op: "exec", Reason: reason, PID: p.PID, PPID: p.PPID, User: &uid, EUser: &euid,
		Exe: clipText(p.Exe), Cmdline: clipCmdline(p.Cmdline), Comm: clipText(p.Comm), Cwd: clipText(p.Cwd)}
	if parent, ok := system.ReadProcess(x.src.FS, p.PPID); ok {
		e.Parent = clipText(parent.Comm)
	}
	return e
}

func (x *Execs) send(e Event) {
	select {
	case x.out <- e:
	default:
		x.Dropped.Add(1)
	}
}

// maxCmdline bounds the command line kept for a process event.
const maxCmdline = 1024

func clipCmdline(s string) string {
	if len(s) > maxCmdline {
		s = s[:maxCmdline] + "…"
	}
	return strings.ToValidUTF8(s, "")
}

// maxText bounds the other text fields of a process event.
const maxText = 256

func clipText(s string) string {
	if len(s) > maxText {
		s = s[:maxText]
	}
	return strings.ToValidUTF8(s, "")
}
