package apps

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/go-sql-driver/mysql"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/system"
)

// maxConnBytes bounds what one database connection may send back: the server at the other end
// is trusted only as far as the checks below go.
const maxConnBytes = 64 << 20

// databaseProcesses are the server processes a local endpoint must belong to.
var databaseProcesses = []string{"mysqld", "mariadbd"}

// socketPaths are where MySQL and MariaDB put their socket on common distributions. /tmp is
// left out on purpose: anyone can create a socket there.
var socketPaths = []string{"run/mysqld/mysqld.sock", "var/run/mysqld/mysqld.sock", "var/lib/mysql/mysql.sock"}

var errUntrustedHost = errors.New("not a local MySQL server")

// endpoint decides where to connect for cfg, or refuses. The configuration that names the host
// may have been written by an attacker, who would then receive the real credentials, so the
// sensor only connects to:
//   - a Unix socket owned by the database user or root, in a directory nobody else can write,
//     with a database server running;
//   - a loopback port on which a database server process is listening;
//   - a host the operator listed explicitly.
func endpoint(ctx context.Context, src collector.Source, cfg dbConfig, allowed []string) (network, addr string, err error) {
	host := strings.ToLower(cfg.Host)
	port := cmpOr(cfg.Port, "3306")

	// An allowed entry names a host and port; a bare host means the default port only.
	if slices.Contains(allowed, net.JoinHostPort(host, port)) || (port == "3306" && slices.Contains(allowed, host)) {
		return "tcp", net.JoinHostPort(cfg.Host, port), nil
	}
	if host == "localhost" || host == "" || cfg.Socket != "" {
		if src.Root != "" {
			if sock, ok := trustedSocket(src, cfg.Socket); ok {
				return "unix", path.Join(src.Root, sock), nil
			}
		}
		if cfg.Socket != "" {
			return "", "", fmt.Errorf("socket %s: %w (owner, directory or server process not as expected)", cfg.Socket, errUntrustedHost)
		}
		host = "127.0.0.1"
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return "", "", fmt.Errorf("%s: %w; add it to -app-db-hosts to query it", cfg.Host, errUntrustedHost)
	}
	target, err := netip.ParseAddrPort(net.JoinHostPort(ip.String(), port))
	if err != nil {
		return "", "", fmt.Errorf("%s:%s: %w", cfg.Host, port, errUntrustedHost)
	}
	if !databaseListening(ctx, src, target) {
		return "", "", fmt.Errorf("%s: %w (no database server process listens on that exact address)", target, errUntrustedHost)
	}
	return "tcp", target.String(), nil
}

func trustedSocket(src collector.Source, configured string) (string, bool) {
	candidates := socketPaths
	if configured != "" {
		candidates = []string{collector.Rel(configured)}
	}
	owners := databaseUIDs(src)
	if !databaseRunning(src) {
		return "", false
	}
	for _, c := range candidates {
		info, err := fs.Lstat(src.FS, c)
		if err != nil || info.Mode()&fs.ModeSocket == 0 {
			continue
		}
		uid, ok := collector.Owner(info)
		if !ok || !slices.Contains(owners, uid) {
			continue
		}
		dir, err := fs.Lstat(src.FS, path.Dir(c))
		if err != nil || !dir.IsDir() || dir.Mode().Perm()&0o022 != 0 {
			continue
		}
		if duid, ok := collector.Owner(dir); !ok || !slices.Contains(owners, duid) {
			continue
		}
		return "/" + c, true
	}
	return "", false
}

// databaseUIDs are root and the users database servers run as.
func databaseUIDs(src collector.Source) []uint32 {
	uids := []uint32{0}
	lines, _ := collector.ReadLines(src.FS, "etc/passwd")
	for _, line := range lines {
		f := strings.Split(line, ":")
		if len(f) > 2 && (f[0] == "mysql" || f[0] == "mariadb") {
			if uid, err := strconv.ParseUint(f[2], 10, 32); err == nil {
				uids = append(uids, uint32(uid))
			}
		}
	}
	return uids
}

func databaseRunning(src collector.Source) bool {
	entries, err := fs.ReadDir(src.FS, "proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		comm, err := fs.ReadFile(src.FS, "proc/"+e.Name()+"/comm")
		if err == nil && slices.Contains(databaseProcesses, strings.TrimSpace(string(comm))) {
			return true
		}
	}
	return false
}

// databaseListening requires a listening socket that serves exactly target, in the sensor's
// own network namespace, held by a database server process running as root or as the database
// user. Matching the port alone is not enough: with the server on 127.0.0.1:3306 anyone can
// listen on [::1]:3306, or on the same port in another namespace. The address that serves
// target is the address itself or the unspecified address of the same family.
func databaseListening(ctx context.Context, src collector.Source, target netip.AddrPort) bool {
	out, err := system.Sockets{}.Collect(ctx, src)
	if err != nil {
		return false
	}
	ownNS, _ := fs.ReadLink(src.FS, "proc/self/ns/net")
	owners := databaseUIDs(src)
	for _, s := range out.(system.SocketsResult).Sockets {
		if s.State != "listen" || s.PID == 0 || !slices.Contains(databaseProcesses, s.Process) || !slices.Contains(owners, uint32(s.UID)) { //nolint:gosec // UIDs fit in 32 bits
			continue
		}
		if ownNS != "" && s.NetNS != "" && s.NetNS != ownNS {
			continue
		}
		local, err := netip.ParseAddrPort(s.Local)
		if err != nil || local.Port() != target.Port() {
			continue
		}
		addr := local.Addr()
		if addr == target.Addr() || (addr.IsUnspecified() && addr.Is4() == target.Addr().Is4()) {
			return true
		}
	}
	return false
}

// limitedConn ends the connection once the peer has sent more than its allowance.
type limitedConn struct {
	net.Conn
	left int64
}

var errConnLimit = errors.New("database connection sent more than allowed")

func (c *limitedConn) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errConnLimit
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.Conn.Read(p)
	c.left -= int64(n)
	return n, err
}

const (
	dialTCP  = "tripwatch-tcp"
	dialUnix = "tripwatch-unix"
)

var registerDialers = sync.OnceFunc(func() {
	for name, network := range map[string]string{dialTCP: "tcp", dialUnix: "unix"} {
		mysql.RegisterDialContext(name, func(ctx context.Context, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{Timeout: connectTimeout}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &limitedConn{Conn: conn, left: maxConnBytes}, nil
		})
	}
})
