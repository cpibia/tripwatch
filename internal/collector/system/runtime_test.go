package system

import (
	"context"
	"crypto/md5"  //nolint:gosec // matches the dpkg checksum format under test
	"crypto/sha1" //nolint:gosec // matches the apk checksum format under test
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/cpibia/tripwatch/internal/collector"
)

func link(target string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(target), Mode: fs.ModeSymlink}
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // see import
	return hex.EncodeToString(sum[:])
}

const (
	hostNetNS      = "net:[4026531840]"
	containerNetNS = "net:[4026532999]"
	tcpHeader      = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
)

// procHost has systemd, a kernel thread, MySQL listening on localhost, a reverse shell
// disguised as a kernel thread whose binary was deleted, and a container in its own network
// namespace.
func procHost() fstest.MapFS {
	return fstest.MapFS{
		"proc/1/status":  text("Name:\tsystemd\nPPid:\t0\nUid:\t0\t0\t0\t0\n"),
		"proc/1/comm":    text("systemd\n"),
		"proc/1/cmdline": text("/sbin/init\x00splash\x00"),
		"proc/1/exe":     link("/usr/lib/systemd/systemd"),
		"proc/1/cwd":     link("/"),
		"proc/1/ns/net":  link(hostNetNS),
		"proc/1/net/tcp": text(tcpHeader + "\n" +
			"   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   111        0 20001 1 0000000000000000 100 0 0 10 0\n" +
			"   1: 0500000A:C822 077100CB:01BB 01 00000000:00000000 02:000A7B2C 00000000    33        0 30001 1 0000000000000000 20 4 30 10 -1\n" +
			"   2: 0500000A:C824 096433C6:0050 02 00000001:00000000 01:00000155 00000002    33        0 30002 1 0000000000000000 400 0 0 10 -1\n" +
			"   3: 0500000A:C826 077100CB:01BB 06 00000000:00000000 03:00001779 00000000     0        0 0 3 0000000000000000\n"),
		"proc/1/net/tcp6": text(tcpHeader + "\n" +
			"   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 20002 1 0000000000000000 100 0 0 10 0\n" +
			"   1: 0000000000000000FFFF00000500000A:01BB 0000000000000000FFFF000004030201:D431 01 00000000:00000000 02:00000A7B 00000000    33        0 20003 1 0000000000000000 20 4 30 10 -1\n"),
		"proc/1/net/udp": text("  sl  local_address rem_address   st\n" +
			"   0: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 20004 2 0000000000000000 0\n"),

		"proc/2/status": text("Name:\tkthreadd\nPPid:\t0\nUid:\t0\t0\t0\t0\n"),
		"proc/2/comm":   text("kthreadd\n"),
		"proc/2/stat":   text("2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 2 0 0"),

		"proc/812/status":  text("Name:\tmysqld\nPPid:\t1\nUid:\t111\t111\t111\t111\n"),
		"proc/812/comm":    text("mysqld\n"),
		"proc/812/cmdline": text("/usr/sbin/mysqld\x00"),
		"proc/812/exe":     link("/usr/sbin/mysqld"),
		"proc/812/ns/net":  link(hostNetNS),
		"proc/812/fd/0":    link("/dev/null"),
		"proc/812/fd/21":   link("socket:[20001]"),

		// The relative exe target lets fstest resolve the link the way the kernel resolves the
		// /proc magic link, so the deleted binary can still be hashed.
		"proc/4242/status":  text("Name:\thelper\nPPid:\t1\nUid:\t33\t33\t33\t33\n"),
		"proc/4242/comm":    text("[kworker/0:2]\n"),
		"proc/4242/cmdline": text("[kworker/0:2]\x00"),
		"proc/4242/exe":     link("../../var/www/.config/x/helper (deleted)"),
		"proc/4242/cwd":     link("/var/www/shop"),
		"proc/4242/environ": text("PATH=/usr/bin\x00LD_PRELOAD=/usr/lib/libprocesshider.so\x00"),
		"proc/4242/maps": text("55d0a000-55d0b000 r-xp 00000000 08:01 1234 /var/www/.config/x/helper (deleted)\n" +
			"7f00a000-7f00b000 r-xp 00000000 08:01 99 /usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)\n" +
			"7f00c000-7f00d000 r-xp 00000000 00:01 7 /memfd:stage2 (deleted)\n" +
			"7f00e000-7f00f000 rw-p 00000000 08:01 55 /dev/shm/data\n" +
			"7f010000-7f011000 r-xp 00000000 08:01 56 /dev/shm/.inject.so\n" +
			"7f020000-7f021000 r-xs 08000000 00:01 9 /dev/zero (deleted)\n" +
			"7f040000-7f041000 r-xs 00000000 08:01 11 /dev/zero (deleted)\n" +
			"7f030000-7f031000 r-xs 00000000 00:01 10 /memfd:doublemapper (deleted)\n" +
			"7ffd0000-7ffd1000 rwxp 00000000 00:00 0 [stack]\n"),
		"proc/4242/ns/net": link(hostNetNS),
		"proc/4242/fd/5":   link("socket:[30001]"),
		"proc/4242/fd/9":   link("socket:[30009]"),
		"proc/1/net/packet": text("sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n" +
			"ffff8880 3      3    0003   2     1 0      0      30009\n"),
		"proc/1/net/raw": text("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
			"   1: 00000000:0001 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 30010 2 0000000000000000 0\n"),
		"var/www/.config/x/helper (deleted)": text("payload"),

		"proc/5000/status":  text("Name:\tnginx\nPPid:\t4999\nUid:\t0\t0\t0\t0\n"),
		"proc/5000/comm":    text("nginx\n"),
		"proc/5000/cmdline": text("nginx: master process\x00"),
		"proc/5000/exe":     link("/usr/sbin/nginx"),
		"proc/5000/ns/net":  link(containerNetNS),
		"proc/5000/fd/6":    link("socket:[40001]"),
		"proc/5000/net/tcp": text(tcpHeader + "\n" +
			"   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 40001 1 0000000000000000 100 0 0 10 0\n"),

		"proc/self":    link("4242"),
		"proc/meminfo": text("MemTotal: 1 kB\n"),
	}
}

func TestProcesses(t *testing.T) {
	res := collect[ProcessesResult](t, Processes{}, collector.Source{FS: procHost()})

	if res.KernelThreads != 1 {
		t.Errorf("kernel threads = %d, want 1", res.KernelThreads)
	}
	var pidList []int
	byPID := map[int]Process{}
	for _, p := range res.Processes {
		pidList = append(pidList, p.PID)
		byPID[p.PID] = p
	}
	if !slices.Equal(pidList, []int{1, 812, 4242, 5000}) {
		t.Fatalf("pids = %v", pidList)
	}

	if init := byPID[1]; init.Cmdline != "/sbin/init splash" || init.Exe != "/usr/lib/systemd/systemd" || init.NetNS != hostNetNS {
		t.Errorf("init = %+v", init)
	}
	if mysql := byPID[812]; mysql.UID != 111 || mysql.EUID != 111 || mysql.PPID != 1 {
		t.Errorf("mysqld = %+v", mysql)
	}

	shell := byPID[4242]
	payload := sha256.Sum256([]byte("payload"))
	switch {
	case shell.Comm != "[kworker/0:2]" || shell.UID != 33:
		t.Errorf("disguised process = %+v", shell)
	case !shell.ExeDeleted || shell.Exe != "../../var/www/.config/x/helper":
		t.Errorf("exe = %q deleted=%v", shell.Exe, shell.ExeDeleted)
	case shell.ExeSHA256 != hex.EncodeToString(payload[:]):
		t.Errorf("exe hash = %q", shell.ExeSHA256)
	case shell.Preload != "/usr/lib/libprocesshider.so" || shell.Cwd != "/var/www/shop":
		t.Errorf("preload = %q cwd = %q", shell.Preload, shell.Cwd)
	}
	if !slices.Equal(shell.Mapped, []string{"/var/www/.config/x/helper (deleted)", "/memfd:stage2 (deleted)", "/dev/shm/.inject.so", "/dev/zero (deleted)", "/memfd:doublemapper (deleted)"}) {
		t.Errorf("mapped = %q", shell.Mapped)
	}
}

func TestProcessesWithoutProc(t *testing.T) {
	res := collect[ProcessesResult](t, Processes{}, collector.Source{FS: fstest.MapFS{}})
	if len(res.Processes) != 0 || res.KernelThreads != 0 {
		t.Errorf("result = %+v", res)
	}
}

func TestSockets(t *testing.T) {
	res := collect[SocketsResult](t, Sockets{}, collector.Source{FS: procHost()})

	if res.Namespaces != 2 {
		t.Errorf("namespaces = %d, want 2", res.Namespaces)
	}
	want := []Socket{
		{Proto: "tcp", Local: "127.0.0.1:3306", State: "listen", UID: 111, PID: 812, Process: "mysqld", NetNS: hostNetNS},
		{Proto: "tcp", Local: "10.0.0.5:51234", Remote: "203.0.113.7:443", State: "established", UID: 33, PID: 4242, Process: "[kworker/0:2]", NetNS: hostNetNS},
		{Proto: "tcp", Local: "10.0.0.5:51236", Remote: "198.51.100.9:80", State: "syn_sent", UID: 33, NetNS: hostNetNS},
		{Proto: "tcp6", Local: "[::]:22", State: "listen", NetNS: hostNetNS},
		{Proto: "tcp6", Local: "10.0.0.5:443", Remote: "1.2.3.4:54321", State: "established", UID: 33, NetNS: hostNetNS},
		{Proto: "udp", Local: "127.0.0.53:53", State: "unconnected", UID: 101, NetNS: hostNetNS},
		{Proto: "raw", Local: "0.0.0.0:1", State: "unconnected", NetNS: hostNetNS},
		{Proto: "packet", Local: "ethertype 0x0003, interface 2", State: "raw", PID: 4242, Process: "[kworker/0:2]", NetNS: hostNetNS, Exe: "../../var/www/.config/x/helper (deleted)"},
		{Proto: "tcp", Local: "0.0.0.0:80", State: "listen", PID: 5000, Process: "nginx", NetNS: containerNetNS},
	}
	if !slices.Equal(res.Sockets, want) {
		t.Errorf("sockets:\n got  %+v\n want %+v", res.Sockets, want)
	}
}

func TestSocketsFallBackToOwnNamespace(t *testing.T) {
	fsys := fstest.MapFS{"proc/net/tcp": text(tcpHeader + "\n" +
		"   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   111        0 20001 1 0000000000000000 100 0 0 10 0\n")}
	res := collect[SocketsResult](t, Sockets{}, collector.Source{FS: fsys})
	if res.Namespaces != 1 || len(res.Sockets) != 1 || res.Sockets[0].Local != "127.0.0.1:3306" {
		t.Errorf("result = %+v", res)
	}
}

func TestParseSocketLineRejectsMalformed(t *testing.T) {
	for _, line := range []string{
		"",
		tcpHeader,
		"0: ZZ00007F:0CEA 00000000:0000 0A 0 0 0 0 0 1",
		"0: 0100007F 00000000:0000 0A 0 0 0 0 0 1",
		"0: 0100007F:XXXX 00000000:0000 0A 0 0 0 0 0 1",
		"0: 0100007F:0CEA 000000:0000 0A 0 0 0 0 0 1",
	} {
		if s, _, ok := parseSocketLine("tcp", line); ok {
			t.Errorf("parseSocketLine(%q) = %+v, want rejection", line, s)
		}
	}
}

func dpkgHost() fstest.MapFS {
	return fstest.MapFS{
		"var/lib/dpkg/status": text("Package: openssh-server\nStatus: install ok installed\nVersion: 1:8.9p1\n" +
			"Conffiles:\n /etc/ssh/moduli " + md5hex("moduli") + "\n /etc/ssh/sshd_config " + md5hex("original config") + "\n" +
			" /etc/init/ssh.conf 0123456789abcdef0123456789abcdef obsolete\nDescription: secure shell server\n\n" +
			"Package: coreutils\nStatus: install ok installed\n\n" +
			"Package: telnetd\nStatus: deinstall ok config-files\nConffiles:\n /etc/telnetd.conf " + md5hex("x") + "\n"),
		"var/lib/dpkg/info/openssh-server.md5sums": text(md5hex("sshd") + "  usr/sbin/sshd\n" +
			md5hex("scp") + "  usr/bin/scp\n" +
			md5hex("readme") + "  usr/share/doc/openssh-server/README\n"),
		"var/lib/dpkg/info/openssh-server.list": text("/usr/sbin/sshd\n/usr/bin/scp\n"),
		"var/lib/dpkg/info/coreutils:amd64.md5sums": text(md5hex("ls") + "  bin/ls\n" +
			md5hex("original x") + "  usr/bin/x\n"),
		"var/lib/dpkg/info/coreutils:amd64.list": text("/bin/ls\n/usr/bin/x\n/usr/bin/vim.basic\n"),
		"var/lib/dpkg/info/linux-headers.list": text("/usr/src/linux-headers-6.8/.config\n/usr/src/linux-headers-6.8/tools/.fixdep.o.d\n" +
			"/usr/lib/modules/6.8/vdso/.build-id\n/usr/lib/modules/6.8/vdso/.build-id/ab\n/usr/lib/modules/6.8/vdso/.build-id/ab/cdef.debug\n"),
		"var/lib/dpkg/diversions": text("/usr/bin/x\n/usr/bin/x.distrib\nother-package\n"),

		"bin":                         link("usr/bin"),
		"usr/bin/ls":                  text("ls"),
		"usr/bin/x":                   text("replaced by the diverting package"),
		"usr/bin/backdoor":            text("not from any package"),
		"usr/bin/editor":              link("/etc/alternatives/editor"),
		"usr/local/bin/sudo":          link("/dev/shm/x"),
		"etc/alternatives/editor":     link("/usr/bin/vim.basic"),
		"usr/bin/vim.basic":           text("vim"),
		"usr/local/bin/su":            link("/etc/alternatives/evil"),
		"etc/alternatives/evil":       link("/dev/shm/y"),
		"usr/local/bin/vi":            link("/etc/alternatives/../../dev/shm/vi"),
		"usr/sbin/sshd":               text("sshd with a backdoor"),
		"etc/ssh/moduli":              text("moduli"),
		"etc/ssh/sshd_config":         text("edited config"),
		"usr/lib/.syslib/fnd":         text("find"),
		"usr/share/.placeholder":      text(""),
		"usr/lib/python3/__init__.py": text(""),

		"usr/src/linux-headers-6.8/.config":                text("CONFIG_X=y"),
		"usr/src/linux-headers-6.8/tools/.fixdep.o.d":      text(""),
		"usr/lib/modules/6.8/vdso/.build-id/ab/cdef.debug": text("elf"),
		"usr/lib/modules/6.8/vdso/.build-id/ab/payload":    text("planted in a packaged hidden directory"),
	}
}

func TestPackagesDpkg(t *testing.T) {
	res := collect[PackagesResult](t, Packages{}, collector.Source{FS: dpkgHost()})
	if st, ok := res.States["openssh-server"]; !ok || st.Version != "1:8.9p1" || len(st.Checksums) != 16 {
		t.Errorf("states = %+v", res.States)
	}
	fsys := dpkgHost()
	fsys["var/lib/dpkg/info/openssh-server.md5sums"] = text(md5hex("rewritten") + "  usr/sbin/sshd\n")
	if again := collect[PackagesResult](t, Packages{}, collector.Source{FS: fsys}); again.States["openssh-server"].Checksums == res.States["openssh-server"].Checksums {
		t.Error("rewritten checksums leave the package's state unchanged")
	}

	if res.Manager != ManagerDpkg || res.Packages != 2 {
		t.Errorf("manager = %q packages = %d", res.Manager, res.Packages)
	}
	want := []ModifiedFile{
		{Path: "/etc/ssh/sshd_config", Package: "openssh-server", Config: true},
		{Path: "/usr/sbin/sshd", Package: "openssh-server"},
	}
	if !slices.Equal(res.Modified, want) {
		t.Errorf("modified = %+v, want %+v", res.Modified, want)
	}
	// moduli, sshd_config, sshd and ls; the diverted file is not checked.
	if res.Checked != 4 {
		t.Errorf("checked = %d, want 4", res.Checked)
	}
	if !slices.Equal(res.Missing, []string{"/usr/bin/scp"}) {
		t.Errorf("missing = %v; documentation must be ignored", res.Missing)
	}
	if !slices.Equal(res.UnownedLinks, []Link{{Path: "/usr/local/bin/su", Target: "/etc/alternatives/evil"}, {Path: "/usr/local/bin/sudo", Target: "/dev/shm/x"}, {Path: "/usr/local/bin/vi", Target: "/etc/alternatives/../../dev/shm/vi"}}) {
		t.Errorf("unowned links = %+v; links managed by update-alternatives are skipped", res.UnownedLinks)
	}
	if len(res.DatabaseSHA256) != 64 {
		t.Errorf("database hash = %q", res.DatabaseSHA256)
	}
	if !slices.Equal(res.Unowned, []string{"/usr/bin/backdoor"}) {
		t.Errorf("unowned = %v; merged-/usr and diverted paths are owned, symlinks are skipped", res.Unowned)
	}
	if !slices.Equal(res.Hidden, []string{"/usr/lib/.syslib", "/usr/lib/modules/6.8/vdso/.build-id/ab/payload", "/usr/share/.placeholder"}) {
		t.Errorf("hidden = %v; packaged hidden entries are skipped, what was added inside them is not", res.Hidden)
	}
}

func TestPackagesApk(t *testing.T) {
	sum := sha1.Sum([]byte("busybox")) //nolint:gosec // see import
	fsys := fstest.MapFS{
		"lib/apk/db/installed": text("C:Q1abc=\nP:busybox\nV:1.36\n" +
			"F:bin\nR:busybox\nZ:Q1" + base64.StdEncoding.EncodeToString(sum[:]) + "\nR:sh\n\n" +
			"P:musl\nF:lib\nR:ld-musl-aarch64.so.1\nZ:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"),
		"bin/busybox":              text("busybox"),
		"bin/sh":                   link("/bin/busybox"),
		"lib/ld-musl-aarch64.so.1": text("tampered"),
		"usr/local/bin/miner":      text("xmrig"),
	}
	res := collect[PackagesResult](t, Packages{}, collector.Source{FS: fsys})

	if res.Manager != ManagerApk || res.Packages != 2 || res.Checked != 2 {
		t.Errorf("manager = %q packages = %d checked = %d", res.Manager, res.Packages, res.Checked)
	}
	if !slices.Equal(res.Modified, []ModifiedFile{{Path: "/lib/ld-musl-aarch64.so.1", Package: "musl"}}) {
		t.Errorf("modified = %+v", res.Modified)
	}
	if !slices.Equal(res.Unowned, []string{"/usr/local/bin/miner"}) {
		t.Errorf("unowned = %v", res.Unowned)
	}
}

func TestPackagesAbsent(t *testing.T) {
	none := collect[PackagesResult](t, Packages{}, collector.Source{FS: fstest.MapFS{}})
	if none.Manager != "" {
		t.Errorf("no package manager = %+v", none)
	}
}

func TestPackagesStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Packages{}).Collect(ctx, collector.Source{FS: dpkgHost()}); err == nil {
		t.Error("cancelled collection did not stop")
	}
}

// fakeExeFS reports the same exe path for different processes, as processes in different
// mount namespaces do, while each /proc/<pid>/exe opens a different binary.
type fakeExeFS struct{ fstest.MapFS }

func (f fakeExeFS) ReadLink(name string) (string, error) {
	if strings.HasSuffix(name, "/exe") {
		return "/usr/sbin/sshd", nil
	}
	return f.MapFS.ReadLink(name)
}

func TestProcessesSamePathDifferentBinary(t *testing.T) {
	fsys := fakeExeFS{fstest.MapFS{
		"proc/10/status": text("Name:\tsshd\nPPid:\t1\nUid:\t0\t0\t0\t0\n"),
		"proc/10/stat":   text("10 (sshd) S 1 10 10 0 -1 4194560 0 0"),
		"proc/10/exe":    text("genuine sshd"),
		"proc/11/status": text("Name:\tsshd\nPPid:\t1\nUid:\t0\t0\t0\t0\n"),
		"proc/11/stat":   text("11 (sshd) S 1 11 11 0 -1 4194560 0 0"),
		"proc/11/exe":    text("trojaned sshd"),
	}}
	res := collect[ProcessesResult](t, Processes{}, collector.Source{FS: fsys})
	if len(res.Processes) != 2 || res.Processes[0].ExeSHA256 == res.Processes[1].ExeSHA256 {
		t.Errorf("two binaries behind the same path got hashes %q and %q", res.Processes[0].ExeSHA256, res.Processes[1].ExeSHA256)
	}
}

// A user process whose exe cannot be read and whose argv is empty must not pass for a kernel
// thread: only the PF_KTHREAD flag makes one.
func TestProcessesKernelThreadFlag(t *testing.T) {
	fsys := fstest.MapFS{
		"proc/2/status":   text("Name:\tkthreadd\nPPid:\t0\nUid:\t0\t0\t0\t0\n"),
		"proc/2/stat":     text("2 (kthreadd) S 0 0 0 0 -1 2129984 0 0"),
		"proc/77/status":  text("Name:\tkworker/0:1\nPPid:\t2\nUid:\t0\t0\t0\t0\n"),
		"proc/700/status": text("Name:\thidden\nPPid:\t1\nUid:\t33\t33\t33\t33\n"),
		"proc/700/stat":   text("700 (a) b) (c) S 1 700 700 0 -1 4194560 0 0"),
		"proc/700/comm":   text("[kworker/1:0]\n"),
	}
	res := collect[ProcessesResult](t, Processes{}, collector.Source{FS: fsys})
	if res.KernelThreads != 2 {
		t.Errorf("kernel threads = %d, want 2 (flag, and parent kthreadd without stat)", res.KernelThreads)
	}
	if len(res.Processes) != 1 || res.Processes[0].PID != 700 {
		t.Fatalf("processes = %+v, want the impostor listed", res.Processes)
	}
	if len(res.Issues) == 0 {
		t.Error("an unreadable exe link must be reported as an issue")
	}
}

// Updating a checksum to match a replaced file hides it from verification, but not from the
// database fingerprint.
func TestPackageDatabaseFingerprint(t *testing.T) {
	before := collect[PackagesResult](t, Packages{}, collector.Source{FS: dpkgHost()})
	tampered := dpkgHost()
	tampered["var/lib/dpkg/info/openssh-server.md5sums"] = text(md5hex("sshd with a backdoor") + "  usr/sbin/sshd\n")
	after := collect[PackagesResult](t, Packages{}, collector.Source{FS: tampered})
	if slices.ContainsFunc(after.Modified, func(m ModifiedFile) bool { return m.Path == "/usr/sbin/sshd" }) {
		t.Fatal("fixture: the checksum update should hide the modified binary")
	}
	if before.DatabaseSHA256 == after.DatabaseSHA256 {
		t.Error("the database fingerprint did not change")
	}
}
