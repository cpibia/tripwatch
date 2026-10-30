// Command tripwatch-sensor collects the state of the machine it runs on and sends it to the
// verifier. It only observes: every decision is taken by the verifier.
//
// With -bundle it runs as a daemon: a heartbeat every -heartbeat, a snapshot every -interval,
// and, on Linux, the changes to critical paths and the suspicious process starts as they happen.
// Without, it prints one snapshot as JSON and exits.
//
//	echo tw1.... | tripwatch-sensor enroll -token-file -   (writes /etc/tripwatch/bundle.json)
//	tripwatch-sensor -update                                (installs the latest release)
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cpibia/tripwatch/internal/buildinfo"
	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/apps"
	"github.com/cpibia/tripwatch/internal/collector/logs"
	"github.com/cpibia/tripwatch/internal/collector/system"
	"github.com/cpibia/tripwatch/internal/collector/web"
	"github.com/cpibia/tripwatch/internal/discovery"
	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/selfupdate"
	"github.com/cpibia/tripwatch/internal/transport"
	"github.com/cpibia/tripwatch/internal/verifier/pki"
	"github.com/cpibia/tripwatch/internal/watch"
)

type report struct {
	Environment discovery.Environment `json:"environment"`
	Snapshot    collector.Snapshot    `json:"snapshot"`
	Realtime    *watch.Status         `json:"realtime,omitempty"`
}

type sensor struct {
	root       string
	collectors []collector.Collector
	weblog     *logs.Collector
	web        *web.Collector
	realtime   *realtime
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		if err := enroll(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "tripwatch-sensor enroll:", err)
			os.Exit(1)
		}
		return
	}
	showVersion := flag.Bool("version", false, "print the version and exit")
	update := flag.Bool("update", false, "install the latest release, as the same .deb, .rpm or binary as this one, and restart the service")
	rootDir := flag.String("root", "/", "root of the filesystem to observe (the host root when running in a DaemonSet)")
	appDB := flag.Bool("app-db", true, "read administrators, extensions and stored scripts from the databases of recognised applications (local database servers only)")
	appDBHosts := flag.String("app-db-hosts", "", "comma-separated database hosts, as host or host:port, trusted beyond the local server, such as a Docker service name")
	stateDir := flag.String("state-dir", "/var/lib/tripwatch", "directory for state kept between runs, such as log positions (empty to keep none)")
	bundlePath := flag.String("bundle", "", "enrollment bundle issued by the verifier; runs as a daemon reporting to it")
	interval := flag.Duration("interval", time.Hour, "time between snapshots in daemon mode")
	heartbeat := flag.Duration("heartbeat", time.Minute, "time between heartbeats in daemon mode")
	uninstallFlag := flag.Bool("apply-uninstall", false, "remove the sensor and its data on the order of the verifier that revoked this host, as the sensor starts it outside its service (needs -bundle)")
	applyUpdate := flag.Bool("apply-update", false, "install the update the verifier ordered, as the sensor starts it on its own outside its service (needs -bundle)")
	watchOnly := flag.Bool("watch-only", false, "print the real-time event batches as JSON lines until interrupted, without a verifier, to see what the watchers report")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("tripwatch-sensor"))
		return
	}
	if *uninstallFlag {
		if err := applyUninstall(*bundlePath, *stateDir); err != nil {
			fmt.Fprintln(os.Stderr, "tripwatch-sensor -apply-uninstall:", err)
			os.Exit(1)
		}
		return
	}
	if *applyUpdate {
		if err := applyOrderedUpdate(*bundlePath, *stateDir); err != nil {
			fmt.Fprintln(os.Stderr, "tripwatch-sensor -apply-update:", err)
			os.Exit(1)
		}
		return
	}
	if *update {
		if err := selfUpdate(*stateDir); err != nil {
			fmt.Fprintln(os.Stderr, "tripwatch-sensor -update:", err)
			os.Exit(1)
		}
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s := sensor{root: *rootDir, weblog: &logs.Collector{StateDir: *stateDir}, web: &web.Collector{StateDir: *stateDir}}
	s.collectors = append(system.All(), s.web, s.weblog)
	if *appDB {
		s.collectors = append(s.collectors, apps.Collector{AllowedHosts: splitList(*appDBHosts)})
	}

	if *watchOnly {
		s.watchOnly(ctx, log)
		return
	}
	if *bundlePath == "" {
		if err := s.printOnce(ctx); err != nil {
			log.Error("snapshot", "err", err)
			os.Exit(1)
		}
		return
	}
	if *stateDir == "" {
		log.Error("daemon mode needs -state-dir: the chain position must survive restarts")
		os.Exit(1)
	}
	if err := s.daemon(ctx, log, *bundlePath, *stateDir, *interval, *heartbeat); err != nil {
		log.Error("sensor stopped", "err", err)
		os.Exit(1)
	}
}

// enroll registers this host with a token from the verifier's interface and writes the bundle,
// readable by root only. The keys are generated here and never leave the host.
func enroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	tokenFile := fs.String("token-file", "", "file holding the enrollment token shown by the verifier's interface, or - for standard input")
	legacy := fs.String("token", "", "refused: a token on the command line is readable by every local user")
	out := fs.String("out", "/etc/tripwatch/bundle.json", "where to write the bundle")
	_ = fs.Parse(args)
	if *legacy != "" {
		return errors.New("-token is refused, since any local user can read a process's arguments: pass the token on standard input with -token-file -")
	}
	if *tokenFile == "" {
		return errors.New("enroll needs -token-file (- for standard input)")
	}
	var raw []byte
	var err error
	if *tokenFile == "-" {
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, 4096))
	} else {
		raw, err = os.ReadFile(*tokenFile) //nolint:gosec // path given by the operator
	}
	if err != nil {
		return err
	}
	t, err := pki.ParseEnrollToken(string(raw))
	if err != nil {
		return err
	}
	// Refuse to overwrite before using the token, which works only once.
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists: remove it first to enroll this host again", *out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	b, err := transport.Enroll(ctx, t)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := pki.SyncDir(filepath.Dir(*out)); err != nil {
		return err
	}
	fmt.Printf("Enrolled as %s. Start the sensor: systemctl enable --now tripwatch-sensor\n", b.HostID)
	return nil
}

func selfUpdate(stateDir string) error {
	u, err := newUpdater(stateDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	_, err = u.Update(ctx)
	return err
}

func newUpdater(stateDir string) (selfupdate.Updater, error) {
	if runtime.GOOS != "linux" {
		return selfupdate.Updater{}, fmt.Errorf("releases are built for Linux only, not %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return selfupdate.Updater{}, errors.New("run it as root, with sudo")
	}
	exe, err := os.Executable()
	if err != nil {
		return selfupdate.Updater{}, err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return selfupdate.Updater{}, err
	}
	return selfupdate.Updater{
		Client:     &http.Client{Timeout: 5 * time.Minute},
		BaseURL:    selfupdate.Repository,
		Current:    buildinfo.Version,
		Arch:       runtime.GOARCH,
		Executable: exe,
		Out:        os.Stdout,
		Run: func(ctx context.Context, out io.Writer, name string, args ...string) error {
			// A binary install restarts the service itself: the running sensor reports the stop
			// as an update.
			if name == "systemctl" && stateDir != "" {
				_ = os.WriteFile(filepath.Join(stateDir, updatingMarker), nil, 0o600)
			}
			cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed commands; the arguments are our own paths
			cmd.Stdout, cmd.Stderr = out, out
			return cmd.Run()
		},
	}, nil
}

func (s sensor) snapshot(ctx context.Context) report {
	src := collector.NewSource(s.root)
	env := discovery.DetectEnvironment(src.FS, os.Getenv)
	system := discovery.DetectSystem(src.FS, buildinfo.Version, interfaceAddresses())
	env.System = &system
	r := report{
		Environment: env,
		Snapshot:    collector.Run(ctx, src, s.collectors, time.Now()),
	}
	if s.realtime != nil {
		r.Realtime = s.realtime.status()
		s.realtime.update(r.Snapshot)
	}
	return r
}

// interfaceAddresses lists the addresses of the sensor's network interfaces that identify the
// machine: loopback and link-local ones say nothing about which server this is, and neither do
// the bridges and virtual links of container runtimes, which carry the same address everywhere.
func interfaceAddresses() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range ifaces {
		if containerInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() || ipnet.IP.IsLinkLocalMulticast() {
				continue
			}
			out = append(out, ipnet.IP.String())
		}
	}
	return out
}

// containerInterfacePrefixes name the interfaces Docker, Podman, LXD, libvirt and Kubernetes
// network plugins create.
var containerInterfacePrefixes = []string{"docker", "br-", "veth", "cni", "flannel", "cali", "cilium", "weave", "vxlan", "kube-", "podman", "lxdbr", "virbr", "tunl", "nodelocaldns"}

func containerInterface(name string) bool {
	return slices.ContainsFunc(containerInterfacePrefixes, func(p string) bool { return strings.HasPrefix(name, p) })
}

func (s sensor) printOnce(ctx context.Context) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s.snapshot(ctx)); err != nil {
		return err
	}
	// Log positions and code manifests advance only once the snapshot carrying them is out.
	return s.commit()
}

// watchOnly prints what the watchers report, pointed at what one snapshot finds, until ctx ends.
func (s sensor) watchOnly(ctx context.Context, log *slog.Logger) {
	var mu sync.Mutex
	s.realtime = s.startRealtime(ctx, log, func(_ context.Context, payload []byte) error {
		mu.Lock()
		defer mu.Unlock()
		_, err := os.Stdout.Write(append(payload, '\n'))
		return err
	})
	s.snapshot(ctx)
	log.Info("watching", "status", s.realtime.status())
	<-ctx.Done()
}

func (s sensor) daemon(ctx context.Context, log *slog.Logger, bundlePath, stateDir string, interval, heartbeat time.Duration) error {
	bundle, key, err := pki.LoadBundle(bundlePath)
	if err != nil {
		return err
	}
	identity, err := bundle.ClientIdentity(stateDir)
	if err != nil {
		return err
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: identity.TLS()}, Timeout: 2 * time.Minute}
	client, err := transport.New(bundle.VerifierURL, httpClient, stateDir, bundle.HostID, key)
	if err != nil {
		return err
	}
	if ca, err := bundle.CAPublicKey(); err != nil {
		log.Warn("update orders ignored: no CA key in the bundle", "err", err)
	} else {
		orders := &updateOrders{ca: ca, hostID: bundle.HostID, bundlePath: bundlePath, stateDir: stateDir, log: log, tried: map[string]time.Time{}}
		client.OnUpdate = func(payload, signature string) { go orders.receive(payload, signature) }
		// Synchronous: the refusal that carries it may end the sensor right after.
		client.OnUninstall = orders.uninstall
	}
	log.Info("tripwatch sensor started", "version", buildinfo.Version, "host", bundle.HostID, "verifier", bundle.VerifierURL)

	// Every start is reported: a stop shorter than the silence threshold would otherwise leave
	// no trace. If the verifier is unreachable the event stays pending and goes out first.
	// A marker left by an earlier removal of the package means nothing to this run.
	_ = os.Remove(filepath.Join(stateDir, removingMarker))
	_ = os.Remove(filepath.Join(stateDir, updatingMarker))
	bootID, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	started, _ := json.Marshal(map[string]string{"event": "sensor_started", "version": buildinfo.Version, "boot_id": strings.TrimSpace(string(bootID))})
	if err := client.Send(ctx, protocol.KindEvent, started, time.Now()); err != nil && ctx.Err() == nil {
		log.Warn("start event not delivered yet", "err", err)
	}

	// The client certificate is renewed before it expires, checked once a day.
	go func() {
		for {
			if renewed, err := transport.RenewIfDue(ctx, httpClient, bundle.VerifierURL, identity, time.Now()); err != nil && ctx.Err() == nil {
				log.Warn("client certificate not renewed yet", "expires", identity.NotAfter(), "err", err)
			} else if renewed {
				log.Info("client certificate renewed", "expires", identity.NotAfter())
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(24 * time.Hour):
			}
		}
	}()

	s.realtime = s.startRealtime(ctx, log, sendEvents(log, client))

	// Heartbeats run on their own: a snapshot taking minutes must not look like silence.
	go func() {
		tick := time.NewTicker(heartbeat)
		defer tick.Stop()
		for {
			if err := client.Send(ctx, protocol.KindHeartbeat, nil, time.Now()); err != nil && ctx.Err() == nil {
				log.Warn("heartbeat not delivered", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()

	for {
		if err := s.sendSnapshot(ctx, client); err != nil {
			if errors.Is(err, transport.ErrRejected) {
				return fmt.Errorf("the verifier refuses this sensor, enroll the host again: %w", err)
			}
			if ctx.Err() == nil {
				log.Warn("snapshot not delivered, retrying at the next interval", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			s.realtime.drained()
			stopping(log, client, stateDir)
			return nil
		case <-time.After(interval):
		}
	}
}

// Markers left in the state directory for the running sensor to read as it stops: by the
// package's pre-removal script, and by the package's post-installation script or -update before
// they restart it on a new version.
const (
	removingMarker = "removing"
	updatingMarker = "updating"
)

// systemStopping reports whether systemd is shutting the system down: only then does the
// verifier take a stop for a shutdown. A stop of the service on a running system is not one.
// systemctl is run by absolute path, never looked up in PATH.
func systemStopping() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// is-system-running exits non-zero for every state but "running", "stopping" included: only
	// its output counts.
	for _, systemctl := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if _, err := os.Stat(systemctl); err != nil {
			continue
		}
		out, _ := exec.CommandContext(ctx, systemctl, "is-system-running").Output() //nolint:gosec // one of the two fixed paths above
		return strings.TrimSpace(string(out)) == "stopping"
	}
	return false
}

// stopping tells the verifier, as the last envelope of the chain, that the sensor is going away
// and why: removed with its package, or stopped (by hand, or for a reboot). Without it a stop
// shows only as silence minutes later.
func stopping(log *slog.Logger, client *transport.Client, stateDir string) {
	reason := "stopped"
	if _, err := os.Stat(filepath.Join(stateDir, removingMarker)); err == nil {
		reason = "package_removed"
	} else if _, err := os.Stat(filepath.Join(stateDir, updatingMarker)); err == nil {
		reason = "updating"
	}
	payload, _ := json.Marshal(map[string]any{"event": "sensor_stopping", "version": buildinfo.Version, "reason": reason, "shutdown": systemStopping()})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Send(ctx, protocol.KindEvent, payload, time.Now()); err != nil {
		log.Warn("stop not reported to the verifier", "reason", reason, "err", err)
	}
}

// Retries of a snapshot that could not be sealed because an earlier envelope is still pending:
// soon, and for a few minutes, without collecting it again.
const (
	snapshotRetry   = 10 * time.Second
	snapshotRetries = 30
)

func (s sensor) sendSnapshot(ctx context.Context, client *transport.Client) error {
	r := s.snapshot(ctx)
	// Cut short by the sensor's own stop (an update, a reboot), the snapshot would be sealed and
	// sent by the next start: it holds what a scan finds by name before its content clears it,
	// and the next start collects a whole one anyway.
	if err := ctx.Err(); err != nil {
		return err
	}
	r.Snapshot.Bound(collector.MaxResultsSize)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(r); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	payload := buf.Bytes()
	if err := retryUnsealed(ctx, snapshotRetry, snapshotRetries, func() error {
		return client.Send(ctx, protocol.KindSnapshot, payload, time.Now())
	}); err != nil {
		return err
	}
	return s.commit()
}

// retryUnsealed sends, and sends again every interval up to tries times while the payload could
// not be sealed: the pending envelope, an event batch the verifier asked to send later, goes
// first, and waiting the next snapshot would leave an hour without one. Any other error, or a
// refusal, ends it.
func retryUnsealed(ctx context.Context, every time.Duration, tries int, send func() error) error {
	for try := 0; ; try++ {
		err := send()
		if err == nil || !errors.Is(err, transport.ErrNotSealed) || errors.Is(err, transport.ErrRejected) || try == tries {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}

func (s sensor) commit() error { return errors.Join(s.weblog.Commit(), s.web.Commit()) }

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(strings.ToLower(v)); v != "" {
			out = append(out, v)
		}
	}
	return out
}
