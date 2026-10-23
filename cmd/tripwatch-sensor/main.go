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
	watchOnly := flag.Bool("watch-only", false, "print the real-time event batches as JSON lines until interrupted, without a verifier, to see what the watchers report")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("tripwatch-sensor"))
		return
	}
	if *update {
		if err := selfUpdate(); err != nil {
			fmt.Fprintln(os.Stderr, "tripwatch-sensor -update:", err)
			os.Exit(1)
		}
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s := sensor{root: *rootDir, weblog: &logs.Collector{StateDir: *stateDir}}
	s.collectors = append(system.All(), web.Collector{}, s.weblog)
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

func selfUpdate() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("releases are built for Linux only, not %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errors.New("run it as root, with sudo")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	u := selfupdate.Updater{
		Client:     &http.Client{Timeout: 5 * time.Minute},
		BaseURL:    selfupdate.Repository,
		Current:    buildinfo.Version,
		Arch:       runtime.GOARCH,
		Executable: exe,
		Out:        os.Stdout,
		Run: func(ctx context.Context, out io.Writer, name string, args ...string) error {
			cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed commands; the arguments are our own paths
			cmd.Stdout, cmd.Stderr = out, out
			return cmd.Run()
		},
	}
	_, err = u.Update(ctx)
	return err
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
// machine: loopback and link-local ones say nothing about which server this is.
func interfaceAddresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() || ipnet.IP.IsLinkLocalMulticast() {
			continue
		}
		out = append(out, ipnet.IP.String())
	}
	return out
}

func (s sensor) printOnce(ctx context.Context) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s.snapshot(ctx)); err != nil {
		return err
	}
	// Log positions advance only once the snapshot carrying their events is out.
	return s.weblog.Commit()
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
	log.Info("tripwatch sensor started", "version", buildinfo.Version, "host", bundle.HostID, "verifier", bundle.VerifierURL)

	// Every start is reported: a stop shorter than the silence threshold would otherwise leave
	// no trace. If the verifier is unreachable the event stays pending and goes out first.
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
			return nil
		case <-time.After(interval):
		}
	}
}

func (s sensor) sendSnapshot(ctx context.Context, client *transport.Client) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(s.snapshot(ctx)); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := client.Send(ctx, protocol.KindSnapshot, buf.Bytes(), time.Now()); err != nil {
		return err
	}
	return s.weblog.Commit()
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(strings.ToLower(v)); v != "" {
			out = append(out, v)
		}
	}
	return out
}
