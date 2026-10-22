// Command tripwatch-sensor collects the state of the machine it runs on and sends it to the
// verifier. It only observes: every decision is taken by the verifier.
//
// With -bundle it runs as a daemon: a heartbeat every -heartbeat, a snapshot every -interval.
// Without, it prints one snapshot as JSON and exits.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	"github.com/cpibia/tripwatch/internal/transport"
	"github.com/cpibia/tripwatch/internal/verifier/pki"
)

type report struct {
	Environment discovery.Environment `json:"environment"`
	Snapshot    collector.Snapshot    `json:"snapshot"`
}

type sensor struct {
	root       string
	collectors []collector.Collector
	weblog     *logs.Collector
}

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	rootDir := flag.String("root", "/", "root of the filesystem to observe (the host root when running in a DaemonSet)")
	appDB := flag.Bool("app-db", true, "read administrators, extensions and stored scripts from the databases of recognised applications (local database servers only)")
	appDBHosts := flag.String("app-db-hosts", "", "comma-separated database hosts, as host or host:port, trusted beyond the local server, such as a Docker service name")
	stateDir := flag.String("state-dir", "/var/lib/tripwatch", "directory for state kept between runs, such as log positions (empty to keep none)")
	bundlePath := flag.String("bundle", "", "enrollment bundle issued by the verifier; runs as a daemon reporting to it")
	interval := flag.Duration("interval", time.Hour, "time between snapshots in daemon mode")
	heartbeat := flag.Duration("heartbeat", time.Minute, "time between heartbeats in daemon mode")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("tripwatch-sensor"))
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

func (s sensor) snapshot(ctx context.Context) report {
	src := collector.NewSource(s.root)
	return report{
		Environment: discovery.DetectEnvironment(src.FS, os.Getenv),
		Snapshot:    collector.Run(ctx, src, s.collectors, time.Now()),
	}
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

func (s sensor) daemon(ctx context.Context, log *slog.Logger, bundlePath, stateDir string, interval, heartbeat time.Duration) error {
	bundle, key, err := pki.LoadBundle(bundlePath)
	if err != nil {
		return err
	}
	tlsConf, err := bundle.ClientTLS()
	if err != nil {
		return err
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}, Timeout: 2 * time.Minute}
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
