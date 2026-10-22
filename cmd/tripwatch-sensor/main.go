// Command tripwatch-sensor collects the state of the machine it runs on and sends it to the
// verifier. It only observes: every decision is taken by the verifier.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cpibia/tripwatch/internal/buildinfo"
	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/logs"
	"github.com/cpibia/tripwatch/internal/collector/system"
	"github.com/cpibia/tripwatch/internal/collector/web"
	"github.com/cpibia/tripwatch/internal/discovery"
)

type report struct {
	Environment discovery.Environment `json:"environment"`
	Snapshot    collector.Snapshot    `json:"snapshot"`
}

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	rootDir := flag.String("root", "/", "root of the filesystem to observe (the host root when running in a DaemonSet)")
	stateDir := flag.String("state-dir", "/var/lib/tripwatch", "directory for state kept between runs, such as log positions (empty to keep none)")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("tripwatch-sensor"))
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	weblog := &logs.Collector{StateDir: *stateDir}
	src := collector.NewSource(*rootDir)
	out := report{
		Environment: discovery.DetectEnvironment(src.FS, os.Getenv),
		Snapshot:    collector.Run(ctx, src, append(system.All(), web.Collector{}, weblog), time.Now()),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		log.Fatal(err)
	}
	// Log positions advance only once the snapshot carrying their events is out.
	if err := weblog.Commit(); err != nil {
		log.Printf("weblog positions not saved, the same lines will be read again: %v", err)
	}
}
