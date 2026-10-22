// Command tripwatch-verifier receives envelopes from the sensors, keeps the baselines off the
// monitored machines and raises alerts.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cpibia/tripwatch/internal/buildinfo"
)

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("tripwatch-verifier"))
		return
	}

	fmt.Fprintln(os.Stderr, "tripwatch-verifier: ingest server not implemented yet")
	os.Exit(2)
}
