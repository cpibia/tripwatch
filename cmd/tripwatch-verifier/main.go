// Command tripwatch-verifier receives envelopes from the sensors, keeps the baselines off the
// monitored machines, raises alerts and serves the web interface.
//
// Usage:
//
//	tripwatch-verifier serve
//	tripwatch-verifier enroll -host web-01 -out web-01.json
//	tripwatch-verifier revoke -host web-01
//	tripwatch-verifier user -email ops@example.com   (password on standard input)
//	tripwatch-verifier healthcheck
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // the container image has no zoneinfo; TZ must still work

	"github.com/cpibia/tripwatch/internal/buildinfo"
	"github.com/cpibia/tripwatch/internal/verifier/analyze"
	"github.com/cpibia/tripwatch/internal/verifier/ingest"
	"github.com/cpibia/tripwatch/internal/verifier/notify"
	"github.com/cpibia/tripwatch/internal/verifier/pki"
	"github.com/cpibia/tripwatch/internal/verifier/store"
	"github.com/cpibia/tripwatch/internal/verifier/ui"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println(buildinfo.String("tripwatch-verifier"))
		return
	}
	cmd, args := "serve", os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}

	var err error
	switch cmd {
	case "serve":
		err = serve(log)
	case "enroll":
		err = enroll(args)
	case "revoke":
		err = revoke(args)
	case "user":
		err = user(args)
	case "healthcheck":
		err = healthcheck()
	default:
		err = fmt.Errorf("unknown command %q (serve, enroll, revoke, user, healthcheck)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tripwatch-verifier:", err)
		os.Exit(1)
	}
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func dataDir() string { return env("TRIPWATCH_DATA", "/data") }

func openStore() (*store.Store, error) {
	if err := os.MkdirAll(dataDir(), 0o700); err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(dataDir(), "tripwatch.db"))
}

func serve(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	now := func() time.Time { return time.Now().UTC() }

	st, err := openStore()
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if err := bootstrapAdmin(ctx, st, now()); err != nil {
		return err
	}

	ca, err := pki.LoadOrCreate(filepath.Join(dataDir(), "pki"), now())
	if err != nil {
		return err
	}
	names := strings.Split(env("TRIPWATCH_HOSTNAMES", "localhost"), ",")
	ingestURL := env("TRIPWATCH_PUBLIC_INGEST_URL", "https://"+names[0]+":8443"+ingest.Path)
	if !strings.HasPrefix(ingestURL, "https://") {
		return fmt.Errorf("TRIPWATCH_PUBLIC_INGEST_URL %q is not https", ingestURL)
	}
	cert, err := ca.ServerCertificate(filepath.Join(dataDir(), "pki"), names, now())
	if err != nil {
		return err
	}

	analyzer := &analyze.Analyzer{Store: st, Now: now, Log: log}
	wake := make(chan struct{}, 1)
	in := &ingest.Server{Store: st, CA: ca, Now: now, Log: log, Wake: wake}
	go analyzer.Worker(ctx, wake)
	ingestSrv := &http.Server{
		Addr:              env("TRIPWATCH_INGEST_ADDR", ":8443"),
		Handler:           in,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    ca.Pool(),
			// Verified when given; required by every path except enrollment, which is how a
			// host gets its first certificate.
			ClientAuth: tls.VerifyClientCertIfGiven,
			MinVersion: tls.VersionTLS13,
		},
	}

	mailer := notify.Mailer{
		Host: os.Getenv("TRIPWATCH_SMTP_HOST"), Port: env("TRIPWATCH_SMTP_PORT", "587"),
		User: os.Getenv("TRIPWATCH_SMTP_USER"), Password: os.Getenv("TRIPWATCH_SMTP_PASSWORD"),
		From: os.Getenv("TRIPWATCH_SMTP_FROM"), To: splitList(os.Getenv("TRIPWATCH_NOTIFY_TO")),
		BaseURL: os.Getenv("TRIPWATCH_PUBLIC_UI_URL"),
	}
	notifier := &notify.Notifier{Store: st, Mailer: mailer, Now: now, Log: log}
	silence, err := time.ParseDuration(env("TRIPWATCH_SILENCE_AFTER", "3m"))
	if err != nil {
		return fmt.Errorf("TRIPWATCH_SILENCE_AFTER: %w", err)
	}
	snapshotsAfter, err := time.ParseDuration(env("TRIPWATCH_SNAPSHOTS_AFTER", "3h"))
	if err != nil {
		return fmt.Errorf("TRIPWATCH_SNAPSHOTS_AFTER: %w", err)
	}

	web, err := ui.New(ui.Config{
		Store: st, CA: ca, IngestURL: ingestURL,
		Notify: mailer.Enabled(), SecureCookies: strings.HasPrefix(os.Getenv("TRIPWATCH_PUBLIC_UI_URL"), "https://"),
		SilenceAfter: silence, Now: now, Log: log,
	})
	if err != nil {
		return err
	}
	uiSrv := &http.Server{
		Addr:              env("TRIPWATCH_UI_ADDR", ":8080"),
		Handler:           web,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				analyzer.Silent(ctx, silence, snapshotsAfter)
				notifier.Round(ctx)
				if err := st.PruneResolved(ctx, now()); err != nil {
					log.Error("prune resolved alerts", "err", err)
				}
			}
		}
	}()

	errs := make(chan error, 2)
	go func() { errs <- ingestSrv.ListenAndServeTLS("", "") }()
	go func() { errs <- uiSrv.ListenAndServe() }()
	log.Info("tripwatch verifier started", "version", buildinfo.Version, "ingest", ingestSrv.Addr, "ui", uiSrv.Addr, "email", mailer.Enabled())

	select {
	case <-ctx.Done():
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = ingestSrv.Shutdown(shutdown)
	_ = uiSrv.Shutdown(shutdown)
	return nil
}

// bootstrapAdmin creates the first user from the environment when there is none yet.
func bootstrapAdmin(ctx context.Context, st *store.Store, now time.Time) error {
	n, err := st.CountUsers(ctx)
	if err != nil || n > 0 {
		return err
	}
	email, password := os.Getenv("TRIPWATCH_ADMIN_EMAIL"), os.Getenv("TRIPWATCH_ADMIN_PASSWORD")
	if email == "" || len(password) < 12 {
		return errors.New("no user yet: set TRIPWATCH_ADMIN_EMAIL and TRIPWATCH_ADMIN_PASSWORD (12 characters or more) for the first start")
	}
	return st.SetUser(ctx, email, password, now)
}

func enroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	host := fs.String("host", "", "name of the host to enroll (its certificate's common name)")
	url := fs.String("url", os.Getenv("TRIPWATCH_PUBLIC_INGEST_URL"), "address sensors use to reach the ingest endpoint")
	out := fs.String("out", "", "file to write the bundle to, readable by its owner only (- for standard output)")
	_ = fs.Parse(args)
	if *host == "" || *url == "" || *out == "" {
		return errors.New("enroll needs -host, -out and -url (or TRIPWATCH_PUBLIC_INGEST_URL)")
	}
	if !strings.HasPrefix(*url, "https://") {
		return fmt.Errorf("ingest URL %q is not https", *url)
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	now := time.Now().UTC()
	ca, err := pki.LoadOrCreate(filepath.Join(dataDir(), "pki"), now)
	if err != nil {
		return err
	}
	bundle, pub, err := ca.Enroll(*host, *url, now)
	if err != nil {
		return err
	}
	if err := st.Enroll(context.Background(), *host, pub, now); err != nil {
		return err
	}
	serial, err := pki.Serial([]byte(bundle.Cert))
	if err != nil {
		return err
	}
	if err := st.SetCertificate(context.Background(), *host, serial, false); err != nil {
		return err
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *out == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	// The bundle holds the host's private keys: created private, never over an existing file.
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func revoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	host := fs.String("host", "", "host to revoke")
	_ = fs.Parse(args)
	st, err := openStore()
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	return st.Revoke(context.Background(), *host)
}

func user(args []string) error {
	fs := flag.NewFlagSet("user", flag.ExitOnError)
	email := fs.String("email", "", "user to create or whose password to change")
	_ = fs.Parse(args)
	if *email == "" {
		return errors.New("user needs -email")
	}
	fmt.Fprint(os.Stderr, "password (12 characters or more): ")
	password, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	password = strings.TrimRight(password, "\r\n")
	if len(password) < 12 {
		return errors.New("password too short")
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	return st.SetUser(context.Background(), *email, password, time.Now().UTC())
}

// healthcheck asks the running interface whether it answers; the container image has no shell
// or curl to do it.
func healthcheck() error {
	addr := env("TRIPWATCH_UI_ADDR", ":8080")
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("interface answered %s", resp.Status)
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
